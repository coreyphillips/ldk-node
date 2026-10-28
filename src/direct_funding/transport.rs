//! Bounded direct-peer and primary-relay transport. A relay identity is never
//! treated as authentication of the payer it claims to forward for.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use bitcoin::secp256k1::PublicKey;
use lightning::ln::msgs::SocketAddress;
use tokio::sync::broadcast;

use super::codec::{self, RelayAddress, RelayFrame, RequestEnvelope};
use super::sender::SenderTransport;
use super::DirectFundingError;
use crate::connection::ConnectionManager;
use crate::logger::Logger;
use crate::primary_wire::{Envelope, PROTOCOL_VERSION};
use crate::types::PeerManager;

const MAX_QUEUE: usize = 128;
const MAX_PEERS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Route {
	pub peer: PublicKey,
	pub relay_target: Option<PublicKey>,
}

#[derive(Clone)]
pub(crate) struct Inbound {
	pub route: Route,
	pub subtype: u16,
	pub payload: Vec<u8>,
}

struct Budget {
	start: Instant,
	frames: usize,
	bytes: usize,
}

impl Budget {
	fn new() -> Self {
		Self { start: Instant::now(), frames: 0, bytes: 0 }
	}
	fn accept(&mut self, bytes: usize) -> bool {
		if self.start.elapsed() >= Duration::from_secs(1) {
			*self = Self::new();
		}
		self.frames += 1;
		self.bytes += bytes;
		self.frames <= 32 && self.bytes <= 128 * 1024
	}
}

struct State {
	outbound: VecDeque<(PublicKey, Envelope)>,
	budgets: HashMap<PublicKey, Budget>,
	global: Budget,
}

type Connections = ConnectionManager<Arc<Logger>>;

pub(crate) struct Transport {
	local_node_id: PublicKey,
	state: Mutex<State>,
	inbound: broadcast::Sender<Inbound>,
	peers: Mutex<Option<(Weak<PeerManager>, Weak<Connections>)>>,
}

impl Transport {
	pub(crate) fn new(local_node_id: PublicKey) -> Self {
		let (inbound, _) = broadcast::channel(MAX_QUEUE);
		Self {
			local_node_id,
			state: Mutex::new(State {
				outbound: VecDeque::new(),
				budgets: HashMap::new(),
				global: Budget::new(),
			}),
			inbound,
			peers: Mutex::new(None),
		}
	}

	pub(crate) fn attach(&self, peers: &Arc<PeerManager>, connections: &Arc<Connections>) {
		*self.peers.lock().unwrap() = Some((Arc::downgrade(peers), Arc::downgrade(connections)));
	}

	pub(crate) fn subscribe(&self) -> broadcast::Receiver<Inbound> {
		self.inbound.subscribe()
	}

	pub(crate) fn handle_message(&self, peer: PublicKey, message: &Envelope) {
		if message.version != PROTOCOL_VERSION || message.payload.len() > codec::MAX_MESSAGE_BYTES {
			return;
		}
		if !matches!(
			message.subtype,
			codec::OFFER
				| codec::OFFER_ACK
				| codec::SIGN_REQUEST
				| codec::WITNESS
				| codec::RECEIPT
				| codec::RELAY
		) {
			return;
		}
		{
			let mut state = self.state.lock().unwrap();
			if !state.global.accept(message.payload.len()) {
				return;
			}
			if !state.budgets.contains_key(&peer) && state.budgets.len() >= MAX_PEERS {
				state.budgets.retain(|_, b| b.start.elapsed() < Duration::from_secs(1));
				if state.budgets.len() >= MAX_PEERS {
					return;
				}
			}
			if !state.budgets.entry(peer).or_insert_with(Budget::new).accept(message.payload.len())
			{
				return;
			}
		}
		let inbound = if message.subtype == codec::RELAY {
			let Ok(frame) = RelayFrame::decode(&message.payload) else {
				return;
			};
			let RelayAddress::From(source) = frame.address else {
				return;
			};
			if source == peer
				|| !matches!(
					frame.subtype,
					codec::OFFER
						| codec::OFFER_ACK | codec::SIGN_REQUEST
						| codec::WITNESS | codec::RECEIPT
				) {
				return;
			}
			Inbound {
				route: Route { peer, relay_target: Some(source) },
				subtype: frame.subtype,
				payload: frame.payload,
			}
		} else {
			Inbound {
				route: Route { peer, relay_target: None },
				subtype: message.subtype,
				payload: message.payload.clone(),
			}
		};
		let _ = self.inbound.send(inbound);
	}

	pub(crate) fn send(
		&self, route: Route, subtype: u16, payload: Vec<u8>,
	) -> Result<(), DirectFundingError> {
		if payload.len() > codec::MAX_MESSAGE_BYTES {
			return Err(DirectFundingError::InvalidFunding);
		}
		let message = match route.relay_target {
			Some(target) => Envelope {
				version: PROTOCOL_VERSION,
				subtype: codec::RELAY,
				payload: RelayFrame { subtype, payload, address: RelayAddress::To(target) }
					.encode()
					.map_err(|_| DirectFundingError::InvalidFunding)?,
			},
			None => Envelope { version: PROTOCOL_VERSION, subtype, payload },
		};
		{
			let mut state = self.state.lock().unwrap();
			if state.outbound.len() >= MAX_QUEUE {
				return Err(DirectFundingError::Busy);
			}
			state.outbound.push_back((route.peer, message));
		}
		let peers = self.peers.lock().unwrap().as_ref().and_then(|(peers, _)| peers.upgrade());
		if let Some(peers) = peers {
			peers.process_events();
		}
		Ok(())
	}

	pub(crate) fn take_messages(&self) -> Vec<(PublicKey, Envelope)> {
		self.state.lock().unwrap().outbound.drain(..).collect()
	}

	pub(crate) async fn open(
		self: &Arc<Self>, request: &RequestEnvelope,
	) -> Result<Lane, DirectFundingError> {
		let (peers, connections) = self
			.peers
			.lock()
			.unwrap()
			.as_ref()
			.and_then(|(peers, connections)| Some((peers.upgrade()?, connections.upgrade()?)))
			.ok_or(DirectFundingError::NotRunning)?;
		for descriptor in &request.transports {
			let Some((peer, host, port, relayed)) = descriptor.endpoint(request.receiver_node_id)
			else {
				continue;
			};
			// When we ARE the introduction peer, talk directly to the receiver
			// already connected to us; we cannot relay a frame to ourselves.
			let peer =
				if relayed && peer == self.local_node_id { request.receiver_node_id } else { peer };
			let relayed = relayed && peer != request.receiver_node_id;
			let connected = peers.peer_by_node_id(&peer).is_some();
			if !connected {
				if !relayed
					&& peer == request.receiver_node_id
					&& descriptor
						.endpoint(request.receiver_node_id)
						.is_some_and(|(p, _, _, relay)| relay && p != peer)
				{
					continue;
				}
				let address = if host.contains(':') {
					format!("[{host}]:{port}")
				} else {
					format!("{host}:{port}")
				};
				let Ok(address) = SocketAddress::from_str(&address) else {
					continue;
				};
				if !matches!(
					tokio::time::timeout(
						Duration::from_secs(15),
						connections.connect_peer_if_necessary(peer, address)
					)
					.await,
					Ok(Ok(()))
				) {
					continue;
				}
			}
			return Ok(Lane {
				transport: Arc::clone(self),
				route: Route { peer, relay_target: relayed.then_some(request.receiver_node_id) },
				incoming: self.subscribe(),
			});
		}
		Err(DirectFundingError::Unavailable)
	}
}

pub(crate) struct Lane {
	transport: Arc<Transport>,
	route: Route,
	incoming: broadcast::Receiver<Inbound>,
}

impl SenderTransport for Lane {
	fn send(&self, subtype: u16, sealed: Vec<u8>) -> Result<(), DirectFundingError> {
		self.transport.send(self.route, subtype, sealed)
	}
	fn receive<'a>(
		&'a mut self,
	) -> Pin<Box<dyn Future<Output = Option<(u16, Vec<u8>)>> + Send + 'a>> {
		Box::pin(async move {
			loop {
				match self.incoming.recv().await {
					Ok(frame) if frame.route == self.route => {
						return Some((frame.subtype, frame.payload))
					},
					Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {},
					Err(broadcast::error::RecvError::Closed) => return None,
				}
			}
		})
	}
}

#[cfg(test)]
mod tests;
