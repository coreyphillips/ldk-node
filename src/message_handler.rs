// This file is Copyright its original authors, visible in version control history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. You may not use this file except in
// accordance with one or both of these licenses.

use std::ops::Deref;
use std::sync::Arc;

use bitcoin::secp256k1::PublicKey;
use lightning::ln::peer_handler::CustomMessageHandler;
use lightning::ln::wire::{CustomMessageReader, Type};
use lightning::util::logger::Logger;
use lightning::util::ser::{LengthLimitedRead, Writeable, Writer};
use lightning_liquidity::lsps0::ser::RawLSPSMessage;
use lightning_types::features::{InitFeatures, NodeFeatures};

#[cfg(feature = "chicory")]
use crate::chicory::ChicoryService;
use crate::liquidity::LiquiditySource;
use crate::primary::PrimaryClient;
use crate::primary_wire as wire;

/// Multiplex independent application protocols without replacing LSPS support.
#[derive(Debug)]
pub(crate) enum NodeCustomMessage {
	Liquidity(RawLSPSMessage),
	Beignet(wire::Envelope),
}

impl Writeable for NodeCustomMessage {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), lightning::io::Error> {
		match self {
			Self::Liquidity(message) => message.write(writer),
			Self::Beignet(message) => {
				let bytes = message.encode().map_err(|_| {
					lightning::io::Error::new(
						lightning::io::ErrorKind::InvalidInput,
						"invalid Beignet envelope",
					)
				})?;
				writer.write_all(&bytes)
			},
		}
	}
}

impl Type for NodeCustomMessage {
	fn type_id(&self) -> u16 {
		match self {
			Self::Liquidity(message) => message.type_id(),
			Self::Beignet(_) => wire::CUSTOM_MESSAGE_TYPE,
		}
	}
}

pub(crate) struct NodeCustomMessageHandler<L: Deref>
where
	L::Target: Logger,
{
	liquidity_source: Option<Arc<LiquiditySource<L>>>,
	primary_client: Option<Arc<PrimaryClient>>,
	direct_funding: Option<Arc<crate::direct_funding::Service>>,
	#[cfg(feature = "chicory")]
	chicory_service: Option<Arc<ChicoryService>>,
}

impl<L: Deref> NodeCustomMessageHandler<L>
where
	L::Target: Logger,
{
	pub(crate) fn new_liquidity(liquidity_source: Arc<LiquiditySource<L>>) -> Self {
		Self {
			liquidity_source: Some(liquidity_source),
			primary_client: None,
			direct_funding: None,
			#[cfg(feature = "chicory")]
			chicory_service: None,
		}
	}

	pub(crate) fn new_ignoring() -> Self {
		Self {
			liquidity_source: None,
			primary_client: None,
			direct_funding: None,
			#[cfg(feature = "chicory")]
			chicory_service: None,
		}
	}

	pub(crate) fn with_primary(mut self, client: Arc<PrimaryClient>) -> Self {
		self.primary_client = Some(client);
		self
	}

	fn has_beignet_handler(&self) -> bool {
		if self.direct_funding.is_some() {
			return true;
		}
		#[cfg(feature = "chicory")]
		if self.chicory_service.is_some() {
			return true;
		}
		self.primary_client.as_ref().is_some_and(|client| client.enabled())
	}

	pub(crate) fn with_direct_funding(
		mut self, service: Arc<crate::direct_funding::Service>,
	) -> Self {
		self.direct_funding = Some(service);
		self
	}

	#[cfg(feature = "chicory")]
	pub(crate) fn with_chicory(mut self, service: Option<Arc<ChicoryService>>) -> Self {
		self.chicory_service = service;
		self
	}
}

impl<L: Deref> CustomMessageReader for NodeCustomMessageHandler<L>
where
	L::Target: Logger,
{
	type CustomMessage = NodeCustomMessage;

	fn read<RD: LengthLimitedRead>(
		&self, message_type: u16, buffer: &mut RD,
	) -> Result<Option<Self::CustomMessage>, lightning::ln::msgs::DecodeError> {
		if message_type == wire::CUSTOM_MESSAGE_TYPE && self.has_beignet_handler() {
			// BOLT 8 already limits frames. Keep the bound here as well for callers
			// that invoke the reader directly, before allocating from untrusted input.
			let length = buffer.remaining_bytes();
			if !(4..=65_533).contains(&length) {
				return Ok(None);
			}
			let mut bytes = vec![0; length as usize];
			buffer.read_exact(&mut bytes)?;
			// Beignet drops malformed application messages without disconnecting
			// the Lightning peer. Unknown versions are ignored by the service.
			return Ok(wire::Envelope::decode(&bytes).ok().map(NodeCustomMessage::Beignet));
		}
		match &self.liquidity_source {
			Some(source) => source
				.liquidity_manager()
				.read(message_type, buffer)
				.map(|message| message.map(NodeCustomMessage::Liquidity)),
			None => Ok(None),
		}
	}
}

impl<L: Deref> CustomMessageHandler for NodeCustomMessageHandler<L>
where
	L::Target: Logger,
{
	fn handle_custom_message(
		&self, message: Self::CustomMessage, sender_node_id: PublicKey,
	) -> Result<(), lightning::ln::msgs::LightningError> {
		match message {
			NodeCustomMessage::Liquidity(message) => {
				if let Some(source) = &self.liquidity_source {
					source.liquidity_manager().handle_custom_message(message, sender_node_id)?;
				}
			},
			NodeCustomMessage::Beignet(message) => {
				if let Some(service) = &self.direct_funding {
					service.transport.handle_message(sender_node_id, &message);
				}
				if let Some(client) = &self.primary_client {
					client.handle_message(sender_node_id, &message);
				}
				#[cfg(feature = "chicory")]
				if let Some(service) = &self.chicory_service {
					service.handle_message(sender_node_id, message);
				}
			},
		}
		Ok(())
	}

	fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Self::CustomMessage)> {
		let mut messages = self
			.liquidity_source
			.as_ref()
			.map(|source| {
				source
					.liquidity_manager()
					.get_and_clear_pending_msg()
					.into_iter()
					.map(|(peer, message)| (peer, NodeCustomMessage::Liquidity(message)))
					.collect::<Vec<_>>()
			})
			.unwrap_or_default();
		if let Some(service) = &self.direct_funding {
			messages.extend(
				service
					.transport
					.take_messages()
					.into_iter()
					.map(|(peer, message)| (peer, NodeCustomMessage::Beignet(message))),
			);
		}
		if let Some(client) = &self.primary_client {
			messages.extend(
				client
					.take_messages()
					.into_iter()
					.map(|(peer, message)| (peer, NodeCustomMessage::Beignet(message))),
			);
		}
		#[cfg(feature = "chicory")]
		let messages = {
			let mut messages = messages;
			if let Some(service) = &self.chicory_service {
				messages.extend(
					service
						.get_and_clear_pending_msg()
						.into_iter()
						.map(|(peer, message)| (peer, NodeCustomMessage::Beignet(message))),
				);
			}
			messages
		};
		messages
	}

	fn provided_node_features(&self) -> NodeFeatures {
		self.liquidity_source
			.as_ref()
			.map(|source| source.liquidity_manager().provided_node_features())
			.unwrap_or_else(NodeFeatures::empty)
	}

	fn provided_init_features(&self, peer: PublicKey) -> InitFeatures {
		// Native ChannelManager owns channel feature negotiation.
		// This application handler contributes only independent LSPS features.
		self.liquidity_source
			.as_ref()
			.map(|source| source.liquidity_manager().provided_init_features(peer))
			.unwrap_or_else(InitFeatures::empty)
	}

	fn peer_connected(
		&self, peer: PublicKey, message: &lightning::ln::msgs::Init, inbound: bool,
	) -> Result<(), ()> {
		if let Some(source) = &self.liquidity_source {
			source.liquidity_manager().peer_connected(peer, message, inbound)?;
		}
		#[cfg(feature = "chicory")]
		if let Some(service) = &self.chicory_service {
			service.peer_connected(peer, message);
		}
		Ok(())
	}

	fn peer_disconnected(&self, peer: PublicKey) {
		if let Some(client) = &self.primary_client {
			client.disconnected(peer);
		}
		if let Some(source) = &self.liquidity_source {
			source.liquidity_manager().peer_disconnected(peer);
		}
		#[cfg(feature = "chicory")]
		if let Some(service) = &self.chicory_service {
			service.peer_disconnected(peer);
		}
	}
}

#[cfg(test)]
mod compatibility_review_tests {
	use super::*;
	use bitcoin::secp256k1::{Secp256k1, SecretKey};
	use lightning::util::logger::Record;
	use lightning_liquidity::lsps0::ser::LSPS_MESSAGE_TYPE_ID;

	#[cfg(feature = "chicory")]
	use crate::builder::NodeBuilder;
	#[cfg(feature = "chicory")]
	use crate::chicory::JitServiceConfig;
	#[cfg(feature = "chicory")]
	use crate::io::test_utils::InMemoryStore;

	struct SilentLogger;
	impl Logger for SilentLogger {
		fn log(&self, _: Record<'_>) {}
	}

	#[test]
	fn disabled_reader_preserves_ignoring_behavior() {
		let handler = NodeCustomMessageHandler::<Arc<SilentLogger>>::new_ignoring();
		for message_type in [44069, LSPS_MESSAGE_TYPE_ID, 55001, 55077, 65535] {
			for length in [0usize, 3, 4, 68, 65533, 65534, 65535] {
				let bytes = vec![0xff; length];
				let mut input = bytes.as_slice();
				assert!(handler.read(message_type, &mut input).unwrap().is_none());
				assert_eq!(input, bytes.as_slice());
			}
		}
		assert!(handler.get_and_clear_pending_msg().is_empty());
		assert_eq!(handler.provided_node_features(), NodeFeatures::empty());
		let key = PublicKey::from_secret_key(
			&Secp256k1::new(),
			&SecretKey::from_slice(&[1; 32]).unwrap(),
		);
		assert_eq!(handler.provided_init_features(key), InitFeatures::empty());
		handler.peer_disconnected(key);
		handler
			.handle_custom_message(
				NodeCustomMessage::Liquidity(RawLSPSMessage { payload: "{}".to_owned() }),
				key,
			)
			.unwrap();
	}

	#[cfg(feature = "chicory")]
	#[test]
	fn active_chicory_service_ignores_removed_offline_message_types() {
		let mut builder = NodeBuilder::new();
		builder.set_entropy_seed_bytes([53; 64]);
		builder.set_log_facade_logger();
		builder.set_chicory_service(JitServiceConfig::default()).unwrap();
		let node = builder.build_with_store(Arc::new(InMemoryStore::new())).unwrap();
		let handler = NodeCustomMessageHandler::<Arc<SilentLogger>>::new_ignoring()
			.with_chicory(node.chicory_service.clone());
		assert!(handler.has_beignet_handler());
		for message_type in [55001, 55003, 55045, 55047, 55049, 55051, 55053, 55075, 55077] {
			for length in [128, 65_533] {
				let bytes = vec![7; length];
				let mut input = bytes.as_slice();
				assert!(handler.read(message_type, &mut input).unwrap().is_none());
				assert_eq!(input, bytes.as_slice());
			}
		}
		assert!(handler.get_and_clear_pending_msg().is_empty());
	}

	#[test]
	fn lsps_wrapper_preserves_type_and_unprefixed_wire_bytes() {
		let payload = r#"{"jsonrpc":"2.0","id":"a","method":"lsps0.list_protocols","params":{}}"#;
		let message = NodeCustomMessage::Liquidity(RawLSPSMessage { payload: payload.to_owned() });
		assert_eq!(message.type_id(), LSPS_MESSAGE_TYPE_ID);
		assert_eq!(message.encode(), payload.as_bytes());
	}
}
