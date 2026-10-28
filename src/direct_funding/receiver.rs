//! Durable direct-funding receiver. Admission verifies ownership and chain
//! evidence before starting a channel negotiation. The channel manager retains
//! commitment and monitor authority; this service only supplies payer witnesses.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::hex::FromHex;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use bitcoin::{Amount, ScriptBuf, Sequence, Transaction, Txid};
use lightning::ln::funding::{FundingSigningDetails, FundingTxInput, SpliceContribution};
use lightning::ln::types::ChannelId;
use lightning::util::persist::KVStoreSync;
use rand::{Rng, RngCore};
use serde::{Deserialize, Serialize};

use super::codec::{
	self, Attestation, FundingPubkeys, Offer, OfferAck, Prevout, Receipt, RequestEnvelope,
	SignRequest, TransportDescriptor, Witness,
};
use super::crypto::{self, LaneKeys};
use super::transport::{Inbound, Route, Transport};
use super::{
	now_ms, request_details, DirectFundingError as Error, DirectFundingPaymentDetails,
	DirectFundingPaymentStatus as Status, DirectFundingRequestDetails,
};
use crate::builder::BuildError;
use crate::chain::ChainSource;
use crate::config::{default_user_config, Config};
use crate::fee_estimator::{ConfirmationTarget, FeeEstimator, OnchainFeeEstimator};
use crate::payment::ConfirmationStatus;
use crate::types::{ChannelManager, DynStore, KeysManager};

const NAMESPACE: &str = "direct_funding";
const STORE_KEY: &str = "receiver_v1";
const HISTORY_NAMESPACE: &str = "receiver_history_v1";
const MAX_RECORDS: usize = 128;
const MAX_STORE_BYTES: usize = 4 * 1024 * 1024;
const MIN_AMOUNT: u64 = 5_000;
const SESSION_TIMEOUT_MS: u64 = 15 * 60 * 1000;

#[derive(Clone, Serialize, Deserialize)]
struct SavedRoute {
	peer: String,
	target: Option<String>,
}
impl SavedRoute {
	fn from_route(route: Route) -> Self {
		Self { peer: route.peer.to_string(), target: route.relay_target.map(|p| p.to_string()) }
	}
	fn route(&self) -> Result<Route, Error> {
		Ok(Route {
			peer: PublicKey::from_str(&self.peer).map_err(|_| Error::PersistenceFailed)?,
			relay_target: self
				.target
				.as_deref()
				.map(PublicKey::from_str)
				.transpose()
				.map_err(|_| Error::PersistenceFailed)?,
		})
	}
}

#[derive(Clone, Serialize, Deserialize)]
struct Session {
	offer: Vec<u8>,
	ephemeral: String,
	route: SavedRoute,
	user_channel_id: u128,
	channel_id: Option<String>,
	is_splice: bool,
	created_at: u64,
	sign_request: Option<Vec<u8>>,
	witness: Option<Vec<Vec<u8>>>,
	funding_txid: Option<String>,
	mempool_seen: bool,
	confirmed: bool,
	failed: bool,
}

impl Session {
	fn active(&self) -> bool {
		!self.failed && !self.confirmed
	}
}

#[derive(Clone, Serialize, Deserialize)]
struct Request {
	envelope: String,
	secret: [u8; 32],
	preimage: [u8; 32],
	expires_at: u64,
	primary: String,
	attempts: u8,
	session: Option<Session>,
	#[serde(default)]
	revoked: bool,
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct State {
	requests: BTreeMap<String, Request>,
}

/// Terminal activity only: no invoice secrets, preimages, routes, transactions or witnesses.
/// Separate immutable records keep the bounded negotiation journal from limiting wallet history.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
struct History {
	request_id: String,
	payment_hash: String,
	amount_sats: u64,
	funding_txid: Option<String>,
	created_at: u64,
	confirmed: bool,
}

impl History {
	fn from_request(id: &str, record: &Request) -> Result<Self, Error> {
		let session = record.session.as_ref().ok_or(Error::PersistenceFailed)?;
		if session.active() {
			return Err(Error::Busy);
		}
		let offer = Offer::decode(&session.offer).map_err(|_| Error::PersistenceFailed)?;
		Ok(Self {
			request_id: id.to_owned(),
			payment_hash: codec::hex(&offer.receipt_hash),
			amount_sats: offer.amount_sat,
			funding_txid: session.funding_txid.clone(),
			created_at: session.created_at,
			confirmed: session.confirmed,
		})
	}

	fn details(&self) -> DirectFundingPaymentDetails {
		DirectFundingPaymentDetails {
			request_id: self.request_id.clone(),
			payment_hash: self.payment_hash.clone(),
			amount_sats: self.amount_sats,
			fee_sats: Some(0),
			funding_txid: self.funding_txid.clone(),
			is_outbound: false,
			created_at: self.created_at,
			status: if self.confirmed { Status::Confirmed } else { Status::Failed },
		}
	}
}

pub(crate) struct Receiver {
	state: Mutex<State>,
	history: Mutex<BTreeMap<String, History>>,
	manager: Arc<ChannelManager>,
	keys: Arc<KeysManager>,
	chain: Arc<ChainSource>,
	fees: Arc<OnchainFeeEstimator>,
	store: Arc<DynStore>,
	config: Arc<Config>,
	transport: Arc<Transport>,
}

impl Receiver {
	pub(crate) fn new(
		manager: Arc<ChannelManager>, keys: Arc<KeysManager>, chain: Arc<ChainSource>,
		fees: Arc<OnchainFeeEstimator>, store: Arc<DynStore>, config: Arc<Config>,
		transport: Arc<Transport>,
	) -> Result<Self, BuildError> {
		let state: State = match KVStoreSync::read(&*store, NAMESPACE, "", STORE_KEY) {
			Ok(bytes) if bytes.len() <= MAX_STORE_BYTES => {
				serde_json::from_slice(&bytes).map_err(|_| BuildError::ReadFailed)?
			},
			Err(error) if error.kind() == lightning::io::ErrorKind::NotFound => State::default(),
			_ => return Err(BuildError::ReadFailed),
		};
		if state.requests.len() > MAX_RECORDS {
			return Err(BuildError::ReadFailed);
		}
		let chain_hash =
			bitcoin::constants::genesis_block(config.network).block_hash().to_byte_array();
		for (id, record) in &state.requests {
			let envelope = RequestEnvelope::decode(&record.envelope, now_ms(), &chain_hash, true)
				.map_err(|_| BuildError::ReadFailed)?;
			if codec::hex(&envelope.request_id) != *id
				|| envelope.receipt_hash != sha256::Hash::hash(&record.preimage).to_byte_array()
				|| SecretKey::from_slice(&record.secret)
					.map(|key| PublicKey::from_secret_key(&Secp256k1::signing_only(), &key))
					.ok() != Some(envelope.encryption_key)
				|| envelope.receiver_node_id
					!= PublicKey::from_secret_key(
						&Secp256k1::signing_only(),
						&keys.get_node_secret_key(),
					) {
				return Err(BuildError::ReadFailed);
			}
			validate_saved_record(record, &envelope).map_err(|_| BuildError::ReadFailed)?;
		}
		let mut history = BTreeMap::new();
		for id in KVStoreSync::list(&*store, NAMESPACE, HISTORY_NAMESPACE)
			.map_err(|_| BuildError::ReadFailed)?
		{
			let bytes = KVStoreSync::read(&*store, NAMESPACE, HISTORY_NAMESPACE, &id)
				.map_err(|_| BuildError::ReadFailed)?;
			if bytes.len() > 1024 {
				return Err(BuildError::ReadFailed);
			}
			let record: History =
				serde_json::from_slice(&bytes).map_err(|_| BuildError::ReadFailed)?;
			if record.request_id != id
				|| <[u8; 16]>::from_hex(&id).is_err()
				|| <[u8; 32]>::from_hex(&record.payment_hash).is_err()
				|| !(MIN_AMOUNT..=codec::MAX_AMOUNT_SAT).contains(&record.amount_sats)
				|| (record.confirmed && record.funding_txid.is_none())
				|| record.funding_txid.as_ref().is_some_and(|txid| Txid::from_str(txid).is_err())
			{
				return Err(BuildError::ReadFailed);
			}
			if let Some(pending) = state.requests.get(&id) {
				if History::from_request(&id, pending).ok().as_ref() != Some(&record) {
					return Err(BuildError::ReadFailed);
				}
			}
			history.insert(id, record);
		}
		Ok(Self {
			state: Mutex::new(state),
			history: Mutex::new(history),
			manager,
			keys,
			chain,
			fees,
			store,
			config,
			transport,
		})
	}

	fn persist(&self, state: State) -> Result<(), Error> {
		let bytes = serde_json::to_vec(&state).map_err(|_| Error::PersistenceFailed)?;
		if bytes.len() > MAX_STORE_BYTES {
			return Err(Error::PersistenceFailed);
		}
		KVStoreSync::write(&*self.store, NAMESPACE, "", STORE_KEY, bytes)
			.map_err(|_| Error::PersistenceFailed)
	}

	fn update<T>(&self, change: impl FnOnce(&mut State) -> Result<T, Error>) -> Result<T, Error> {
		let mut current = self.state.lock().unwrap();
		let mut next = current.clone();
		let result = change(&mut next)?;
		self.persist(next.clone())?;
		*current = next;
		Ok(result)
	}

	fn archive_expired(&self, now: u64) -> Result<(), Error> {
		// Lock order is always journal, then history. Persist each immutable archive before
		// removing its secret record. A crash between writes yields a deduplicated overlap.
		let mut current = self.state.lock().unwrap();
		let mut history = self.history.lock().unwrap();
		let completed: Vec<_> = current
			.requests
			.iter()
			.filter(|(_, record)| {
				record.expires_at < now
					&& record.session.as_ref().is_some_and(|session| !session.active())
			})
			.map(|(id, record)| History::from_request(id, record))
			.collect::<Result<_, _>>()?;
		if completed.is_empty() {
			return Ok(());
		}
		let mut next = current.clone();
		for record in completed {
			if let Some(existing) = history.get(&record.request_id) {
				if existing != &record {
					return Err(Error::PersistenceFailed);
				}
			} else {
				let bytes = serde_json::to_vec(&record).map_err(|_| Error::PersistenceFailed)?;
				KVStoreSync::write(
					&*self.store,
					NAMESPACE,
					HISTORY_NAMESPACE,
					&record.request_id,
					bytes,
				)
				.map_err(|_| Error::PersistenceFailed)?;
				history.insert(record.request_id.clone(), record.clone());
			}
			next.requests.remove(&record.request_id);
		}
		self.persist(next.clone())?;
		*current = next;
		Ok(())
	}

	pub(crate) fn mint(
		&self, amount: Option<u64>, expiry_seconds: u32, host: String, port: u16,
	) -> Result<DirectFundingRequestDetails, Error> {
		let primary = self.config.primary_node_id.ok_or(Error::Unavailable)?;
		if amount.is_some_and(|amount| !(MIN_AMOUNT..=codec::MAX_AMOUNT_SAT).contains(&amount))
			|| !(1..=codec::DEFAULT_REQUEST_TTL_MS / 1000).contains(&u64::from(expiry_seconds))
		{
			return Err(Error::AmountMismatch);
		}
		if self.has_pending() {
			return Err(Error::Busy);
		}
		let now = now_ms();
		self.archive_expired(now)?;
		let secret = crypto::random_secret();
		let mut preimage = [0; 32];
		let mut request_id = [0; 16];
		rand::rng().fill_bytes(&mut preimage);
		rand::rng().fill_bytes(&mut request_id);
		let mut envelope = RequestEnvelope {
			request_id,
			chain_hash: bitcoin::constants::genesis_block(self.config.network)
				.block_hash()
				.to_byte_array(),
			receiver_node_id: PublicKey::from_secret_key(
				&Secp256k1::signing_only(),
				&self.keys.get_node_secret_key(),
			),
			expires_at: now
				.checked_add(u64::from(expiry_seconds) * 1000)
				.ok_or(Error::InvalidRequest)?,
			amount_sat: amount,
			receipt_hash: sha256::Hash::hash(&preimage).to_byte_array(),
			encryption_key: PublicKey::from_secret_key(&Secp256k1::signing_only(), &secret),
			transports: vec![TransportDescriptor::Relay { relay_node_id: primary, host, port }],
			signature: [0; 65],
			signed_bytes: Vec::new(),
		};
		let message = envelope.prepare_signature(now).map_err(|_| Error::InvalidRequest)?;
		envelope.signature = crypto::sign_message(&message, &self.keys.get_node_secret_key());
		let encoded = envelope.encode().map_err(|_| Error::InvalidRequest)?;
		let record = Request {
			envelope: encoded.clone(),
			secret: secret.secret_bytes(),
			preimage,
			expires_at: envelope.expires_at,
			primary: primary.to_string(),
			attempts: 0,
			session: None,
			revoked: false,
		};
		self.update(|state| {
			// Expiry limits admission, not payment history or recovery. Only unused requests
			// can be discarded; completed and failed attempts remain visible after restart.
			state.requests.retain(|_, r| r.expires_at >= now || r.session.is_some());
			if state.requests.len() >= MAX_RECORDS {
				return Err(Error::Busy);
			}
			if state.requests.contains_key(&codec::hex(&request_id))
				|| self.history.lock().unwrap().contains_key(&codec::hex(&request_id))
			{
				return Err(Error::Busy);
			}
			state.requests.insert(codec::hex(&request_id), record);
			Ok(())
		})?;
		Ok(request_details(&envelope, encoded))
	}

	pub(crate) fn has_pending(&self) -> bool {
		self.state
			.lock()
			.unwrap()
			.requests
			.values()
			.any(|r| r.session.as_ref().is_some_and(Session::active))
	}

	/// Revoke an unused request on ordinary invoice settlement or explicit replacement.
	/// An active external funding negotiation must remain recoverable and cannot be torn down
	/// by closing the receive screen or settling another component of a composite invoice.
	pub(crate) fn invalidate(&self, request_id: &str) -> Result<(), Error> {
		self.update(|state| {
			let Some(record) = state.requests.get_mut(request_id) else {
				return match self.history.lock().unwrap().get(request_id) {
					Some(history) if history.confirmed => Err(Error::Busy),
					Some(_) => Ok(()),
					None => Err(Error::InvalidRequest),
				};
			};
			if record.session.as_ref().is_some_and(|session| session.active() || session.confirmed)
			{
				return Err(Error::Busy);
			}
			record.revoked = true;
			Ok(())
		})
	}

	pub(crate) fn payments(&self) -> Vec<DirectFundingPaymentDetails> {
		let state = self.state.lock().unwrap();
		let history = self.history.lock().unwrap();
		let mut payments: BTreeMap<_, _> =
			history.iter().map(|(id, record)| (id.clone(), record.details())).collect();
		payments.extend(state.requests.iter().filter_map(|(id, request)| {
			let session = request.session.as_ref()?;
			let offer = Offer::decode(&session.offer).ok()?;
			Some((
				id.clone(),
				DirectFundingPaymentDetails {
					request_id: id.clone(),
					payment_hash: codec::hex(&offer.receipt_hash),
					amount_sats: offer.amount_sat,
					fee_sats: Some(0),
					funding_txid: session.funding_txid.clone(),
					is_outbound: false,
					created_at: session.created_at,
					status: if session.confirmed {
						Status::Confirmed
					} else if session.mempool_seen {
						Status::MempoolSeen
					} else if session.witness.is_some() {
						Status::SignedPending
					} else if session.failed {
						Status::Failed
					} else {
						Status::Offered
					},
				},
			))
		}));
		payments.into_values().collect()
	}

	fn envelope(&self, request: &Request) -> Result<RequestEnvelope, Error> {
		RequestEnvelope::decode(
			&request.envelope,
			now_ms(),
			&bitcoin::constants::genesis_block(self.config.network).block_hash().to_byte_array(),
			true,
		)
		.map_err(|_| Error::PersistenceFailed)
	}

	fn keys_for(&self, request: &Request, ephemeral: &str) -> Result<LaneKeys, Error> {
		Ok(crypto::receiver_lane_keys(
			&SecretKey::from_slice(&request.secret).map_err(|_| Error::PersistenceFailed)?,
			&PublicKey::from_str(ephemeral).map_err(|_| Error::PersistenceFailed)?,
			&self.envelope(request)?.request_id,
		))
	}

	fn send(
		&self, request: &Request, session: &Session, subtype: u16, bytes: Vec<u8>,
	) -> Result<(), Error> {
		let id = self.envelope(request)?.request_id;
		let sealed = crypto::seal_frame(
			&self.keys_for(request, &session.ephemeral)?.send_key,
			&id,
			subtype,
			&bytes,
			None,
		)
		.map_err(|_| Error::InvalidFunding)?;
		self.transport.send(session.route.route()?, subtype, sealed)
	}

	pub(crate) async fn handle(&self, frame: Inbound) {
		if !matches!(frame.subtype, codec::OFFER | codec::WITNESS) {
			return;
		}
		let Some(sealed) = crypto::decode_frame(&frame.payload) else {
			return;
		};
		if frame.subtype == codec::OFFER {
			let (Some(id), Some(ephemeral)) = (sealed.request_id, sealed.ephemeral_public_key)
			else {
				return;
			};
			let key = codec::hex(&id);
			let record = self.state.lock().unwrap().requests.get(&key).cloned();
			let Some(record) = record else {
				return;
			};
			// A changed primary does not invalidate an existing obligation's introduction
			// route. Authorize the relay against the primary bound when this request was minted.
			if frame.route.relay_target.is_some() && record.primary != frame.route.peer.to_string()
			{
				return;
			}
			let Ok(keys) = self.keys_for(&record, &ephemeral.to_string()) else {
				return;
			};
			let Some(plain) = crypto::open_frame(&keys.recv_key, &id, codec::OFFER, &sealed) else {
				return;
			};
			let Ok(offer) = Offer::decode(&plain) else {
				return;
			};
			let _ = self.admit(&key, record, offer, plain, ephemeral, frame.route).await;
		} else {
			let records: Vec<_> = self
				.state
				.lock()
				.unwrap()
				.requests
				.iter()
				.filter_map(|(id, r)| {
					r.session
						.as_ref()
						.filter(|s| !s.failed && s.route.route().ok() == Some(frame.route))
						.map(|_| (id.clone(), r.clone()))
				})
				.collect();
			for (id, record) in records {
				let session = record.session.as_ref().unwrap();
				let Ok(keys) = self.keys_for(&record, &session.ephemeral) else {
					continue;
				};
				let Ok(envelope) = self.envelope(&record) else {
					continue;
				};
				let Some(plain) = crypto::open_frame(
					&keys.recv_key,
					&envelope.request_id,
					codec::WITNESS,
					&sealed,
				) else {
					continue;
				};
				let Ok(witness) = Witness::decode(&plain) else {
					continue;
				};
				let _ = self.accept_witness(&id, record, witness);
				break;
			}
		}
	}

	async fn admit(
		&self, id: &str, record: Request, offer: Offer, encoded_offer: Vec<u8>,
		ephemeral: PublicKey, route: Route,
	) -> Result<(), Error> {
		let mut session = Session {
			offer: encoded_offer,
			ephemeral: ephemeral.to_string(),
			route: SavedRoute::from_route(route),
			user_channel_id: rand::rng().random(),
			channel_id: None,
			is_splice: false,
			created_at: now_ms(),
			sign_request: None,
			witness: None,
			funding_txid: None,
			mempool_seen: false,
			confirmed: false,
			failed: false,
		};
		if let Some(existing) = &record.session {
			if existing.offer == session.offer
				&& existing.ephemeral == session.ephemeral
				&& !existing.failed
			{
				let mut replay = existing.clone();
				replay.route = session.route;
				self.update(|state| {
					state
						.requests
						.get_mut(id)
						.and_then(|r| r.session.as_mut())
						.ok_or(Error::InvalidRequest)?
						.route = replay.route.clone();
					Ok(())
				})?;
				self.replay(&record, &replay)?;
				return Ok(());
			}
			return self.decline(
				&record,
				&session,
				&offer,
				"request already has a funding attempt",
			);
		}
		let envelope = self.envelope(&record)?;
		let primary = self.config.primary_node_id.ok_or(Error::Unavailable)?;
		let problem = if record.revoked {
			Some("request revoked")
		} else if now_ms() >= record.expires_at {
			Some("request expired")
		} else if record.primary != primary.to_string() {
			Some("primary changed")
		} else if offer.receipt_hash != envelope.receipt_hash
			|| envelope.amount_sat.is_some_and(|v| v != offer.amount_sat)
		{
			Some("request amount or receipt mismatch")
		} else if !(MIN_AMOUNT..=codec::MAX_AMOUNT_SAT).contains(&offer.amount_sat)
			|| offer.amount_sat >= offer.value_sat
			|| offer.value_sat > codec::MAX_AMOUNT_SAT
			|| offer.sequence != Sequence::ENABLE_RBF_NO_LOCKTIME.0
		{
			Some("invalid offer values")
		} else if offer.offer_id
			!= codec::derive_offer_id(&offer.txid, offer.vout, offer.amount_sat)
		{
			Some("invalid offer identity")
		} else if !valid_change(&offer.change_script) {
			Some("unsupported change script")
		} else if record.attempts >= 3 || self.has_pending() {
			Some("funding already pending")
		} else {
			None
		};
		if let Some(reason) = problem {
			return self.decline(&record, &session, &offer, reason);
		}
		let transaction = self
			.chain
			.fetch_transaction(offer.outpoint().txid)
			.await
			.map_err(|_| Error::ChainUnavailable)?;
		let output =
			transaction.output.get(offer.vout as usize).ok_or(Error::InvalidFunding)?.clone();
		if transaction.is_coinbase()
			|| output.value.to_sat() != offer.value_sat
			|| !crypto::verify_ownership(
				&offer,
				output.script_pubkey.as_bytes(),
				&envelope.receiver_node_id,
			) {
			return self.decline(&record, &session, &offer, "invalid coin ownership proof");
		}
		if !matches!(
			self.chain.fetch_transaction_status(offer.outpoint().txid).await,
			Ok(ConfirmationStatus::Confirmed { .. })
		) || !self
			.chain
			.is_unspent_output(offer.outpoint(), output.clone())
			.await
			.map_err(|_| Error::ChainUnavailable)?
		{
			return self.decline(&record, &session, &offer, "coin must be confirmed and unspent");
		}
		let channels: Vec<_> = self
			.manager
			.list_channels()
			.into_iter()
			.filter(|c| c.counterparty.node_id == primary)
			.collect();
		if self.manager.has_pending_funding_operation()
			|| channels.iter().any(|c| !c.is_channel_ready || !c.is_usable)
		{
			return self.decline(&record, &session, &offer, "channel funding already pending");
		}
		let channel = channels.first();
		session.is_splice = channel.is_some();
		session.channel_id = channel.map(|c| c.channel_id.to_string());
		if let Some(channel) = channel {
			session.user_channel_id = channel.user_channel_id;
		}
		let input = if output.script_pubkey.is_p2tr() {
			FundingTxInput::new_p2tr_key_spend(transaction, offer.vout)
		} else {
			FundingTxInput::new_p2wpkh(transaction, offer.vout)
		}
		.map_err(|_| Error::InvalidFunding)?;
		let rate = u32::try_from(
			self.fees.estimate_fee_rate(ConfirmationTarget::ChannelFunding).to_sat_per_kwu(),
		)
		.map_err(|_| Error::InvalidFunding)?;
		self.update(|state| {
			if state
				.requests
				.values()
				.any(|r| r.session.as_ref().is_some_and(|s| !s.failed && !s.confirmed))
			{
				return Err(Error::Busy);
			}
			let request = state.requests.get_mut(id).ok_or(Error::InvalidRequest)?;
			if request.revoked || request.session.is_some() || now_ms() >= request.expires_at {
				return Err(Error::Expired);
			}
			request.attempts += 1;
			request.session = Some(session.clone());
			Ok(())
		})?;
		let result = if let Some(channel) = channel {
			self.manager
				.splice_channel_with_minimum_depth(
					&channel.channel_id,
					&primary,
					SpliceContribution::SpliceIn {
						value: Amount::from_sat(offer.amount_sat),
						inputs: vec![input],
						change_script: Some(ScriptBuf::from_bytes(offer.change_script.clone())),
					},
					rate,
					None,
					3,
				)
				.map(|_| channel.channel_id)
		} else {
			let mut config = default_user_config(&self.config);
			config.channel_handshake_config.announce_for_forwarding = false;
			self.manager.create_channel_v2(
				primary,
				offer.amount_sat,
				vec![input],
				ScriptBuf::from_bytes(offer.change_script.clone()),
				rate,
				session.user_channel_id,
				Some(config),
			)
		};
		match result {
			Ok(channel_id) => {
				self.update(|state| {
					state
						.requests
						.get_mut(id)
						.and_then(|r| r.session.as_mut())
						.ok_or(Error::PersistenceFailed)?
						.channel_id = Some(channel_id.to_string());
					Ok(())
				})?;
				self.send(
					&record,
					&session,
					codec::OFFER_ACK,
					OfferAck { offer_id: offer.offer_id, accepted: true, reason: None }
						.encode()
						.map_err(|_| Error::InvalidFunding)?,
				)
			},
			Err(_) => {
				self.update(|state| {
					state
						.requests
						.get_mut(id)
						.and_then(|r| r.session.as_mut())
						.ok_or(Error::PersistenceFailed)?
						.failed = true;
					Ok(())
				})?;
				self.decline(&record, &session, &offer, "primary could not start funding")
			},
		}
	}

	fn decline(
		&self, record: &Request, session: &Session, offer: &Offer, reason: &str,
	) -> Result<(), Error> {
		self.send(
			record,
			session,
			codec::OFFER_ACK,
			OfferAck { offer_id: offer.offer_id, accepted: false, reason: Some(reason.to_owned()) }
				.encode()
				.map_err(|_| Error::InvalidFunding)?,
		)
	}

	fn replay(&self, record: &Request, session: &Session) -> Result<(), Error> {
		let offer = Offer::decode(&session.offer).map_err(|_| Error::PersistenceFailed)?;
		self.send(
			record,
			session,
			codec::OFFER_ACK,
			OfferAck { offer_id: offer.offer_id, accepted: true, reason: None }
				.encode()
				.map_err(|_| Error::InvalidFunding)?,
		)?;
		if session.mempool_seen || session.confirmed {
			return self.send_receipt(record, session);
		}
		if let Some(bytes) = &session.sign_request {
			self.send(record, session, codec::SIGN_REQUEST, bytes.clone())?;
		}
		Ok(())
	}

	pub(crate) fn funding_ready(
		&self, channel_id: ChannelId, peer: PublicKey, user_id: u128, transaction: &Transaction,
	) -> Result<bool, Error> {
		let found = self
			.state
			.lock()
			.unwrap()
			.requests
			.iter()
			.find(|(_, r)| {
				r.primary == peer.to_string()
					&& r.session
						.as_ref()
						.is_some_and(|s| s.active() && s.user_channel_id == user_id)
			})
			.map(|(id, r)| (id.clone(), r.clone()));
		let Some((id, record)) = found else {
			return Ok(false);
		};
		let session = record.session.as_ref().ok_or(Error::PersistenceFailed)?;
		let offer = Offer::decode(&session.offer).map_err(|_| Error::PersistenceFailed)?;
		let details = self
			.manager
			.funding_signing_details(&channel_id, &peer)
			.map_err(|_| Error::InvalidFunding)?;
		if &details.unsigned_transaction != transaction {
			return Err(Error::InvalidFunding);
		}
		let sign_request = make_sign_request(&offer, &details, &self.keys.get_node_secret_key())?;
		let bytes = sign_request.encode().map_err(|_| Error::InvalidFunding)?;
		self.update(|state| {
			let current = state
				.requests
				.get_mut(&id)
				.and_then(|r| r.session.as_mut())
				.ok_or(Error::PersistenceFailed)?;
			if current.sign_request.as_ref().is_some_and(|old| old != &bytes) {
				return Err(Error::InvalidFunding);
			}
			current.channel_id = Some(channel_id.to_string());
			current.sign_request = Some(bytes.clone());
			current.funding_txid = Some(transaction.compute_txid().to_string());
			Ok(())
		})?;
		if let Some(witness) = &session.witness {
			self.submit_witness(channel_id, peer, &offer, &sign_request, witness.clone())?;
		} else {
			self.send(&record, session, codec::SIGN_REQUEST, bytes)?;
		}
		Ok(true)
	}

	fn accept_witness(&self, id: &str, record: Request, witness: Witness) -> Result<(), Error> {
		let session = record.session.as_ref().ok_or(Error::InvalidFunding)?;
		let offer = Offer::decode(&session.offer).map_err(|_| Error::InvalidFunding)?;
		if witness.offer_id != offer.offer_id {
			return Err(Error::InvalidFunding);
		}
		if session.mempool_seen || session.confirmed {
			return self.send_receipt(&record, session);
		}
		let signed =
			SignRequest::decode(session.sign_request.as_deref().ok_or(Error::InvalidFunding)?)
				.map_err(|_| Error::InvalidFunding)?;
		let channel =
			parse_channel_id(session.channel_id.as_deref().ok_or(Error::InvalidFunding)?)?;
		let peer = PublicKey::from_str(&record.primary).map_err(|_| Error::InvalidFunding)?;
		// Validate the witness ourselves before making it a durable obligation;
		// the native manager verifies it again before accepting it.
		verify_payer_witness(&offer, &signed, &witness.witness)?;
		self.update(|state| {
			let current = state
				.requests
				.get_mut(id)
				.and_then(|r| r.session.as_mut())
				.ok_or(Error::PersistenceFailed)?;
			if current.witness.as_ref().is_some_and(|old| old != &witness.witness) {
				return Err(Error::InvalidFunding);
			}
			current.witness = Some(witness.witness.clone());
			Ok(())
		})?;
		self.submit_witness(channel, peer, &offer, &signed, witness.witness)
	}

	fn submit_witness(
		&self, channel: ChannelId, peer: PublicKey, offer: &Offer, signed: &SignRequest,
		witness: Vec<Vec<u8>>,
	) -> Result<(), Error> {
		let mut transaction = signed.transaction().map_err(|_| Error::InvalidFunding)?;
		let details = self
			.manager
			.funding_signing_details(&channel, &peer)
			.map_err(|_| Error::InvalidFunding)?;
		if details.unsigned_transaction != transaction {
			return Err(Error::InvalidFunding);
		}
		if details.local_witnesses_submitted {
			return Ok(());
		}
		let input = transaction
			.input
			.iter_mut()
			.find(|input| input.previous_output == offer.outpoint())
			.ok_or(Error::InvalidFunding)?;
		input.witness = bitcoin::Witness::from_slice(&witness);
		self.manager
			.funding_transaction_signed(&channel, &peer, transaction)
			.map_err(|_| Error::InvalidFunding)
	}

	fn send_receipt(&self, record: &Request, session: &Session) -> Result<(), Error> {
		let offer = Offer::decode(&session.offer).map_err(|_| Error::PersistenceFailed)?;
		let txid = Txid::from_str(session.funding_txid.as_deref().ok_or(Error::PersistenceFailed)?)
			.map_err(|_| Error::PersistenceFailed)?;
		self.send(
			record,
			session,
			codec::RECEIPT,
			Receipt {
				offer_id: offer.offer_id,
				preimage: record.preimage,
				funding_txid: codec::txid_to_display(txid),
				raw_tx: None,
			}
			.encode()
			.map_err(|_| Error::InvalidFunding)?,
		)
	}

	pub(crate) async fn tick(&self) {
		let records: Vec<_> = self
			.state
			.lock()
			.unwrap()
			.requests
			.iter()
			.filter(|(_, r)| r.session.as_ref().is_some_and(Session::active))
			.map(|(id, r)| (id.clone(), r.clone()))
			.collect();
		for (id, record) in records {
			let session = record.session.as_ref().unwrap();
			if session.witness.is_some() {
				// The journal is committed before native submission. A crash or a temporarily
				// unavailable monitor may occur between them; replay only the identical witness.
				let _ = self.resume_witness(&record, session);
				if let Some(txid) =
					session.funding_txid.as_deref().and_then(|id| Txid::from_str(id).ok())
				{
					if let (Ok(status), Ok(transaction)) = (
						self.chain.fetch_transaction_status(txid).await,
						self.chain.fetch_transaction(txid).await,
					) {
						if !observed_transaction_matches(session, &transaction) {
							continue;
						}
						let confirmed = matches!(status, ConfirmationStatus::Confirmed { .. });
						if self
							.update(|state| {
								let current = state
									.requests
									.get_mut(&id)
									.and_then(|r| r.session.as_mut())
									.ok_or(Error::PersistenceFailed)?;
								current.mempool_seen = true;
								current.confirmed = confirmed;
								Ok(())
							})
							.is_ok()
						{
							let _ = self.send_receipt(&record, session);
						}
					}
				}
				continue;
			}
			if now_ms().saturating_sub(session.created_at) < SESSION_TIMEOUT_MS {
				continue;
			}
			let Ok(peer) = PublicKey::from_str(&record.primary) else {
				continue;
			};
			// V2's permanent ID replaces its temporary ID during acceptance. The persisted
			// user ID lets us find the live negotiation even if the application crashed then.
			let channel = self.manager.list_channels().into_iter().find(|channel| {
				channel.counterparty.node_id == peer
					&& channel.user_channel_id == session.user_channel_id
			});
			let safe_to_release = if let Some(channel) = channel {
				if session.is_splice {
					self.manager.abandon_splice(&channel.channel_id, &peer).is_ok()
						|| (session.sign_request.is_none()
							&& !self.manager.has_pending_funding_operation())
				} else {
					self.manager.abandon_unfunded_channel(&channel.channel_id, &peer).is_ok()
				}
			} else {
				// Native LDK intentionally forgets precommitment openings on disconnect/restart.
				// A sign request proves a durable commitment existed: retain those obligations.
				session.sign_request.is_none()
			};
			if safe_to_release {
				let _ = self.update(|state| {
					let current = state
						.requests
						.get_mut(&id)
						.and_then(|r| r.session.as_mut())
						.ok_or(Error::PersistenceFailed)?;
					if current.witness.is_some() || current.sign_request != session.sign_request {
						return Err(Error::Busy);
					}
					current.failed = true;
					Ok(())
				});
			}
		}
	}

	fn resume_witness(&self, record: &Request, session: &Session) -> Result<(), Error> {
		let offer = Offer::decode(&session.offer).map_err(|_| Error::PersistenceFailed)?;
		let request =
			SignRequest::decode(session.sign_request.as_deref().ok_or(Error::PersistenceFailed)?)
				.map_err(|_| Error::PersistenceFailed)?;
		let channel =
			parse_channel_id(session.channel_id.as_deref().ok_or(Error::PersistenceFailed)?)?;
		let peer = PublicKey::from_str(&record.primary).map_err(|_| Error::PersistenceFailed)?;
		self.submit_witness(
			channel,
			peer,
			&offer,
			&request,
			session.witness.clone().ok_or(Error::PersistenceFailed)?,
		)
	}
}

fn validate_saved_record(record: &Request, envelope: &RequestEnvelope) -> Result<(), Error> {
	if record.expires_at != envelope.expires_at
		|| PublicKey::from_str(&record.primary).is_err()
		|| record.attempts > 3
	{
		return Err(Error::PersistenceFailed);
	}
	let Some(session) = &record.session else {
		return Ok(());
	};
	let offer = Offer::decode(&session.offer).map_err(|_| Error::PersistenceFailed)?;
	let route = session.route.route()?;
	if offer.receipt_hash != envelope.receipt_hash
		|| envelope.amount_sat.is_some_and(|amount| amount != offer.amount_sat)
		|| PublicKey::from_str(&session.ephemeral).is_err()
		|| (route.relay_target.is_some() && route.peer.to_string() != record.primary)
		|| (session.confirmed && !session.mempool_seen)
		|| (session.failed
			&& (session.witness.is_some() || session.mempool_seen || session.confirmed))
		|| ((session.mempool_seen || session.confirmed) && session.witness.is_none())
	{
		return Err(Error::PersistenceFailed);
	}
	if let Some(channel) = &session.channel_id {
		parse_channel_id(channel).map_err(|_| Error::PersistenceFailed)?;
	}
	if let Some(bytes) = &session.sign_request {
		let request = SignRequest::decode(bytes).map_err(|_| Error::PersistenceFailed)?;
		let tx = request.transaction().map_err(|_| Error::PersistenceFailed)?;
		if request.offer_id != offer.offer_id
			|| !request.verify_attestation(&envelope.receiver_node_id)
			|| session.channel_id.is_none()
			|| session.is_splice != request.shared_input_index.is_some()
			|| session.funding_txid.as_deref() != Some(tx.compute_txid().to_string().as_str())
		{
			return Err(Error::PersistenceFailed);
		}
		if let Some(witness) = &session.witness {
			verify_payer_witness(&offer, &request, witness)
				.map_err(|_| Error::PersistenceFailed)?;
		}
	} else if session.witness.is_some() || session.funding_txid.is_some() {
		return Err(Error::PersistenceFailed);
	}
	Ok(())
}

fn observed_transaction_matches(session: &Session, transaction: &Transaction) -> bool {
	let Some(witness) = &session.witness else {
		return false;
	};
	let Ok(offer) = Offer::decode(&session.offer) else {
		return false;
	};
	let Some(request) =
		session.sign_request.as_deref().and_then(|bytes| SignRequest::decode(bytes).ok())
	else {
		return false;
	};
	let Ok(expected) = request.transaction() else {
		return false;
	};
	if transaction.input.iter().any(|input| input.witness.is_empty()) {
		return false;
	}
	let Some(input) =
		transaction.input.iter().find(|input| input.previous_output == offer.outpoint())
	else {
		return false;
	};
	if input.witness != bitcoin::Witness::from_slice(witness) {
		return false;
	}
	let mut unsigned = transaction.clone();
	for input in &mut unsigned.input {
		input.witness.clear();
	}
	unsigned == expected && verify_payer_witness(&offer, &request, witness).is_ok()
}

fn valid_change(bytes: &[u8]) -> bool {
	let script = ScriptBuf::from_bytes(bytes.to_vec());
	script.is_p2wpkh()
		|| script.is_p2tr()
		|| script.is_p2pkh()
		|| script.is_p2sh()
		|| script.is_p2wsh()
}

fn funding_keys(script: &ScriptBuf) -> Result<FundingPubkeys, Error> {
	let bytes = script.as_bytes();
	if bytes.len() != 71
		|| bytes[0] != 0x52
		|| bytes[1] != 33
		|| bytes[35] != 33
		|| bytes[69..] != [0x52, 0xae]
	{
		return Err(Error::InvalidFunding);
	}
	Ok(FundingPubkeys {
		local: PublicKey::from_slice(&bytes[2..35]).map_err(|_| Error::InvalidFunding)?,
		remote: PublicKey::from_slice(&bytes[36..69]).map_err(|_| Error::InvalidFunding)?,
	})
}

fn make_sign_request(
	offer: &Offer, details: &FundingSigningDetails, node_secret: &SecretKey,
) -> Result<SignRequest, Error> {
	let tx = &details.unsigned_transaction;
	let index = usize::from(details.funding_output_index);
	let funding = tx.output.get(index).ok_or(Error::InvalidFunding)?;
	if funding.script_pubkey != details.funding_redeem_script.to_p2wsh()
		|| tx.input.len() != details.prevouts.len()
		|| tx.input.len() != if details.shared_input_index.is_some() { 2 } else { 1 }
		|| tx.output.len() > 2
		|| tx.input.iter().any(|i| !i.witness.is_empty() || !i.script_sig.is_empty())
	{
		return Err(Error::InvalidFunding);
	}
	let payer_index = tx
		.input
		.iter()
		.position(|i| i.previous_output == offer.outpoint())
		.ok_or(Error::InvalidFunding)?;
	if tx.input[payer_index].sequence.0 != offer.sequence
		|| details.prevouts[payer_index].value.to_sat() != offer.value_sat
	{
		return Err(Error::InvalidFunding);
	}
	let base = match details.shared_input_index {
		Some(i) if usize::from(i) != payer_index => {
			details.prevouts.get(usize::from(i)).ok_or(Error::InvalidFunding)?.value.to_sat()
		},
		None => 0,
		_ => return Err(Error::InvalidFunding),
	};
	if funding.value.to_sat() != base.checked_add(offer.amount_sat).ok_or(Error::InvalidFunding)? {
		return Err(Error::InvalidFunding);
	}
	let mut change = 0u64;
	for (i, output) in tx.output.iter().enumerate() {
		if i != index {
			if output.script_pubkey.as_bytes() != offer.change_script {
				return Err(Error::InvalidFunding);
			}
			change = change.checked_add(output.value.to_sat()).ok_or(Error::InvalidFunding)?;
		}
	}
	let fee = offer
		.value_sat
		.checked_sub(offer.amount_sat)
		.and_then(|v| v.checked_sub(change))
		.ok_or(Error::InvalidFunding)?;
	if fee > offer.max_total_fee_sat {
		return Err(Error::InvalidFunding);
	}
	let keys = funding_keys(&details.funding_redeem_script)?;
	let prior = details.previous_funding_redeem_script.as_ref().map(funding_keys).transpose()?;
	let prior = prior.filter(|prior| prior != &keys);
	let mut request = SignRequest {
		offer_id: offer.offer_id,
		raw_tx: bitcoin::consensus::serialize(tx),
		prevouts: details
			.prevouts
			.iter()
			.map(|o| Prevout {
				value_sat: o.value.to_sat(),
				script: o.script_pubkey.as_bytes().to_vec(),
			})
			.collect(),
		shared_input_index: details.shared_input_index.map(u32::from),
		attestation: Attestation {
			funding_output_index: u32::from(details.funding_output_index),
			local_funding_pubkey: keys.local,
			remote_funding_pubkey: keys.remote,
			prior_funding_pubkeys: prior,
			signature: [0; 65],
		},
	};
	request.attestation.signature = crypto::sign_message(
		&request.attestation_message().map_err(|_| Error::InvalidFunding)?,
		node_secret,
	);
	Ok(request)
}

fn verify_payer_witness(
	offer: &Offer, request: &SignRequest, witness: &[Vec<u8>],
) -> Result<(), Error> {
	use bitcoin::secp256k1::{ecdsa, schnorr, Message, XOnlyPublicKey};
	use bitcoin::sighash::{Prevouts, SighashCache};
	use bitcoin::{EcdsaSighashType, TapSighashType};
	let tx = request.transaction().map_err(|_| Error::InvalidFunding)?;
	let index = tx
		.input
		.iter()
		.position(|i| i.previous_output == offer.outpoint())
		.ok_or(Error::InvalidFunding)?;
	let prevouts: Vec<_> = request.prevouts.iter().map(Prevout::txout).collect();
	let previous = prevouts.get(index).ok_or(Error::InvalidFunding)?;
	let secp = Secp256k1::verification_only();
	let mut cache = SighashCache::new(&tx);
	if previous.script_pubkey.is_p2wpkh() && witness.len() == 2 {
		let key = PublicKey::from_slice(&witness[1]).map_err(|_| Error::InvalidFunding)?;
		if bitcoin::hashes::hash160::Hash::hash(&key.serialize()).as_byte_array()
			!= &previous.script_pubkey.as_bytes()[2..]
			|| witness[0].last() != Some(&(EcdsaSighashType::All as u8))
		{
			return Err(Error::InvalidFunding);
		}
		let signature = ecdsa::Signature::from_der(&witness[0][..witness[0].len() - 1])
			.map_err(|_| Error::InvalidFunding)?;
		let hash = cache
			.p2wpkh_signature_hash(
				index,
				&previous.script_pubkey,
				previous.value,
				EcdsaSighashType::All,
			)
			.map_err(|_| Error::InvalidFunding)?;
		secp.verify_ecdsa(&Message::from_digest(hash.to_byte_array()), &signature, &key)
			.map_err(|_| Error::InvalidFunding)
	} else if previous.script_pubkey.is_p2tr() && witness.len() == 1 {
		let bytes = &witness[0];
		let ty = match bytes.len() {
			64 => TapSighashType::Default,
			65 if bytes[64] == 1 => TapSighashType::All,
			_ => return Err(Error::InvalidFunding),
		};
		let signature =
			schnorr::Signature::from_slice(&bytes[..64]).map_err(|_| Error::InvalidFunding)?;
		let key = XOnlyPublicKey::from_slice(&previous.script_pubkey.as_bytes()[2..])
			.map_err(|_| Error::InvalidFunding)?;
		let hash = cache
			.taproot_key_spend_signature_hash(index, &Prevouts::All(&prevouts), ty)
			.map_err(|_| Error::InvalidFunding)?;
		secp.verify_schnorr(&signature, &Message::from_digest(hash.to_byte_array()), &key)
			.map_err(|_| Error::InvalidFunding)
	} else {
		Err(Error::InvalidFunding)
	}
}

fn parse_channel_id(value: &str) -> Result<ChannelId, Error> {
	<[u8; 32]>::from_hex(value).map(ChannelId::from_bytes).map_err(|_| Error::InvalidFunding)
}

#[cfg(all(test, not(feature = "uniffi")))]
mod tests;
