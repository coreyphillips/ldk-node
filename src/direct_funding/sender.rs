//! Durable payer for Beignet v3 direct channel funding.
//!
//! The receiver is adversarial. Its complete transaction and every prevout are checked before
//! signing one reserved wallet input. A durable SignedPending record precedes witness emission;
//! every later timeout or disconnect returns that record instead of authorizing a fallback.
#![forbid(unsafe_code)]

use lightning::io::ErrorKind;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bitcoin::hashes::{hash160, sha256, Hash};
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{Amount, OutPoint, ScriptBuf, Transaction, TxOut, Txid};
use lightning::ln::chan_utils::make_funding_redeemscript;
use lightning::util::persist::KVStoreSync;
use serde::{Deserialize, Serialize};
use tokio::time::{timeout_at, Instant};

use super::codec::{
	self, CodecError, Offer, OfferAck, OwnershipProof, ProbeProof, Receipt, RequestEnvelope,
	SignRequest, Witness,
};
use super::crypto::{self, LaneKeys};
use super::{now_ms, DirectFundingError as Error};
use crate::chain::ChainSource;
use crate::config::Config;
use crate::payment::ConfirmationStatus;
use crate::types::{ChannelManager, DynStore, Wallet};

const STORE_NAMESPACE: &str = "direct_funding";
const STORE_KEY: &str = "sender_v1";
const MAX_RECORDS: usize = 512;
const MAX_STORE_BYTES: usize = 32 * 1024 * 1024;
const RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1000;
const OFFER_TIMEOUT: Duration = Duration::from_secs(120);
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(45);
const RETRY_SECONDS: [u64; 5] = [4, 12, 30, 60, 90];
const PAYER_SEQUENCE: u32 = 0xfffffffd;

/// A transport authenticated to the envelope's receiver, directly or through its relay.
/// Frames here are sealed. Returning an error from send means nothing was enqueued; after
/// witness commitment the sender still conservatively retains the pending payment.
pub(crate) trait SenderTransport: Send {
	fn send(&self, subtype: u16, sealed: Vec<u8>) -> Result<(), Error>;
	fn receive<'a>(
		&'a mut self,
	) -> Pin<Box<dyn Future<Output = Option<(u16, Vec<u8>)>> + Send + 'a>>;
}

/// A persisted payer state. Only Aborted has never committed a witness.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum SenderPaymentStatus {
	Offered,
	SignedPending,
	MempoolSeen,
	Confirmed,
	Aborted,
	Failed,
}
impl SenderPaymentStatus {
	fn committed(self) -> bool {
		matches!(self, Self::SignedPending | Self::MempoolSeen | Self::Confirmed | Self::Failed)
	}
	fn holds_coin(self) -> bool {
		matches!(self, Self::Offered | Self::SignedPending | Self::MempoolSeen)
	}
}

/// Secret-free information about an attempted direct-funding payment.
#[derive(Clone, Debug)]
pub struct SendResult {
	pub request_id: String,
	pub created_at: u64,
	pub payment_hash: String,
	pub amount_sats: u64,
	pub fee_sats: Option<u64>,
	pub funding_txid: Option<String>,
	pub status: SenderPaymentStatus,
	pub caveat: Option<String>,
}

/// Verified request metadata, obtained without spending or reserving any coin.
pub(crate) struct PreparedRequest {
	pub envelope: RequestEnvelope,
	pub amount_sats: Option<u64>,
	pub prior_result: Option<SendResult>,
}

#[derive(Clone, Serialize, Deserialize)]
struct Record {
	request: String,
	request_id: String,
	offer: Vec<u8>,
	coin_script: Vec<u8>,
	status: SenderPaymentStatus,
	created_at: u64,
	ephemeral_secret: [u8; 32],
	sign_request: Option<Vec<u8>>,
	witness: Option<Vec<u8>>,
	funding_txid: Option<String>,
	fee_sats: Option<u64>,
	receipt_preimage: Option<String>,
	caveat: Option<String>,
}
impl Record {
	fn offer(&self) -> Result<Offer, Error> {
		Offer::decode(&self.offer).map_err(|_| Error::PersistenceFailed)
	}
	fn result(&self) -> Result<SendResult, Error> {
		let offer = self.offer()?;
		Ok(SendResult {
			request_id: self.request_id.clone(),
			created_at: self.created_at,
			payment_hash: codec::hex(&offer.receipt_hash),
			amount_sats: offer.amount_sat,
			fee_sats: self.fee_sats,
			funding_txid: self.funding_txid.clone(),
			status: self.status,
			caveat: self.caveat.clone(),
		})
	}
}
#[derive(Default)]
struct State {
	records: HashMap<String, Record>,
	faulted: bool,
}

/// The sender owns its journal and coordinates reservations with every native wallet signer.
pub(crate) struct Sender {
	wallet: Arc<Wallet>,
	chain: Arc<ChainSource>,
	store: Arc<DynStore>,
	config: Arc<Config>,
	channel_manager: Arc<ChannelManager>,
	chain_hash: [u8; 32],
	state: Mutex<State>,
	operation: tokio::sync::Mutex<()>,
}
impl Sender {
	/// Restore the journal before the node is made available. Corrupt or unreadable state fails
	/// closed because silently losing it could spend a coin whose witness is already outside.
	pub(crate) fn new(
		wallet: Arc<Wallet>, chain: Arc<ChainSource>, store: Arc<DynStore>, config: Arc<Config>,
		channel_manager: Arc<ChannelManager>,
	) -> Result<Self, Error> {
		let chain_hash = bitcoin::blockdata::constants::genesis_block(config.network)
			.block_hash()
			.to_byte_array();
		let bytes = match KVStoreSync::read(&*store, STORE_NAMESPACE, "", STORE_KEY) {
			Ok(bytes) => bytes,
			Err(error) if error.kind() == ErrorKind::NotFound => Vec::new(),
			Err(_) => return Err(Error::PersistenceFailed),
		};
		if bytes.len() > MAX_STORE_BYTES {
			return Err(Error::PersistenceFailed);
		}
		let records: Vec<Record> = if bytes.is_empty() {
			Vec::new()
		} else {
			serde_json::from_slice(&bytes).map_err(|_| Error::PersistenceFailed)?
		};
		if records.len() > MAX_RECORDS {
			return Err(Error::PersistenceFailed);
		}
		let mut state = State::default();
		for record in records {
			validate_record(&record, &chain_hash)?;
			if state.records.insert(record.request_id.clone(), record).is_some() {
				return Err(Error::PersistenceFailed);
			}
		}
		// Validate the whole store before installing any reservation.
		let mut outpoints = HashSet::new();
		for record in state.records.values().filter(|record| record.status.holds_coin()) {
			let outpoint = record.offer()?.outpoint();
			if !outpoints.insert(outpoint) {
				return Err(Error::PersistenceFailed);
			}
		}
		for record in state.records.values().filter(|record| record.status.holds_coin()) {
			if !wallet
				.restore_direct_funding_reservation(&record.request_id, record.offer()?.outpoint())
			{
				return Err(Error::PersistenceFailed);
			}
		}
		Ok(Self {
			wallet,
			chain,
			store,
			config,
			channel_manager,
			chain_hash,
			state: Mutex::new(state),
			operation: tokio::sync::Mutex::new(()),
		})
	}

	pub(crate) fn prepare(
		&self, encoded: &str, amount: Option<u64>,
	) -> Result<PreparedRequest, Error> {
		let envelope = RequestEnvelope::decode(encoded, now_ms(), &self.chain_hash, true)
			.map_err(map_codec)?;
		let state = self.state.lock().unwrap();
		let record = state.records.get(&codec::hex(&envelope.request_id));
		if let Some(record) = record {
			if record.request != encoded {
				return Err(Error::InvalidRequest);
			}
		}
		// Once a witness was committed, callers must always see the existing payment,
		// including after a later storage failure or an attempted amount change. It is
		// no longer safe to treat this request as a fresh, failed payment.
		if let Some(record) = record.filter(|record| record.status.committed()) {
			let mut result = record.result()?;
			if state.faulted {
				result.caveat = Some(Error::PersistenceFailed.to_string());
			}
			return Ok(PreparedRequest {
				envelope,
				amount_sats: Some(result.amount_sats),
				prior_result: Some(result),
			});
		}
		if state.faulted {
			return Err(Error::PersistenceFailed);
		}
		if record.is_none() && envelope.expires_at <= now_ms() {
			return Err(Error::Expired);
		}
		let amount_sats = resolve_amount(envelope.amount_sat, amount)?;
		if record.is_some_and(|record| {
			amount_sats.is_some_and(|amount| {
				record.offer().map_or(true, |offer| offer.amount_sat != amount)
			})
		}) {
			return Err(Error::AmountMismatch);
		}
		let prior_result = record.map(Record::result).transpose()?;
		Ok(PreparedRequest { envelope, amount_sats, prior_result })
	}

	/// Retain terminal activity for 30 days, bounded by 512 total records. At
	/// capacity only expired terminal requests may be removed; committed pending
	/// records remain durable without a time limit. Apps may keep longer history.
	pub(crate) fn list(&self) -> Vec<SendResult> {
		self.state
			.lock()
			.unwrap()
			.records
			.values()
			.filter_map(|record| record.result().ok())
			.collect()
	}

	/// Execute one exchange. Concurrent calls serialize, including duplicate requests: returning
	/// Busy while a duplicate may still sign would incorrectly permit a parallel fallback.
	pub(crate) async fn send(
		&self, encoded: &str, amount: Option<u64>, max_fee_sats: u64,
		transport: &mut dyn SenderTransport,
	) -> Result<SendResult, Error> {
		let _operation = self.operation.lock().await;
		let prepared = self.prepare(encoded, amount)?;
		let amount_sats = prepared
			.amount_sats
			.or_else(|| prepared.prior_result.as_ref().map(|result| result.amount_sats))
			.ok_or(Error::AmountRequired)?;
		let id = codec::hex(&prepared.envelope.request_id);
		if let Some(previous) = &prepared.prior_result {
			// A failed durable write may have left a committed record only in memory.
			// Never emit or re-emit its witness until restart resolves the durable state.
			if previous.status.committed() && self.state.lock().unwrap().faulted {
				return Ok(previous.clone());
			}
			if previous.status == SenderPaymentStatus::Aborted {
				return Err(Error::Declined);
			}
			if matches!(
				previous.status,
				SenderPaymentStatus::Confirmed | SenderPaymentStatus::Failed
			) {
				return Ok(previous.clone());
			}
		}
		let record = match self.record(&id) {
			Some(record) => record,
			None => {
				if self.channel_manager.has_pending_funding_operation() {
					return Err(Error::Busy);
				}
				self.begin(encoded, &prepared.envelope, amount_sats, max_fee_sats)?
			},
		};
		let result =
			self.exchange(&prepared.envelope, record.clone(), max_fee_sats, transport).await;
		match result {
			Ok(()) => self.result(&id),
			Err(error) => {
				let current = self.record(&id).ok_or(Error::PersistenceFailed)?;
				if current.status.committed() {
					Ok(self.pending_result(&current, error.to_string()))
				} else {
					self.abort(&id, error)?;
					Err(error)
				}
			},
		}
	}

	fn begin(
		&self, encoded: &str, envelope: &RequestEnvelope, amount: u64, max_fee: u64,
	) -> Result<Record, Error> {
		let required = amount
			.checked_add(max_fee)
			.filter(|value| *value <= codec::MAX_AMOUNT_SAT)
			.ok_or(Error::AmountMismatch)?;
		self.make_record_room()?;
		let id = codec::hex(&envelope.request_id);
		let reserve =
			crate::total_anchor_channels_reserve_sats(&self.channel_manager, &self.config);
		let (coin, change) =
			self.wallet.reserve_direct_funding_coin(&id, required, reserve).map_err(|error| {
				if matches!(error, crate::Error::InsufficientFunds) {
					Error::InsufficientFunds
				} else {
					Error::PersistenceFailed
				}
			})?;
		let build = (|| {
			let txid = codec::txid_to_display(coin.outpoint.txid);
			let mut offer = Offer {
				offer_id: codec::derive_offer_id(&txid, coin.outpoint.vout, amount),
				amount_sat: amount,
				txid,
				vout: coin.outpoint.vout,
				value_sat: coin.txout.value.to_sat(),
				sequence: PAYER_SEQUENCE,
				change_script: change.into_bytes(),
				max_total_fee_sat: max_fee,
				receipt_hash: envelope.receipt_hash,
				ownership: OwnershipProof {
					pubkey: vec![0; 33],
					signature: [0; 64],
					message_proof: None,
					probe_proof: None,
				},
			};
			let (probe, prevouts) = codec::ownership_probe_transaction(
				&offer,
				coin.txout.script_pubkey.as_bytes(),
				&envelope.receiver_node_id,
			);
			let witness = self
				.wallet
				.sign_direct_funding_input(&id, coin.outpoint, probe, &prevouts)
				.map_err(|_| Error::InvalidFunding)?;
			offer.ownership = ownership_from_witness(&witness, &coin.txout.script_pubkey)?;
			if !crypto::verify_ownership(
				&offer,
				coin.txout.script_pubkey.as_bytes(),
				&envelope.receiver_node_id,
			) {
				return Err(Error::InvalidFunding);
			}
			Ok(Record {
				request: encoded.to_owned(),
				request_id: id.clone(),
				offer: offer.encode().map_err(map_codec)?,
				coin_script: coin.txout.script_pubkey.to_bytes(),
				status: SenderPaymentStatus::Offered,
				created_at: now_ms(),
				ephemeral_secret: crypto::random_secret().secret_bytes(),
				sign_request: None,
				witness: None,
				funding_txid: None,
				fee_sats: None,
				receipt_preimage: None,
				caveat: None,
			})
		})();
		let record = match build {
			Ok(record) => record,
			Err(error) => {
				self.wallet.release_direct_funding_reservation(&id, coin.outpoint);
				return Err(error);
			},
		};
		let mut state = self.state.lock().unwrap();
		state.records.insert(id.clone(), record.clone());
		if let Err(error) = self.persist(&mut state) {
			state.records.remove(&id);
			self.wallet.release_direct_funding_reservation(&id, coin.outpoint);
			return Err(error);
		}
		Ok(record)
	}

	async fn exchange(
		&self, envelope: &RequestEnvelope, record: Record, max_fee_sats: u64,
		transport: &mut dyn SenderTransport,
	) -> Result<(), Error> {
		let secret = SecretKey::from_slice(&record.ephemeral_secret)
			.map_err(|_| Error::PersistenceFailed)?;
		let ephemeral = PublicKey::from_secret_key(&Secp256k1::new(), &secret);
		let keys =
			crypto::sender_lane_keys(&secret, &envelope.encryption_key, &envelope.request_id);
		let offer = record.offer()?;
		send_frame(transport, &keys, envelope, codec::OFFER, &record.offer, Some(ephemeral))?;
		let start = Instant::now();
		let mut deadline =
			start + if record.status.committed() { RECEIPT_TIMEOUT } else { OFFER_TIMEOUT };
		let mut retry_index = 0;
		let mut committed = record.status.committed();
		loop {
			let retry = RETRY_SECONDS
				.get(retry_index)
				.map(|secs| start + Duration::from_secs(*secs))
				.unwrap_or(deadline);
			let wake = if committed { deadline } else { retry.min(deadline) };
			let received = timeout_at(wake, transport.receive()).await;
			let (subtype, sealed) = match received {
				Ok(Some(frame)) => frame,
				Ok(None) => return Err(Error::Unavailable),
				Err(_) if !committed && Instant::now() < deadline => {
					send_frame(
						transport,
						&keys,
						envelope,
						codec::OFFER,
						&record.offer,
						Some(ephemeral),
					)?;
					retry_index += 1;
					continue;
				},
				Err(_) => return Err(Error::Timeout),
			};
			if Instant::now() >= deadline {
				return Err(Error::Timeout);
			}
			let Some(frame) = crypto::decode_frame(&sealed) else {
				continue;
			};
			let Some(plain) =
				crypto::open_frame(&keys.recv_key, &envelope.request_id, subtype, &frame)
			else {
				continue;
			};
			match subtype {
				codec::OFFER_ACK => {
					let ack = OfferAck::decode(&plain).map_err(|_| Error::InvalidFunding)?;
					if ack.offer_id != offer.offer_id {
						continue;
					}
					if !ack.accepted {
						return Err(Error::Declined);
					}
				},
				codec::SIGN_REQUEST => {
					let request = SignRequest::decode(&plain).map_err(|_| Error::InvalidFunding)?;
					if request.offer_id != offer.offer_id {
						continue;
					}
					let current =
						self.record(&record.request_id).ok_or(Error::PersistenceFailed)?;
					let witness = if current.status.committed() {
						let saved = current
							.sign_request
							.as_ref()
							.and_then(|bytes| SignRequest::decode(bytes).ok())
							.ok_or(Error::PersistenceFailed)?;
						if !same_funding_transaction(&request, &saved) {
							return Err(Error::InvalidFunding);
						}
						verify_sign_request(
							&offer,
							&record.coin_script,
							envelope,
							&request,
							self.wallet.direct_funding_height(),
							|outpoint| self.wallet.owns_direct_funding_input(outpoint),
						)?;
						current.witness.ok_or(Error::PersistenceFailed)?
					} else {
						if envelope.expires_at <= now_ms() {
							return Err(Error::Expired);
						}
						let verified = timeout_at(
							deadline,
							self.verify(
								&offer,
								&record.coin_script,
								envelope,
								&request,
								max_fee_sats,
							),
						)
						.await
						.map_err(|_| Error::Timeout)??;
						if Instant::now() >= deadline || envelope.expires_at <= now_ms() {
							return Err(Error::Expired);
						}
						let signed = self
							.wallet
							.sign_direct_funding_input(
								&record.request_id,
								offer.outpoint(),
								verified.tx.clone(),
								&verified.prevouts,
							)
							.map_err(|_| Error::InvalidFunding)?;
						let witness =
							Witness { offer_id: offer.offer_id, witness: signed.to_vec() }
								.encode()
								.map_err(|_| Error::InvalidFunding)?;
						self.commit(&record.request_id, &request, &verified, witness.clone())?;
						committed = true;
						deadline = Instant::now() + RECEIPT_TIMEOUT;
						witness
					};
					// No await separates durable commitment and emission. Any subsequent error
					// is converted to the saved pending record by send().
					send_frame(transport, &keys, envelope, codec::WITNESS, &witness, None)?;
				},
				codec::RECEIPT if committed => {
					let receipt = Receipt::decode(&plain).map_err(|_| Error::InvalidFunding)?;
					let current =
						self.record(&record.request_id).ok_or(Error::PersistenceFailed)?;
					if receipt.offer_id != offer.offer_id {
						continue;
					}
					let txid = current
						.funding_txid
						.as_ref()
						.and_then(|id| Txid::from_str(id).ok())
						.ok_or(Error::PersistenceFailed)?;
					if codec::txid_from_display(receipt.funding_txid) != txid
						|| sha256::Hash::hash(&receipt.preimage).to_byte_array()
							!= envelope.receipt_hash
					{
						return Err(Error::InvalidFunding);
					}
					if let Some(raw) = receipt.raw_tx {
						let tx: Transaction = bitcoin::consensus::deserialize(&raw)
							.map_err(|_| Error::InvalidFunding)?;
						if tx.compute_txid() != txid {
							return Err(Error::InvalidFunding);
						}
					}
					self.update(&record.request_id, |record| {
						record.receipt_preimage = Some(codec::hex(&receipt.preimage));
						record.caveat = None;
					})?;
					return Ok(());
				},
				_ => {},
			}
		}
	}

	async fn verify(
		&self, offer: &Offer, coin_script: &[u8], envelope: &RequestEnvelope,
		request: &SignRequest, max_fee_sats: u64,
	) -> Result<Verified, Error> {
		// A resumed pre-witness attempt retains its exact offer bytes, but never
		// spends above a lower ceiling selected for this call.
		let mut effective_offer = offer.clone();
		effective_offer.max_total_fee_sat = offer.max_total_fee_sat.min(max_fee_sats);
		let verified = verify_sign_request(
			&effective_offer,
			coin_script,
			envelope,
			request,
			self.wallet.direct_funding_height(),
			|outpoint| self.wallet.owns_direct_funding_input(outpoint),
		)?;
		// Authenticate ALL values/scripts, including the shared channel output. P2WPKH does not
		// commit to other inputs but still must not accept a fabricated old channel capacity.
		for (input, prevout) in verified.tx.input.iter().zip(&verified.prevouts) {
			let previous = self
				.chain
				.fetch_transaction(input.previous_output.txid)
				.await
				.map_err(|_| Error::ChainUnavailable)?;
			if previous.output.get(input.previous_output.vout as usize) != Some(prevout) {
				return Err(Error::InvalidFunding);
			}
		}
		let own = TxOut {
			value: Amount::from_sat(offer.value_sat),
			script_pubkey: ScriptBuf::from_bytes(coin_script.to_vec()),
		};
		if !self
			.chain
			.is_unspent_output(offer.outpoint(), own)
			.await
			.map_err(|_| Error::ChainUnavailable)?
		{
			return Err(Error::InvalidFunding);
		}
		Ok(verified)
	}

	fn commit(
		&self, id: &str, request: &SignRequest, verified: &Verified, witness: Vec<u8>,
	) -> Result<(), Error> {
		let encoded = request.encode().map_err(|_| Error::InvalidFunding)?;
		let record = self.record(id).ok_or(Error::PersistenceFailed)?;
		let decoded_witness = Witness::decode(&witness).map_err(|_| Error::InvalidFunding)?;
		if !verify_funding_witness(
			&record.offer()?,
			&record.coin_script,
			verified,
			&decoded_witness,
		) {
			return Err(Error::InvalidFunding);
		}
		self.update(id, |record| {
			record.status = SenderPaymentStatus::SignedPending;
			record.sign_request = Some(encoded);
			record.witness = Some(witness);
			record.funding_txid = Some(verified.tx.compute_txid().to_string());
			record.fee_sats = Some(verified.fee_sats);
		})
	}
	fn record(&self, id: &str) -> Option<Record> {
		self.state.lock().unwrap().records.get(id).cloned()
	}
	// A forgotten terminal request must already be expired, so a later scan
	// cannot start it again. Live reservations and unexpired idempotency keys
	// always take priority over admitting another payment.
	fn make_record_room(&self) -> Result<(), Error> {
		let mut state = self.state.lock().unwrap();
		if state.faulted {
			return Err(Error::PersistenceFailed);
		}
		let now = now_ms();
		let mut removable: Vec<_> = state
			.records
			.values()
			.filter(|record| !record.status.holds_coin())
			.filter(|record| {
				RequestEnvelope::decode(&record.request, now, &self.chain_hash, true)
					.is_ok_and(|envelope| envelope.expires_at <= now)
			})
			.map(|record| (record.created_at, record.request_id.clone()))
			.collect();
		removable.sort_unstable();
		let before = state.records.len();
		for (created_at, id) in removable {
			if state.records.len() < MAX_RECORDS && now.saturating_sub(created_at) < RETENTION_MS {
				break;
			}
			state.records.remove(&id);
		}
		if state.records.len() != before {
			self.persist(&mut state)?;
		}
		if state.records.len() >= MAX_RECORDS {
			return Err(Error::Busy);
		}
		Ok(())
	}
	fn result(&self, id: &str) -> Result<SendResult, Error> {
		self.record(id).ok_or(Error::PersistenceFailed)?.result()
	}
	fn pending_result(&self, record: &Record, caveat: String) -> SendResult {
		let mut result = record.result().expect("validated sender record");
		result.caveat = Some(caveat);
		result
	}
	fn update(&self, id: &str, update: impl FnOnce(&mut Record)) -> Result<(), Error> {
		let mut state = self.state.lock().unwrap();
		if state.faulted {
			return Err(Error::PersistenceFailed);
		}
		update(state.records.get_mut(id).ok_or(Error::PersistenceFailed)?);
		self.persist(&mut state)
	}
	fn persist(&self, state: &mut State) -> Result<(), Error> {
		let bytes = serde_json::to_vec(&state.records.values().collect::<Vec<_>>())
			.map_err(|_| Error::PersistenceFailed)?;
		if bytes.len() > MAX_STORE_BYTES
			|| KVStoreSync::write(&*self.store, STORE_NAMESPACE, "", STORE_KEY, bytes).is_err()
		{
			state.faulted = true;
			return Err(Error::PersistenceFailed);
		}
		Ok(())
	}
	fn abort(&self, id: &str, error: Error) -> Result<(), Error> {
		self.update(id, |record| {
			record.status = SenderPaymentStatus::Aborted;
			record.caveat = Some(error.to_string());
		})?;
		let record = self.record(id).ok_or(Error::PersistenceFailed)?;
		self.wallet.release_direct_funding_reservation(id, record.offer()?.outpoint());
		Ok(())
	}

	/// Reconcile only positive canonical evidence. Unknown transactions, eviction and timeouts
	/// leave the reservation in place. Confirmed conflicts are the only failed committed state.
	pub(crate) async fn reconcile(&self) -> Result<(), Error> {
		let _operation = self.operation.lock().await;
		let records: Vec<_> = self
			.state
			.lock()
			.unwrap()
			.records
			.values()
			.filter(|record| record.status.holds_coin())
			.cloned()
			.collect();
		for record in records {
			let offer = record.offer()?;
			if record.status == SenderPaymentStatus::Offered {
				let env =
					RequestEnvelope::decode(&record.request, now_ms(), &self.chain_hash, true)
						.map_err(map_codec)?;
				if env.expires_at <= now_ms() {
					self.abort(&record.request_id, Error::Expired)?;
				}
				continue;
			}
			let txid = record
				.funding_txid
				.as_ref()
				.and_then(|id| Txid::from_str(id).ok())
				.ok_or(Error::PersistenceFailed)?;
			let (known, confirmed, conflict) =
				self.wallet.direct_funding_chain_state(offer.outpoint(), Some(txid));
			let remote = self.chain.fetch_transaction_status(txid).await;
			let status = if confirmed || matches!(remote, Ok(ConfirmationStatus::Confirmed { .. }))
			{
				Some(SenderPaymentStatus::Confirmed)
			} else if conflict {
				Some(SenderPaymentStatus::Failed)
			} else if known || matches!(remote, Ok(ConfirmationStatus::Unconfirmed)) {
				Some(SenderPaymentStatus::MempoolSeen)
			} else {
				None
			};
			if let Some(status) = status {
				self.update(&record.request_id, |record| record.status = status)?;
				if !status.holds_coin() {
					self.wallet
						.release_direct_funding_reservation(&record.request_id, offer.outpoint());
				}
			}
		}
		Ok(())
	}
}

struct Verified {
	tx: Transaction,
	prevouts: Vec<TxOut>,
	fee_sats: u64,
}
fn verify_sign_request(
	offer: &Offer, coin_script: &[u8], envelope: &RequestEnvelope, request: &SignRequest, tip: u32,
	owns: impl Fn(OutPoint) -> bool,
) -> Result<Verified, Error> {
	let tx = request.transaction().map_err(|_| Error::InvalidFunding)?;
	if request.offer_id != offer.offer_id
		|| tx.version.0 != 2
		|| tx.input.is_empty()
		|| tx.input.len() > 16
		|| tx.output.is_empty()
		|| tx.output.len() > 8
		|| request.prevouts.len() != tx.input.len()
		|| tx.input.iter().any(|input| !input.script_sig.is_empty())
		|| tx.lock_time.to_consensus_u32() >= 500_000_000
		|| (tx.lock_time.to_consensus_u32() > 0
			&& (tip == 0 || u64::from(tx.lock_time.to_consensus_u32()) > u64::from(tip) + 144))
	{
		return Err(Error::InvalidFunding);
	}
	let mut seen = HashSet::new();
	if tx.input.iter().any(|input| !seen.insert(input.previous_output)) {
		return Err(Error::InvalidFunding);
	}
	let own_index = tx
		.input
		.iter()
		.position(|input| input.previous_output == offer.outpoint())
		.ok_or(Error::InvalidFunding)?;
	if !tx.input[own_index].witness.is_empty()
		|| tx.input[own_index].sequence.0 != offer.sequence
		|| tx
			.input
			.iter()
			.enumerate()
			.any(|(i, input)| i != own_index && owns(input.previous_output))
	{
		return Err(Error::InvalidFunding);
	}
	let prevouts: Vec<_> = request
		.prevouts
		.iter()
		.map(|prevout| TxOut {
			value: Amount::from_sat(prevout.value_sat),
			script_pubkey: ScriptBuf::from_bytes(prevout.script.clone()),
		})
		.collect();
	if prevouts.iter().any(|prevout| prevout.value.to_sat() > codec::MAX_AMOUNT_SAT)
		|| prevouts[own_index].value.to_sat() != offer.value_sat
		|| prevouts[own_index].script_pubkey.as_bytes() != coin_script
	{
		return Err(Error::InvalidFunding);
	}
	let change = tx
		.output
		.iter()
		.filter(|out| out.script_pubkey.as_bytes() == offer.change_script)
		.try_fold(0u64, |sum, out| sum.checked_add(out.value.to_sat()))
		.ok_or(Error::InvalidFunding)?;
	let fee_sats = offer
		.value_sat
		.checked_sub(change)
		.and_then(|cost| cost.checked_sub(offer.amount_sat))
		.filter(|fee| *fee <= offer.max_total_fee_sat)
		.ok_or(Error::InvalidFunding)?;
	let funding_script = make_funding_redeemscript(
		&request.attestation.local_funding_pubkey,
		&request.attestation.remote_funding_pubkey,
	)
	.to_p2wsh();
	let funding = tx
		.output
		.get(request.attestation.funding_output_index as usize)
		.ok_or(Error::InvalidFunding)?;
	if funding.script_pubkey != funding_script
		|| !request.verify_attestation(&envelope.receiver_node_id)
	{
		return Err(Error::InvalidFunding);
	}
	let floor = if let Some(shared) = request.shared_input_index {
		if shared as usize == own_index {
			return Err(Error::InvalidFunding);
		}
		let previous = prevouts.get(shared as usize).ok_or(Error::InvalidFunding)?;
		let script = request
			.attestation
			.prior_funding_pubkeys
			.as_ref()
			.map(|keys| make_funding_redeemscript(&keys.local, &keys.remote).to_p2wsh())
			.unwrap_or(funding_script);
		if previous.script_pubkey != script {
			return Err(Error::InvalidFunding);
		}
		previous
			.value
			.to_sat()
			.checked_add(offer.amount_sat)
			.and_then(|value| value.checked_sub(fee_sats))
			.ok_or(Error::InvalidFunding)?
	} else {
		if request.attestation.prior_funding_pubkeys.is_some() {
			return Err(Error::InvalidFunding);
		}
		offer.amount_sat
	};
	if funding.value.to_sat() < floor {
		return Err(Error::InvalidFunding);
	}
	let input_value = prevouts
		.iter()
		.try_fold(0u64, |sum, out| sum.checked_add(out.value.to_sat()))
		.ok_or(Error::InvalidFunding)?;
	let output_value = tx
		.output
		.iter()
		.try_fold(0u64, |sum, out| sum.checked_add(out.value.to_sat()))
		.ok_or(Error::InvalidFunding)?;
	if input_value > codec::MAX_AMOUNT_SAT || output_value > input_value {
		return Err(Error::InvalidFunding);
	}
	Ok(Verified { tx, prevouts, fee_sats })
}

/// Peer witnesses can arrive between the first request and a recovery replay.
/// They do not change the transaction identifier or the donor's signature.
fn same_funding_transaction(a: &SignRequest, b: &SignRequest) -> bool {
	let (Ok(mut a), Ok(mut b)) = (a.transaction(), b.transaction()) else {
		return false;
	};
	for input in &mut a.input {
		input.witness.clear();
	}
	for input in &mut b.input {
		input.witness.clear();
	}
	a == b
}

fn validate_record(record: &Record, chain: &[u8; 32]) -> Result<(), Error> {
	let envelope = RequestEnvelope::decode(&record.request, now_ms(), chain, true)
		.map_err(|_| Error::PersistenceFailed)?;
	let offer = record.offer()?;
	SecretKey::from_slice(&record.ephemeral_secret).map_err(|_| Error::PersistenceFailed)?;
	if record.request_id != codec::hex(&envelope.request_id)
		|| offer.receipt_hash != envelope.receipt_hash
		|| resolve_amount(envelope.amount_sat, Some(offer.amount_sat)).is_err()
		|| offer.offer_id != codec::derive_offer_id(&offer.txid, offer.vout, offer.amount_sat)
		|| offer.sequence != PAYER_SEQUENCE
		|| !crypto::verify_ownership(&offer, &record.coin_script, &envelope.receiver_node_id)
	{
		return Err(Error::PersistenceFailed);
	}
	if record.status.committed() {
		let request = record
			.sign_request
			.as_ref()
			.and_then(|bytes| SignRequest::decode(bytes).ok())
			.ok_or(Error::PersistenceFailed)?;
		let witness = record
			.witness
			.as_ref()
			.and_then(|bytes| Witness::decode(bytes).ok())
			.ok_or(Error::PersistenceFailed)?;
		// Time-sensitive chain checks happened before commitment. On restore still
		// authenticate every persisted economic field and the exact funding signature.
		let verified =
			verify_sign_request(&offer, &record.coin_script, &envelope, &request, u32::MAX, |_| {
				false
			})
			.map_err(|_| Error::PersistenceFailed)?;
		if !verify_funding_witness(&offer, &record.coin_script, &verified, &witness)
			|| record.fee_sats != Some(verified.fee_sats)
			|| record.funding_txid.as_deref()
				!= Some(verified.tx.compute_txid().to_string().as_str())
		{
			return Err(Error::PersistenceFailed);
		}
	} else if record.witness.is_some()
		|| record.sign_request.is_some()
		|| record.funding_txid.is_some()
	{
		return Err(Error::PersistenceFailed);
	}
	Ok(())
}

/// Check the actual donor signature before journaling it and again when restoring it.
/// Only signatures committing to the complete transaction are permitted.
fn verify_funding_witness(
	offer: &Offer, coin_script: &[u8], verified: &Verified, witness: &Witness,
) -> bool {
	if witness.offer_id != offer.offer_id {
		return false;
	}
	let Some(index) =
		verified.tx.input.iter().position(|input| input.previous_output == offer.outpoint())
	else {
		return false;
	};
	let script = ScriptBuf::from_bytes(coin_script.to_vec());
	let mut cache = SighashCache::new(&verified.tx);
	let secp = Secp256k1::verification_only();
	if script.is_p2tr() {
		if witness.witness.len() != 1 || witness.witness[0].len() != 64 {
			return false;
		}
		let Ok(signature) = bitcoin::secp256k1::schnorr::Signature::from_slice(&witness.witness[0])
		else {
			return false;
		};
		let Ok(key) = XOnlyPublicKey::from_slice(&coin_script[2..]) else {
			return false;
		};
		let Ok(hash) = cache.taproot_key_spend_signature_hash(
			index,
			&Prevouts::All(&verified.prevouts),
			bitcoin::TapSighashType::Default,
		) else {
			return false;
		};
		secp.verify_schnorr(&signature, &Message::from_digest(hash.to_byte_array()), &key).is_ok()
	} else if script.is_p2wpkh() {
		if witness.witness.len() != 2 || witness.witness[1].len() != 33 {
			return false;
		}
		let Ok(signature) = bitcoin::ecdsa::Signature::from_slice(&witness.witness[0]) else {
			return false;
		};
		if signature.sighash_type != bitcoin::EcdsaSighashType::All {
			return false;
		}
		let Ok(key) = PublicKey::from_slice(&witness.witness[1]) else {
			return false;
		};
		if hash160::Hash::hash(&key.serialize()).as_byte_array() != &coin_script[2..] {
			return false;
		}
		let Ok(hash) = cache.p2wpkh_signature_hash(
			index,
			&script,
			Amount::from_sat(offer.value_sat),
			bitcoin::EcdsaSighashType::All,
		) else {
			return false;
		};
		secp.verify_ecdsa(&Message::from_digest(hash.to_byte_array()), &signature.signature, &key)
			.is_ok()
	} else {
		false
	}
}
fn ownership_from_witness(
	witness: &bitcoin::Witness, script: &ScriptBuf,
) -> Result<OwnershipProof, Error> {
	let parts: Vec<_> = witness.iter().collect();
	let (pubkey, proof_key, signature) = if script.is_p2tr() {
		if parts.len() != 1 || parts[0].len() != 64 {
			return Err(Error::InvalidFunding);
		}
		(
			script.as_bytes()[2..].to_vec(),
			[0; 33],
			parts[0].try_into().map_err(|_| Error::InvalidFunding)?,
		)
	} else if script.is_p2wpkh() {
		if parts.len() != 2 {
			return Err(Error::InvalidFunding);
		}
		let signature =
			bitcoin::ecdsa::Signature::from_slice(parts[0]).map_err(|_| Error::InvalidFunding)?;
		if signature.sighash_type != bitcoin::EcdsaSighashType::All {
			return Err(Error::InvalidFunding);
		}
		let pubkey: [u8; 33] = parts[1].try_into().map_err(|_| Error::InvalidFunding)?;
		(pubkey.to_vec(), pubkey, signature.signature.serialize_compact())
	} else {
		return Err(Error::InvalidFunding);
	};
	Ok(OwnershipProof {
		pubkey,
		signature: [0; 64],
		message_proof: None,
		probe_proof: Some(ProbeProof { pubkey: proof_key, signature }),
	})
}
fn resolve_amount(signed: Option<u64>, selected: Option<u64>) -> Result<Option<u64>, Error> {
	if signed.zip(selected).is_some_and(|(signed, selected)| signed != selected) {
		return Err(Error::AmountMismatch);
	}
	let amount = signed.or(selected);
	if amount.is_some_and(|amount| amount == 0 || amount > codec::MAX_AMOUNT_SAT) {
		return Err(Error::AmountMismatch);
	}
	Ok(amount)
}
fn send_frame(
	transport: &dyn SenderTransport, keys: &LaneKeys, envelope: &RequestEnvelope, subtype: u16,
	body: &[u8], opening: Option<PublicKey>,
) -> Result<(), Error> {
	let sealed = crypto::seal_frame(&keys.send_key, &envelope.request_id, subtype, body, opening)
		.map_err(|_| Error::InvalidFunding)?;
	transport.send(subtype, sealed)
}
fn map_codec(error: CodecError) -> Error {
	match error {
		CodecError::Expired => Error::Expired,
		CodecError::WrongChain => Error::WrongNetwork,
		_ => Error::InvalidRequest,
	}
}

#[cfg(test)]
mod tests;
