//! Native, opt-in JIT forwarding for Beignet's custom peer protocol.
//!
//! The provider accepts bounded multipart payments. An authorization
//! without a payment hash binds to the first matching intercepted payment. It never
//! accepts inbound zero-confirmation risk on behalf of the operator. Durable
//! allocation records precede channel creation, and interrupted holds are failed
//! after restart rather than initiating funding again.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{Amount, OutPoint};
use lightning::events::bump_transaction::Input;
use lightning::ln::chan_utils::{make_funding_redeemscript, FUNDING_TRANSACTION_WITNESS_WEIGHT};
use lightning::ln::channel_state::{ChannelDetails, ChannelShutdownState};
use lightning::ln::channelmanager::InterceptId;
use lightning::ln::funding::{FundingTxInput, SpliceContribution};
use lightning::ln::msgs::Init;
use lightning::ln::types::ChannelId;
use lightning::types::payment::PaymentHash;
use lightning::util::config::ChannelHandshakeConfigUpdate;
use lightning::util::persist::KVStoreSync;
use rand::Rng;
use serde::{Deserialize, Serialize};

use super::conflict::{SpliceConflictAck, ACK_SUBTYPE, REQUEST_SUBTYPE};
use super::conflict_service::ConflictService;
use super::wire::{
	Envelope, FeeMode, JitAck, JitAuthorization, JitQuote, JitQuoteRequest, RelayAddress,
	RelayFrame, DIRECT_FUNDING_RELAY, JIT_ACK, JIT_AUTHORIZATION, JIT_QUOTE, JIT_QUOTE_REQUEST,
	PROTOCOL_VERSION,
};
use crate::builder::BuildError;
use crate::chain::ChainSource;
use crate::config::{default_user_config, Config};
use crate::fee_estimator::ConfirmationTarget;
use crate::types::{ChainMonitor, ChannelManager, DynStore, Wallet};

const STORAGE_NAMESPACE: &str = "chicory";
const STORAGE_KEY: &str = "jit_provider_v1";
const MAX_STORE_BYTES: usize = 2 * 1024 * 1024;
const MAX_PENDING_RESPONSES: usize = 256;
const MAX_PARTS_PER_PAYMENT: usize = 16;
const RELAY_PEER_MESSAGES_PER_SECOND: usize = 32;
const RELAY_PEER_BYTES_PER_SECOND: usize = 128 * 1024;
const RELAY_GLOBAL_MESSAGES_PER_SECOND: usize = 128;
const RELAY_GLOBAL_BYTES_PER_SECOND: usize = 1024 * 1024;

/// Operator limits for the experimental native JIT provider.
///
/// Funding spends this node's on-chain wallet. Enable this only after deciding
/// how much capital to allocate. Limits apply to authenticated peers collectively,
/// so creating additional peer identities does not bypass the global budget.
///
/// This provider supports at most 16 parts per receive and new private
/// channels, with optional locally funded splices of an existing private home.
/// Funding attempts are serialized globally. A failed payment keeps its funding
/// lease until native funding resolves, including across restart. Guardian and
/// swap services are not implemented here.
#[derive(Clone, Debug)]
pub struct JitServiceConfig {
	/// Explicit JIT opt-in. The default refuses funding and registration.
	pub enabled: bool,
	/// Fund a splice of an existing private home when native forwarding proves
	/// that additional local balance resolves the shortage. A pending splice,
	/// channel policy limit or disconnect may still fail the payment safely.
	pub allow_splice_jit: bool,
	/// Relay sealed direct-funding frames between connected peers. This does not
	/// implement direct funding or authorize any channel operation. Fixed limits
	/// allow at most 32 messages and 128 KiB per peer per second, plus global limits.
	pub relay_enabled: bool,
	/// Accept confirmed inbound v2 channels without contributing wallet inputs.
	/// This is independent of JIT funding. Inbound v2 channels require confirmations
	/// even when their peer is listed as trusted for v1 zero-conf channels.
	pub allow_confirmed_v2: bool,
	/// Confirmations required for every peer-initiated splice, including splices
	/// which remove liquidity. Must be between 1 and 144. This is independent of
	/// the zero-conf policy for a new channel funded entirely by this node.
	pub inbound_splice_minimum_depth: u32,
	/// Keep each channel's original funding key across splices for Beignet
	/// interoperability. The native signer continues to verify all commitments.
	pub reuse_funding_key_on_splice: bool,
	/// Flat fee charged once for an accepted receive, in satoshis.
	pub flat_fee_sat: u64,
	/// Additional fee in parts per million of the forwarded invoice amount.
	pub fee_ppm: u32,
	/// Maximum size of one funded channel, including requested spare liquidity.
	pub max_client_funding_sats: u64,
	/// Lifetime channel-value allocation ceiling, charged before each attempt.
	/// Mining fees are additional and use the node's normal fee estimator.
	/// Failed or interrupted attempts remain charged conservatively.
	pub max_total_fronted_sats: u64,
	/// Global cap on unexpired registrations, including consumed registrations.
	pub max_live_intents: usize,
	/// Per-peer cap on unexpired registrations, including consumed registrations.
	pub max_live_intents_per_peer: usize,
	/// Global cap on held HTLCs across gathering and funding payments.
	pub max_held_htlcs: usize,
	/// Largest accepted registration lifetime, in seconds.
	pub intent_ttl_secs: u64,
	/// Maximum wall-clock hold while waiting for a channel to become usable.
	pub hold_timeout_secs: u64,
	/// Additional outbound liquidity reserved for channel fees and reserve.
	pub funding_buffer_sats: u64,
	/// Minimum new channel value. Smaller receives may use an existing channel.
	pub min_channel_sats: u64,
	/// Affordability reserve beyond the channel value and anchor reserve.
	/// This is not a mining-fee ceiling.
	pub funding_fee_reserve_sats: u64,
}

impl Default for JitServiceConfig {
	fn default() -> Self {
		Self {
			enabled: false,
			allow_splice_jit: false,
			relay_enabled: false,
			allow_confirmed_v2: false,
			inbound_splice_minimum_depth: 6,
			reuse_funding_key_on_splice: false,
			flat_fee_sat: 0,
			fee_ppm: 0,
			max_client_funding_sats: 1_000_000,
			max_total_fronted_sats: 10_000_000,
			max_live_intents: 128,
			max_live_intents_per_peer: 4,
			max_held_htlcs: 16,
			intent_ttl_secs: 600,
			hold_timeout_secs: 60,
			funding_buffer_sats: 10_000,
			min_channel_sats: 20_000,
			funding_fee_reserve_sats: 10_000,
		}
	}
}

/// Invalid operator limits for the native JIT provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JitConfigError;

impl fmt::Display for JitConfigError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str("invalid JIT provider limits")
	}
}

impl std::error::Error for JitConfigError {}

impl JitServiceConfig {
	fn private_splice_handshake(&self, announced: bool) -> Option<ChannelHandshakeConfigUpdate> {
		(self.enabled && self.allow_splice_jit && !announced)
			.then(crate::primary::splice_channel_handshake)
	}

	/// Validate bounded provider limits before enabling peer requests.
	pub fn validate(&self) -> Result<(), JitConfigError> {
		if self.max_live_intents == 0
			|| !(1..=144).contains(&self.inbound_splice_minimum_depth)
			|| self.max_live_intents > 1024
			|| self.max_live_intents_per_peer == 0
			|| self.max_live_intents_per_peer > self.max_live_intents
			|| self.max_held_htlcs == 0
			|| self.max_held_htlcs > self.max_live_intents
			|| self.intent_ttl_secs == 0
			|| self.intent_ttl_secs > 86_400
			|| self.hold_timeout_secs == 0
			|| self.hold_timeout_secs > 120
			|| self.min_channel_sats < 20_000
			|| self.min_channel_sats > self.max_client_funding_sats
			|| self.max_client_funding_sats > 100_000_000
			|| self.max_total_fronted_sats < self.max_client_funding_sats
			|| self.max_total_fronted_sats > 2_100_000_000_000_000
			|| self.fee_ppm > 1_000_000
			|| self.flat_fee_sat.checked_mul(1000).is_none()
			|| self.funding_buffer_sats > self.max_client_funding_sats
		{
			return Err(JitConfigError);
		}
		Ok(())
	}

	fn funding_amount(&self, amount_msat: u64, spare_sat: u64) -> Result<u64, &'static str> {
		if amount_msat == 0 {
			return Err("receive amount must be positive");
		}
		let amount_sat = amount_msat / 1000 + u64::from(amount_msat % 1000 != 0);
		let funding = amount_sat
			.checked_add(spare_sat)
			.and_then(|v| v.checked_add(self.funding_buffer_sats))
			.ok_or("funding amount exceeds provider limit")?
			.max(self.min_channel_sats);
		if funding > self.max_client_funding_sats {
			return Err("funding amount exceeds provider limit");
		}
		Ok(funding)
	}
}

#[derive(Clone, Serialize, Deserialize)]
struct Intent {
	peer: String,
	request_id: [u8; 8],
	request: Vec<u8>,
	scid: u64,
	// Wildcard authorizations bind atomically with consumption before funding.
	// Serde also reads the array representation written by hash-bound records.
	payment_hash: Option<[u8; 32]>,
	expected_msat: u64,
	funding_sats: u64,
	spare_sats: u64,
	expires_at: u64,
	skim: bool,
	flat_fee_sat: u64,
	fee_ppm: u32,
	consumed: bool,
}

impl Intent {
	fn ack(&self) -> JitAck {
		JitAck {
			request_id: self.request_id,
			intercept_scid: self.scid,
			accepted: true,
			flat_fee_sat: self.flat_fee_sat,
			fee_ppm: self.fee_ppm,
			reason: None,
			fee_mode: Some(if self.skim { FeeMode::Skim } else { FeeMode::Hop }),
		}
	}
}

#[derive(Clone, Serialize, Deserialize)]
struct Hold {
	intercept_id: [u8; 32],
	scid: u64,
	peer: String,
	forward_msat: u64,
	/// Original principal and received amount, retained for group fee validation.
	#[serde(default)]
	outbound_msat: u64,
	#[serde(default)]
	inbound_msat: u64,
	deadline: u64,
	/// A random local channel tag. None means a forward over an existing channel.
	user_channel_id: Option<u64>,
}

/// One channel-specific attempt. Funding outpoints prevent an old ChannelReady
/// event from releasing payments for a new splice on the same permanent ID.
#[derive(Clone, Serialize, Deserialize)]
struct SpliceFunding {
	scid: u64,
	peer: String,
	channel_id: [u8; 32],
	old_funding_txo: String,
	new_funding_txo: Option<String>,
	collect_until: u64,
	started: bool,
}

impl SpliceFunding {
	fn bind_candidate(&mut self, funding: OutPoint) -> Result<bool, ()> {
		let funding = funding.to_string();
		if !self.started || funding == self.old_funding_txo {
			return Ok(false);
		}
		if self.new_funding_txo.as_ref().is_some_and(|previous| previous != &funding) {
			return Err(());
		}
		self.new_funding_txo = Some(funding);
		Ok(true)
	}

	fn matches_ready(
		&self, channel: ChannelId, peer: PublicKey, funding: Option<OutPoint>,
	) -> bool {
		self.started
			&& self.channel_id == channel.0
			&& self.peer == peer.to_string()
			&& funding.is_some_and(|txo| {
				self.new_funding_txo.as_deref() == Some(txo.to_string().as_str())
			})
	}
}

/// Independent from payment holds: their expiry must not release wallet inputs
/// which native funding may still be negotiating.
#[derive(Clone, Serialize, Deserialize)]
enum FundingLease {
	Open {
		scid: u64,
		peer: String,
		channel_tag: u64,
		allocation_sats: u64,
	},
	Splice {
		attempt: SpliceFunding,
		allocation_sats: u64,
	},
	/// Older journals did not retain operations after payment expiry. Native
	/// state must confirm that all funding has resolved before lifting this fence.
	Recovery,
}

impl FundingLease {
	fn scid(&self) -> Option<u64> {
		match self {
			Self::Open { scid, .. } => Some(*scid),
			Self::Splice { attempt, .. } => Some(attempt.scid),
			Self::Recovery => None,
		}
	}
	fn allocation_sats(&self) -> Option<u64> {
		match self {
			Self::Open { allocation_sats, .. } | Self::Splice { allocation_sats, .. } => {
				Some(*allocation_sats)
			},
			Self::Recovery => None,
		}
	}
	fn matches_ready(
		&self, channel: ChannelId, user_id: u128, peer: PublicKey, funding: Option<OutPoint>,
	) -> bool {
		match self {
			Self::Open { channel_tag, peer: expected, .. } => {
				u128::from(*channel_tag) == user_id && *expected == peer.to_string()
			},
			Self::Splice { attempt, .. } => attempt.matches_ready(channel, peer, funding),
			Self::Recovery => false,
		}
	}
}

#[derive(Clone, Default, Serialize, Deserialize)]
struct DurableState {
	version: u8,
	fronted_sats: u64,
	intents: Vec<Intent>,
	holds: Vec<Hold>,
	#[serde(default)]
	splices: Vec<SpliceFunding>,
	#[serde(default)]
	funding_lease: Option<FundingLease>,
}

/// Accumulate one authenticated native intercept. The caller persists the
/// binding and hold together before funding or accepting another part.
fn append_part(
	state: &mut DurableState, policy: &JitServiceConfig, scid: u64, intercept: [u8; 32],
	hash: [u8; 32], inbound: u64, outbound: u64, now: u64,
) -> Result<bool, &'static str> {
	let index = state.intents.iter().position(|i| i.scid == scid).ok_or("unknown registration")?;
	let intent = &state.intents[index];
	if intent.consumed || intent.expires_at <= now {
		return Err("registration is no longer available");
	}
	if outbound == 0 || inbound < outbound {
		return Err("each part must cover its principal");
	}
	if intent.payment_hash.is_some_and(|bound| bound != hash)
		|| state.intents.iter().any(|i| i.scid != scid && i.payment_hash == Some(hash))
	{
		return Err("payment hash does not match registration");
	}
	if state.holds.len() >= policy.max_held_htlcs
		|| state.holds.iter().any(|h| h.intercept_id == intercept)
	{
		return Err("part capacity exhausted or duplicate intercept");
	}
	let parts: Vec<_> = state.holds.iter().filter(|h| h.scid == scid).collect();
	if parts.len() >= MAX_PARTS_PER_PAYMENT {
		return Err("too many parts in one payment");
	}
	let total = parts
		.iter()
		.try_fold(outbound, |sum, part| sum.checked_add(part.outbound_msat))
		.ok_or("payment amount overflow")?;
	let request = JitAuthorization::decode(&intent.request).map_err(|_| "invalid registration")?;
	if total > request.max_amount_msat {
		return Err("payment exceeds authorization cap");
	}
	let deadline = parts.first().map_or_else(
		|| now.saturating_add(policy.hold_timeout_secs).min(intent.expires_at),
		|part| part.deadline,
	);
	if deadline <= now {
		return Err("payment hold expired");
	}
	let ready = intent.expected_msat == 0 || total >= intent.expected_msat;
	let peer = intent.peer.clone();
	state.intents[index].payment_hash = Some(hash);
	state.holds.push(Hold {
		intercept_id: intercept,
		scid,
		peer,
		forward_msat: outbound,
		outbound_msat: outbound,
		inbound_msat: inbound,
		deadline,
		user_channel_id: None,
	});
	Ok(ready)
}

/// Match Beignet's once-per-group fee accounting exactly. Hop proportional
/// fees are rounded on each part; skim proportional fees use the held total.
fn group_forwards(intent: &Intent, parts: &[&Hold]) -> Result<Vec<u64>, ()> {
	if parts.is_empty() || parts.len() > MAX_PARTS_PER_PAYMENT {
		return Err(());
	}
	let total = parts
		.iter()
		.try_fold(0u64, |sum, part| {
			if part.outbound_msat == 0 || part.inbound_msat < part.outbound_msat {
				return None;
			}
			sum.checked_add(part.outbound_msat)
		})
		.ok_or(())?;
	let cap = JitAuthorization::decode(&intent.request).map_err(|_| ())?.max_amount_msat;
	if total < intent.expected_msat || total > cap {
		return Err(());
	}
	let mut forwards: Vec<_> = parts.iter().map(|part| part.outbound_msat).collect();
	if intent.skim {
		let fee = opening_fee(total, intent.flat_fee_sat, intent.fee_ppm).ok_or(())?;
		if fee > 0
			&& !JitAuthorization::decode(&intent.request).map_err(|_| ())?.accepts_skimmed_fee
		{
			return Err(());
		}
		let largest = forwards
			.iter()
			.enumerate()
			.max_by_key(|(index, value)| (**value, std::cmp::Reverse(*index)))
			.map(|(index, _)| index)
			.ok_or(())?;
		if forwards[largest] <= fee {
			return Err(());
		}
		forwards[largest] -= fee;
	} else {
		let fee = parts
			.iter()
			.try_fold(opening_fee(0, intent.flat_fee_sat, 0).ok_or(())?, |fee, part| {
				fee.checked_add(opening_fee(part.outbound_msat, 0, intent.fee_ppm)?)
			})
			.ok_or(())?;
		let collected = parts
			.iter()
			.try_fold(0u64, |sum, part| sum.checked_add(part.inbound_msat - part.outbound_msat))
			.ok_or(())?;
		if collected < fee {
			return Err(());
		}
	}
	Ok(forwards)
}

fn forwards_for_state(state: &DurableState, scid: u64) -> Result<Vec<u64>, ()> {
	let mut intent = state.intents.iter().find(|i| i.scid == scid).ok_or(())?.clone();
	if state.splices.iter().any(|splice| splice.scid == scid) {
		intent.expected_msat = 0;
	}
	let parts: Vec<_> = state.holds.iter().filter(|h| h.scid == scid).collect();
	group_forwards(&intent, &parts)
}

fn freeze_group(state: &mut DurableState, scid: u64, channel_tag: Option<u64>) -> Result<(), ()> {
	let index = state.intents.iter().position(|i| i.scid == scid).ok_or(())?;
	let intent = &state.intents[index];
	if intent.consumed {
		return Err(());
	}
	let forwards = forwards_for_state(state, scid)?;
	let splice = state.splices.iter().position(|splice| splice.scid == scid);
	let allocation =
		if channel_tag.is_some() || splice.is_some() { intent.funding_sats } else { 0 };
	let fronted_sats = state.fronted_sats.checked_add(allocation).ok_or(())?;
	if allocation > 0 && state.funding_lease.is_some() {
		return Err(());
	}
	let lease = if let Some(tag) = channel_tag {
		Some(FundingLease::Open {
			scid,
			peer: intent.peer.clone(),
			channel_tag: tag,
			allocation_sats: allocation,
		})
	} else if let Some(index) = splice {
		let mut attempt = state.splices[index].clone();
		attempt.started = true;
		Some(FundingLease::Splice { attempt, allocation_sats: allocation })
	} else {
		None
	};
	if lease.is_some() {
		state.funding_lease = lease;
	}
	state.intents[index].consumed = true;
	if let Some(index) = splice {
		state.splices[index].started = true;
	}
	for (hold, amount) in state.holds.iter_mut().filter(|h| h.scid == scid).zip(forwards) {
		hold.forward_msat = amount;
		hold.user_channel_id = channel_tag;
	}
	state.fronted_sats = fronted_sats;
	Ok(())
}

fn reserved_funding(state: &DurableState) -> Option<u64> {
	if let Some(lease) = &state.funding_lease {
		return lease.allocation_sats();
	}
	let groups: HashSet<_> = state
		.holds
		.iter()
		.filter(|h| h.user_channel_id.is_some())
		.map(|h| h.scid)
		.chain(state.splices.iter().filter(|s| s.started).map(|s| s.scid))
		.collect();
	groups.into_iter().try_fold(0u64, |sum, scid| {
		sum.checked_add(state.intents.iter().find(|i| i.scid == scid)?.funding_sats)
	})
}

enum ReceiveTarget {
	Existing(ChannelId),
	Open,
	Splice(ChannelDetails),
}

struct RelayWindow {
	started: Instant,
	messages: usize,
	bytes: usize,
}

impl RelayWindow {
	fn new() -> Self {
		Self { started: Instant::now(), messages: 0, bytes: 0 }
	}

	fn admit(&mut self, bytes: usize, messages_limit: usize, bytes_limit: usize) -> bool {
		if self.started.elapsed().as_secs() >= 1 {
			*self = Self::new();
		}
		if self.messages >= messages_limit || bytes > bytes_limit.saturating_sub(self.bytes) {
			return false;
		}
		self.messages += 1;
		self.bytes += bytes;
		true
	}
}

struct State {
	durable: DurableState,
	connected: HashSet<PublicKey>,
	relay_peers: HashMap<PublicKey, RelayWindow>,
	relay_global: RelayWindow,
	pending: Vec<(PublicKey, Envelope)>,
	faulted: bool,
	manual_wallet_operation: bool,
}

// The guard fences JIT funding while the host starts a manual wallet operation.
// Native pending funding state keeps the fence after asynchronous opens/splices.
pub(crate) struct WalletOperationGuard<'a>(&'a ChicoryService);
impl Drop for WalletOperationGuard<'_> {
	fn drop(&mut self) {
		self.0.state.lock().unwrap().manual_wallet_operation = false;
	}
}

/// Coordinates durable JIT authorization with the native channel manager.
pub(crate) struct ChicoryService {
	policy: JitServiceConfig,
	channel_manager: Arc<ChannelManager>,
	wallet: Arc<Wallet>,
	kv_store: Arc<DynStore>,
	config: Arc<Config>,
	state: Mutex<State>,
	conflicts: ConflictService,
}

impl ChicoryService {
	pub(crate) fn new(
		policy: JitServiceConfig, channel_manager: Arc<ChannelManager>,
		chain_monitor: Arc<ChainMonitor>, wallet: Arc<Wallet>, kv_store: Arc<DynStore>,
		config: Arc<Config>,
	) -> Result<Self, BuildError> {
		policy.validate().map_err(|_| BuildError::KVStoreSetupFailed)?;
		let mut durable =
			match KVStoreSync::read(kv_store.as_ref(), STORAGE_NAMESPACE, "", STORAGE_KEY) {
				Ok(bytes) if bytes.len() <= MAX_STORE_BYTES => {
					serde_json::from_slice::<DurableState>(&bytes)
						.map_err(|_| BuildError::ReadFailed)?
				},
				Ok(_) => return Err(BuildError::ReadFailed),
				Err(e) if e.kind() == lightning::io::ErrorKind::NotFound => {
					DurableState { version: 3, ..Default::default() }
				},
				Err(_) => return Err(BuildError::ReadFailed),
			};
		validate_durable(&durable).map_err(|_| BuildError::ReadFailed)?;
		// A native snapshot reconciles crashes between the durable allocation and
		// the API call, and older records which lost payment holds on timeout.
		if channel_manager.has_pending_funding_operation() {
			if durable.version < 3 && durable.funding_lease.is_none() {
				durable.funding_lease = Some(FundingLease::Recovery);
			}
		} else {
			durable.funding_lease = None;
		}
		// Resolve saved intercepts before dropping them. LDK may already have
		// failed these on restore; an absent intercept is an idempotent outcome.
		for hold in &durable.holds {
			let _ = channel_manager.fail_intercepted_htlc(InterceptId(hold.intercept_id));
			if let Some(intent) = durable.intents.iter_mut().find(|i| i.scid == hold.scid) {
				intent.consumed = true;
			}
		}
		durable.holds.clear();
		durable.splices.clear();
		// Version 1 only allowed single-part holds. They are failed above before
		// migrating, so missing part-level accounting never authorizes a forward.
		durable.version = 3;
		let service = Self {
			conflicts: ConflictService::new(Arc::clone(&channel_manager), chain_monitor),
			policy,
			channel_manager,
			wallet,
			kv_store,
			config,
			state: Mutex::new(State {
				durable,
				connected: HashSet::new(),
				relay_peers: HashMap::new(),
				relay_global: RelayWindow::new(),
				pending: Vec::new(),
				faulted: false,
				manual_wallet_operation: false,
			}),
		};
		{
			let state = service.state.lock().unwrap();
			service.persist(&state.durable).map_err(|_| BuildError::WriteFailed)?;
		}
		Ok(service)
	}

	pub(crate) fn private_splice_handshake(
		&self, announced: bool,
	) -> Option<ChannelHandshakeConfigUpdate> {
		self.policy.private_splice_handshake(announced)
	}

	pub(crate) fn begin_wallet_operation(&self) -> Result<WalletOperationGuard<'_>, ()> {
		let mut state = self.state.lock().unwrap();
		if state.faulted
			|| state.manual_wallet_operation
			|| state.durable.funding_lease.is_some()
			|| self.channel_manager.has_pending_funding_operation()
		{
			return Err(());
		}
		state.manual_wallet_operation = true;
		Ok(WalletOperationGuard(self))
	}

	fn persist(&self, durable: &DurableState) -> Result<(), ()> {
		let bytes = serde_json::to_vec(durable).map_err(|_| ())?;
		if bytes.len() > MAX_STORE_BYTES {
			return Err(());
		}
		KVStoreSync::write(self.kv_store.as_ref(), STORAGE_NAMESPACE, "", STORAGE_KEY, bytes)
			.map_err(|_| ())
	}

	fn save(&self, state: &mut State) -> bool {
		if self.persist(&state.durable).is_err() {
			// No future acceptance or funding after any uncertain durable write.
			state.faulted = true;
			return false;
		}
		true
	}

	pub(crate) fn peer_connected(&self, peer: PublicKey, _init: &Init) {
		self.state.lock().unwrap().connected.insert(peer);
	}

	pub(crate) fn peer_disconnected(&self, peer: PublicKey) {
		let mut state = self.state.lock().unwrap();
		state.connected.remove(&peer);
		state.relay_peers.remove(&peer);
		state.pending.retain(|(to, _)| *to != peer);
	}

	pub(crate) fn get_and_clear_pending_msg(&self) -> Vec<(PublicKey, Envelope)> {
		let mut messages = std::mem::take(&mut self.state.lock().unwrap().pending);
		// Native dequeue releases quiescence only after it queues the durable ACK.
		// The peer manager sends these custom frames before its next native cycle.
		for response in self.channel_manager.get_and_clear_pending_splice_conflict_responses() {
			let ack = SpliceConflictAck {
				channel_id: response.channel_id.0,
				splice_txid: response.splice_txid.to_byte_array(),
				agreed: response.agreed,
				reason: if response.reason.len() <= super::conflict::MAX_REASON_BYTES {
					response.reason
				} else {
					"Splice conflict request could not be completed.".to_owned()
				},
			};
			if let Ok(payload) = ack.encode() {
				messages.push((
					response.counterparty_node_id,
					Envelope { version: PROTOCOL_VERSION, subtype: ACK_SUBTYPE, payload },
				));
			}
		}
		messages
	}

	pub(crate) fn start_conflicts(&self) {
		self.conflicts.start();
	}
	pub(crate) fn stop_conflicts(&self) {
		self.conflicts.stop();
	}
	pub(crate) async fn handle_next_conflict(&self, source: &ChainSource) {
		self.conflicts.handle_next(source).await;
	}

	pub(crate) fn owns_scid(&self, scid: u64) -> bool {
		self.state.lock().unwrap().durable.intents.iter().any(|intent| intent.scid == scid)
			|| (self.policy.enabled
				&& self.policy.allow_splice_jit
				&& self.channel_for_alias(scid).is_some())
	}

	fn channel_for_alias(&self, scid: u64) -> Option<ChannelDetails> {
		self.channel_manager.list_channels().into_iter().find(|channel| {
			channel.outbound_scid_alias == Some(scid) || channel.short_channel_id == Some(scid)
		})
	}

	pub(crate) fn handle_message(&self, peer: PublicKey, envelope: Envelope) {
		if envelope.version != PROTOCOL_VERSION {
			return;
		}
		if envelope.subtype == REQUEST_SUBTYPE {
			if self.state.lock().unwrap().connected.contains(&peer) {
				self.conflicts.submit(peer, &envelope.payload);
			}
			return;
		}
		self.tick();
		let mut state = self.state.lock().unwrap();
		if !state.connected.contains(&peer) || state.pending.len() >= MAX_PENDING_RESPONSES {
			return;
		}
		if envelope.subtype == DIRECT_FUNDING_RELAY {
			self.relay(&mut state, peer, &envelope.payload);
			return;
		}
		let response = match envelope.subtype {
			JIT_AUTHORIZATION => {
				let Ok(auth) = JitAuthorization::decode(&envelope.payload) else {
					return;
				};
				Envelope {
					version: PROTOCOL_VERSION,
					subtype: JIT_ACK,
					payload: self.authorize(&mut state, peer, auth.clone(), auth.encode()).encode(),
				}
			},
			JIT_QUOTE_REQUEST => {
				let Ok(request) = JitQuoteRequest::decode(&envelope.payload) else {
					return;
				};
				Envelope {
					version: PROTOCOL_VERSION,
					subtype: JIT_QUOTE,
					payload: self.quote(&state, peer, request).encode(),
				}
			},
			_ => return,
		};
		state.pending.push((peer, response));
	}

	fn relay(&self, state: &mut State, sender: PublicKey, bytes: &[u8]) {
		if !self.policy.relay_enabled || state.faulted {
			return;
		}
		let Ok(frame) = RelayFrame::decode(bytes) else {
			return;
		};
		let RelayAddress::To(target) = frame.address else {
			return;
		};
		let Ok(target) = PublicKey::from_slice(&target) else {
			return;
		};
		if target == sender
			|| !state.connected.contains(&target)
			|| !matches!(frame.subtype, 16 | 17 | 18 | 19 | 21)
		{
			return;
		}
		if !state.relay_peers.entry(sender).or_insert_with(RelayWindow::new).admit(
			bytes.len(),
			RELAY_PEER_MESSAGES_PER_SECOND,
			RELAY_PEER_BYTES_PER_SECOND,
		) || !state.relay_global.admit(
			bytes.len(),
			RELAY_GLOBAL_MESSAGES_PER_SECOND,
			RELAY_GLOBAL_BYTES_PER_SECOND,
		) {
			return;
		}
		let forwarded = RelayFrame {
			subtype: frame.subtype,
			payload: frame.payload,
			address: RelayAddress::From(sender.serialize()),
		};
		if let Ok(payload) = forwarded.encode() {
			state.pending.push((
				target,
				Envelope { version: PROTOCOL_VERSION, subtype: DIRECT_FUNDING_RELAY, payload },
			));
		}
	}

	fn admission(
		&self, state: &State, peer: &str, amount: u64, spare: u64,
	) -> Result<u64, &'static str> {
		if !self.policy.enabled {
			return Err("native JIT provider is disabled");
		}
		if state.faulted {
			return Err("JIT persistence requires operator attention");
		}
		if state.durable.holds.len() >= self.policy.max_held_htlcs {
			return Err("provider held-payment limit reached");
		}
		if state.durable.intents.len() >= self.policy.max_live_intents {
			return Err("provider registration limit reached");
		}
		if state.durable.intents.iter().filter(|i| i.peer == peer).count()
			>= self.policy.max_live_intents_per_peer
		{
			return Err("peer registration limit reached");
		}
		let funding = self.policy.funding_amount(amount, spare)?;
		Ok(funding)
	}

	fn authorize(
		&self, state: &mut State, peer: PublicKey, auth: JitAuthorization, payload: Vec<u8>,
	) -> JitAck {
		let refuse = |reason: &str| JitAck {
			request_id: auth.request_id,
			intercept_scid: 0,
			accepted: false,
			flat_fee_sat: 0,
			fee_ppm: 0,
			reason: Some(reason.into()),
			fee_mode: None,
		};
		let peer_id = peer;
		let peer = peer.to_string();
		if let Some(existing) =
			state.durable.intents.iter().find(|i| i.peer == peer && i.request_id == auth.request_id)
		{
			return if !state.faulted && self.policy.enabled && existing.request == payload {
				existing.ack()
			} else {
				refuse("request id already registered with different terms or unavailable")
			};
		}
		let payment_hash = auth.payment_hash;
		let expected = auth.expected_total_msat.unwrap_or(0);
		if expected > auth.max_amount_msat {
			return refuse("expected payment share exceeds authorization cap");
		}
		if auth.expiry_seconds == 0 || u64::from(auth.expiry_seconds) > self.policy.intent_ttl_secs
		{
			return refuse("registration lifetime is outside provider limits");
		}
		if payment_hash.is_some()
			&& state.durable.intents.iter().any(|i| i.payment_hash == payment_hash)
		{
			return refuse("payment hash is already registered");
		}
		let funding_sats = match self.admission(
			state,
			&peer,
			auth.max_amount_msat,
			auth.target_remaining_inbound_sat,
		) {
			Ok(v) => v,
			Err(reason) => return refuse(reason),
		};
		let Some(fee) =
			opening_fee(auth.max_amount_msat, self.policy.flat_fee_sat, self.policy.fee_ppm)
		else {
			return refuse("opening fee exceeds supported amount");
		};
		if auth.accepts_skimmed_fee && fee >= auth.max_amount_msat {
			return refuse("opening fee consumes payment");
		}
		match self.channel_for_receive(
			peer_id,
			auth.max_amount_msat,
			auth.target_remaining_inbound_sat,
		) {
			Ok(ReceiveTarget::Existing(_)) => {},
			Ok(ReceiveTarget::Open | ReceiveTarget::Splice(_)) => {
				if let Err(reason) = self.funding_available(state, peer_id, funding_sats) {
					return refuse(reason);
				}
			},
			Err(reason) => return refuse(reason),
		}
		let Some(now) = unix_now() else {
			return refuse("provider clock unavailable");
		};
		let scid = (0..16)
			.map(|_| self.channel_manager.get_intercept_scid())
			.find(|scid| !state.durable.intents.iter().any(|i| i.scid == *scid));
		let Some(scid) = scid else {
			return refuse("no unused intercept identifier available");
		};
		let intent = Intent {
			peer,
			request_id: auth.request_id,
			request: payload,
			scid,
			payment_hash,
			expected_msat: expected,
			funding_sats,
			spare_sats: auth.target_remaining_inbound_sat,
			expires_at: now.saturating_add(u64::from(auth.expiry_seconds)),
			skim: auth.accepts_skimmed_fee || fee == 0,
			flat_fee_sat: self.policy.flat_fee_sat,
			fee_ppm: self.policy.fee_ppm,
			consumed: false,
		};
		let ack = intent.ack();
		state.durable.intents.push(intent);
		if !self.save(state) {
			return refuse("could not persist registration");
		}
		ack
	}

	fn quote(&self, state: &State, peer: PublicKey, request: JitQuoteRequest) -> JitQuote {
		let result = self
			.admission(
				state,
				&peer.to_string(),
				request.max_amount_msat,
				request.target_remaining_inbound_sat,
			)
			.and_then(|funding| {
				if matches!(
					self.channel_for_receive(
						peer,
						request.max_amount_msat,
						request.target_remaining_inbound_sat
					)?,
					ReceiveTarget::Existing(_)
				) {
					Ok(0)
				} else {
					self.funding_available(state, peer, funding)?;
					Ok(funding)
				}
			});
		JitQuote {
			request_id: request.request_id,
			accepted: result.is_ok(),
			flat_fee_sat: self.policy.flat_fee_sat,
			fee_ppm: self.policy.fee_ppm,
			max_client_funding_sats: self.policy.max_client_funding_sats,
			funding_sats: result.as_ref().copied().unwrap_or(0),
			reason: result.err().map(str::to_owned),
		}
	}

	fn channel_for_receive(
		&self, peer: PublicKey, amount: u64, spare_sat: u64,
	) -> Result<ReceiveTarget, &'static str> {
		let channels = self.channel_manager.list_channels_with_counterparty(&peer);
		let total = spare_sat
			.checked_mul(1000)
			.and_then(|v| v.checked_add(amount))
			.ok_or("required inbound liquidity overflow")?;
		if let Some(channel) = channels.iter().find(|c| {
			c.is_usable
				&& c.next_outbound_htlc_limit_msat >= amount
				&& c.next_outbound_htlc_minimum_msat <= amount
				&& c.outbound_capacity_msat >= total
		}) {
			return Ok(ReceiveTarget::Existing(channel.channel_id));
		}
		if channels.len() == 1 && self.policy.allow_splice_jit {
			let channel = &channels[0];
			if channel.is_usable
				&& !channel.is_announced
				&& channel.funding_txo.is_some()
				&& matches!(
					channel.channel_shutdown_state,
					Some(ChannelShutdownState::NotShuttingDown)
				) {
				let funding = self.policy.funding_amount(amount, spare_sat)?;
				self.select_splice_inputs(channel, funding)
					.map_err(|_| "provider lacks confirmed native-witness funds for this splice")?;
				return Ok(ReceiveTarget::Splice(channel.clone()));
			}
		}
		if !channels.is_empty() {
			return Err("existing home cannot currently accept a native JIT splice");
		}
		Ok(ReceiveTarget::Open)
	}

	fn funding_available(
		&self, state: &State, peer: PublicKey, funding: u64,
	) -> Result<(), &'static str> {
		if state.manual_wallet_operation
			|| state.durable.funding_lease.is_some()
			|| self.channel_manager.has_pending_funding_operation()
		{
			return Err("provider has a native funding operation in progress");
		}
		if state.durable.holds.len() > self.policy.max_held_htlcs {
			return Err("provider held-payment limit reached");
		}
		if state
			.durable
			.fronted_sats
			.checked_add(funding)
			.filter(|v| *v <= self.policy.max_total_fronted_sats)
			.is_none()
		{
			return Err("provider lifetime funding budget exhausted");
		}
		let reserve =
			crate::total_anchor_channels_reserve_sats(&self.channel_manager, &self.config);
		let extra_anchor = self.config.anchor_channels_config.as_ref().map_or(0, |config| {
			if config.trusted_peers_no_reserve.contains(&peer) {
				0
			} else {
				config.per_channel_reserve_sats
			}
		});
		let reserved =
			reserved_funding(&state.durable).ok_or("pending funding reservation overflow")?;
		let required = funding
			.checked_add(reserved)
			.and_then(|v| v.checked_add(extra_anchor))
			.and_then(|v| v.checked_add(self.policy.funding_fee_reserve_sats))
			.ok_or("funding amount overflow")?;
		let available = self.wallet.get_witness_spendable_amount_sats(reserve).unwrap_or(0);
		if available < required {
			return Err("provider wallet has insufficient available funds");
		}
		Ok(())
	}

	pub(crate) fn handle_htlc_intercepted(
		&self, scid: u64, intercept: InterceptId, hash: PaymentHash, inbound: u64, outbound: u64,
	) {
		self.tick();
		let mut state = self.state.lock().unwrap();
		if state.durable.holds.iter().any(|h| h.intercept_id == intercept.0) {
			return;
		}
		let fail = || {
			let _ = self.channel_manager.fail_intercepted_htlc(intercept);
		};
		if !self.policy.enabled
			|| state.faulted
			|| self.channel_manager.intercepted_htlc_inbound_amount_msat(intercept) != Some(inbound)
		{
			fail();
			return;
		}
		let Some(now) = unix_now() else {
			fail();
			return;
		};
		let alias_channel = if state.durable.intents.iter().any(|i| i.scid == scid) {
			None
		} else if self.policy.allow_splice_jit {
			self.channel_for_alias(scid)
		} else {
			None
		};
		let scid = if let Some(channel) = &alias_channel {
			let peer = channel.counterparty.node_id.to_string();
			let matching = state
				.durable
				.intents
				.iter()
				.filter(|i| {
					i.peer == peer
						&& !i.consumed && i.expires_at > now
						&& i.payment_hash.is_none_or(|bound| bound == hash.0)
				})
				.min_by_key(|i| (i.payment_hash.is_none(), i.expires_at));
			let Some(intent) = matching else {
				fail();
				return;
			};
			intent.scid
		} else {
			scid
		};
		let Some(index) = state.durable.intents.iter().position(|i| i.scid == scid) else {
			fail();
			return;
		};
		let Ok(peer) = PublicKey::from_str(&state.durable.intents[index].peer) else {
			fail();
			return;
		};
		if !state.connected.contains(&peer) {
			fail();
			return;
		}
		if let Some(channel) = &alias_channel {
			if !self.stage_splice(&mut state, scid, channel, now) {
				fail();
				return;
			}
		}
		let ready = match append_part(
			&mut state.durable,
			&self.policy,
			scid,
			intercept.0,
			hash.0,
			inbound,
			outbound,
			now,
		) {
			Ok(ready) => ready,
			Err(_) => {
				if !state.durable.holds.iter().any(|h| h.scid == scid) {
					state.durable.splices.retain(|s| s.scid != scid);
				}
				fail();
				return;
			},
		};
		// Even the first partial payment binds its hash durably, before waiting
		// for more parts. This write never allocates on-chain funds.
		if !self.save(&mut state) {
			self.fail_group(&mut state, scid);
			return;
		}
		if state.durable.splices.iter().any(|s| s.scid == scid) || !ready {
			return;
		}
		let intent = state.durable.intents[index].clone();
		let parts: Vec<_> = state.durable.holds.iter().filter(|h| h.scid == scid).collect();
		let forwards = match group_forwards(&intent, &parts) {
			Ok(forwards) => forwards,
			Err(_) => {
				self.fail_group(&mut state, scid);
				return;
			},
		};
		let Some(total_forward) =
			forwards.iter().try_fold(0u64, |sum, amount| sum.checked_add(*amount))
		else {
			self.fail_group(&mut state, scid);
			return;
		};
		let channel = match self.channel_for_receive(peer, total_forward, intent.spare_sats) {
			Ok(channel) => channel,
			Err(_) => {
				self.fail_group(&mut state, scid);
				return;
			},
		};
		if let ReceiveTarget::Splice(channel) = &channel {
			if self.stage_splice(&mut state, scid, channel, now) {
				self.save(&mut state);
			} else {
				self.fail_group(&mut state, scid);
			}
			return;
		}
		let user_channel_id = if matches!(channel, ReceiveTarget::Open) {
			if state
				.durable
				.holds
				.iter()
				.any(|h| h.peer == intent.peer && h.user_channel_id.is_some())
				|| self.funding_available(&state, peer, intent.funding_sats).is_err()
			{
				self.fail_group(&mut state, scid);
				return;
			}
			let Some(tag) = (0..16)
				.map(|_| rand::rng().random::<u64>())
				.find(|tag| !state.durable.holds.iter().any(|h| h.user_channel_id == Some(*tag)))
			else {
				self.fail_group(&mut state, scid);
				return;
			};
			Some(tag)
		} else {
			None
		};
		if freeze_group(&mut state.durable, scid, user_channel_id).is_err() {
			self.fail_group(&mut state, scid);
			return;
		}
		// The frozen group, fee allocation and one funding charge are durable
		// before any native open or forward. No later parts can join this set.
		if !self.save(&mut state) || !self.group_is_live(&state, scid) {
			self.fail_group(&mut state, scid);
			return;
		}
		if let ReceiveTarget::Existing(channel) = channel {
			self.forward_group(&mut state, scid, channel, peer);
		} else if let Some(user_channel_id) = user_channel_id {
			let mut config = default_user_config(&self.config);
			if let Some(handshake) = self.private_splice_handshake(false) {
				config.channel_handshake_config.apply(&handshake);
			}
			config.channel_handshake_config.announce_for_forwarding = false;
			config.channel_handshake_config.require_zero_conf = true;
			config.channel_handshake_config.reuse_funding_key_on_splice =
				self.policy.reuse_funding_key_on_splice;
			config.channel_handshake_config.max_inbound_htlc_value_in_flight_percent_of_channel =
				100;
			config.channel_handshake_limits.trust_own_funding_0conf = true;
			config.channel_handshake_limits.max_minimum_depth = 0;
			if self
				.channel_manager
				.create_channel(
					peer,
					intent.funding_sats,
					0,
					u128::from(user_channel_id),
					None,
					Some(config),
				)
				.is_err()
			{
				self.release_funding_lease(&mut state, scid);
				self.fail_group(&mut state, scid);
			}
		}
	}

	// A real-alias intercept has already passed native shortage checks. A fake
	// alias may select the same operation, but never opens a second home.
	fn stage_splice(
		&self, state: &mut State, scid: u64, channel: &ChannelDetails, now: u64,
	) -> bool {
		if let Some(existing) = state.durable.splices.iter().find(|s| s.scid == scid) {
			return !existing.started && existing.channel_id == channel.channel_id.0;
		}
		if !self.policy.allow_splice_jit
			|| !channel.is_usable
			|| channel.is_announced
			|| !matches!(
				channel.channel_shutdown_state,
				Some(ChannelShutdownState::NotShuttingDown)
			) || self
			.channel_manager
			.list_channels_with_counterparty(&channel.counterparty.node_id)
			.len() != 1
			|| state.durable.splices.iter().any(|s| s.channel_id == channel.channel_id.0)
		{
			return false;
		}
		let Some(funding_txo) = channel.funding_txo else {
			return false;
		};
		state.durable.splices.push(SpliceFunding {
			scid,
			peer: channel.counterparty.node_id.to_string(),
			channel_id: channel.channel_id.0,
			old_funding_txo: funding_txo.to_string(),
			new_funding_txo: None,
			collect_until: now.saturating_add(1),
			started: false,
		});
		true
	}

	fn start_splice(&self, state: &mut State, scid: u64) {
		let Some(attempt) =
			state.durable.splices.iter().find(|s| s.scid == scid && !s.started).cloned()
		else {
			return;
		};
		let Ok(peer) = PublicKey::from_str(&attempt.peer) else {
			self.fail_group(state, scid);
			return;
		};
		let Some(intent) = state.durable.intents.iter().find(|i| i.scid == scid).cloned() else {
			self.fail_group(state, scid);
			return;
		};
		let channel =
			self.channel_manager.list_channels_with_counterparty(&peer).into_iter().find(|c| {
				c.channel_id.0 == attempt.channel_id
					&& c.is_usable && c
					.funding_txo
					.is_some_and(|txo| txo.to_string() == attempt.old_funding_txo)
			});
		if !state.connected.contains(&peer)
			|| channel.is_none()
			|| !self.group_is_live(state, scid)
			|| self.funding_available(state, peer, intent.funding_sats).is_err()
			|| freeze_group(&mut state.durable, scid, None).is_err()
		{
			self.fail_group(state, scid);
			return;
		}
		// Persist the once-only budget and exact old funding point before any
		// native operation. A restart fails holds and never repeats this attempt.
		if !self.save(state) || !self.group_is_live(state, scid) {
			self.fail_group(state, scid);
			return;
		}
		if self.splice_in(&channel.unwrap(), peer, intent.funding_sats).is_err() {
			self.release_funding_lease(state, scid);
			self.fail_group(state, scid);
		}
	}

	// Quotes use the same confirmed-input dry run as execution. Pending change
	// may be spendable for an ordinary open but cannot fund an interactive splice.
	fn select_splice_inputs(
		&self, channel: &ChannelDetails, amount_sats: u64,
	) -> Result<(Vec<FundingTxInput>, u32), ()> {
		let funding_txo = channel.funding_txo.ok_or(())?;
		let dummy_key = PublicKey::from_slice(&[2; 33]).map_err(|_| ())?;
		let script = make_funding_redeemscript(&dummy_key, &dummy_key).to_p2wsh();
		let shared_input = Input {
			outpoint: funding_txo.into_bitcoin_outpoint(),
			previous_utxo: bitcoin::TxOut {
				value: Amount::from_sat(channel.channel_value_satoshis),
				script_pubkey: script.clone(),
			},
			satisfaction_weight: bitcoin::constants::WITNESS_SCALE_FACTOR as u64
				+ FUNDING_TRANSACTION_WITNESS_WEIGHT,
		};
		let new_value = channel.channel_value_satoshis.checked_add(amount_sats).ok_or(())?;
		let shared_output =
			bitcoin::TxOut { value: Amount::from_sat(new_value), script_pubkey: script };
		let fee_rate = self.wallet.estimate_fee_rate(ConfirmationTarget::ChannelFunding);
		let inputs =
			self.wallet.select_confirmed_utxos(vec![shared_input], &[shared_output], fee_rate)?;
		let rate = u32::try_from(fee_rate.to_sat_per_kwu()).map_err(|_| ())?;
		Ok((inputs, rate))
	}

	fn splice_in(
		&self, channel: &ChannelDetails, peer: PublicKey, amount_sats: u64,
	) -> Result<(), ()> {
		let (inputs, rate) = self.select_splice_inputs(channel, amount_sats)?;
		let change_address = self.wallet.get_new_internal_address().map_err(|_| ())?;
		let change_script = change_address.script_pubkey();
		let contribution = SpliceContribution::SpliceIn {
			value: Amount::from_sat(amount_sats),
			inputs,
			change_script: Some(change_script.clone()),
		};
		if self
			.channel_manager
			.splice_channel(&channel.channel_id, &peer, contribution, rate, None)
			.is_err()
		{
			let tx = bitcoin::Transaction {
				version: bitcoin::transaction::Version::TWO,
				lock_time: bitcoin::absolute::LockTime::ZERO,
				input: vec![],
				output: vec![bitcoin::TxOut { value: Amount::ZERO, script_pubkey: change_script }],
			};
			let _ = self.wallet.cancel_tx(&tx);
			return Err(());
		}
		Ok(())
	}

	pub(crate) fn splice_pending(
		&self, channel: ChannelId, peer: PublicKey, new_funding: OutPoint,
	) {
		let mut state = self.state.lock().unwrap();
		let mut changed = false;
		let mut failed = None;
		if let Some(FundingLease::Splice { attempt, .. }) = &mut state.durable.funding_lease {
			if attempt.channel_id == channel.0 && attempt.peer == peer.to_string() {
				match attempt.bind_candidate(new_funding) {
					Ok(update) => changed |= update,
					Err(()) => failed = Some(attempt.scid),
				}
			}
		}
		if let Some(attempt) = state
			.durable
			.splices
			.iter_mut()
			.find(|s| s.started && s.channel_id == channel.0 && s.peer == peer.to_string())
		{
			match attempt.bind_candidate(new_funding) {
				Ok(update) => changed |= update,
				Err(()) => failed = Some(attempt.scid),
			}
		}
		if let Some(scid) = failed {
			self.fail_group(&mut state, scid);
		} else if changed && !self.save(&mut state) {
			let groups: Vec<_> = state
				.durable
				.splices
				.iter()
				.filter(|s| s.channel_id == channel.0)
				.map(|s| s.scid)
				.collect();
			for scid in groups {
				self.fail_group(&mut state, scid);
			}
		}
	}

	pub(crate) fn splice_failed(&self, channel: ChannelId, peer: PublicKey) {
		let mut state = self.state.lock().unwrap();
		self.reconcile_funding_lease(&mut state);
		let groups: Vec<_> = state
			.durable
			.splices
			.iter()
			.filter(|s| s.channel_id == channel.0 && s.peer == peer.to_string())
			.map(|s| s.scid)
			.collect();
		for scid in groups {
			self.fail_group(&mut state, scid);
		}
	}

	fn release_funding_lease(&self, state: &mut State, scid: u64) {
		if state.durable.funding_lease.as_ref().and_then(FundingLease::scid) == Some(scid) {
			state.durable.funding_lease = None;
			self.save(state);
		}
	}

	fn reconcile_funding_lease(&self, state: &mut State) {
		if state.durable.funding_lease.is_some()
			&& !self.channel_manager.has_pending_funding_operation()
		{
			state.durable.funding_lease = None;
			self.save(state);
		}
	}

	pub(crate) fn channel_closed(
		&self, channel: ChannelId, user_id: u128, peer: Option<PublicKey>,
	) {
		let mut state = self.state.lock().unwrap();
		let groups: HashSet<_> = state
			.durable
			.holds
			.iter()
			.filter(|h| {
				h.user_channel_id.map(u128::from) == Some(user_id)
					&& peer.is_some_and(|p| h.peer == p.to_string())
			})
			.map(|h| h.scid)
			.chain(
				state
					.durable
					.splices
					.iter()
					.filter(|s| {
						s.channel_id == channel.0 && peer.is_some_and(|p| s.peer == p.to_string())
					})
					.map(|s| s.scid),
			)
			.collect();
		for scid in groups {
			self.fail_group(&mut state, scid);
		}
		self.reconcile_funding_lease(&mut state);
	}

	fn group_is_live(&self, state: &State, scid: u64) -> bool {
		let now = unix_now().unwrap_or(u64::MAX);
		let parts: Vec<_> = state.durable.holds.iter().filter(|h| h.scid == scid).collect();
		!state.faulted
			&& !parts.is_empty()
			&& parts.iter().all(|hold| {
				hold.deadline > now
					&& self
						.channel_manager
						.intercepted_htlc_inbound_amount_msat(InterceptId(hold.intercept_id))
						== Some(hold.inbound_msat)
			})
	}

	fn fail_group(&self, state: &mut State, scid: u64) {
		for hold in state.durable.holds.iter().filter(|h| h.scid == scid) {
			let _ = self.channel_manager.fail_intercepted_htlc(InterceptId(hold.intercept_id));
		}
		state.durable.holds.retain(|h| h.scid != scid);
		state.durable.splices.retain(|s| s.scid != scid);
		if let Some(intent) = state.durable.intents.iter_mut().find(|i| i.scid == scid) {
			intent.consumed = true;
		}
		self.save(state);
	}

	fn forward_group(&self, state: &mut State, scid: u64, channel: ChannelId, peer: PublicKey) {
		if !self.group_is_live(state, scid) {
			self.fail_group(state, scid);
			return;
		}
		let parts: Vec<_> =
			state.durable.holds.iter().filter(|h| h.scid == scid).cloned().collect();
		for hold in parts {
			if unix_now().map_or(true, |now| hold.deadline <= now)
				|| self
					.channel_manager
					.forward_intercepted_htlc(
						InterceptId(hold.intercept_id),
						&channel,
						peer,
						hold.forward_msat,
					)
					.is_err()
			{
				// Native forwarding is per part. Already released parts remain
				// governed by normal MPP settlement; fail every remaining intercept.
				self.fail_group(state, scid);
				return;
			}
		}
		// Keep the entire frozen group in the journal until all calls finish.
		// Restart can then fail any remaining intercepts without replaying them.
		state.durable.holds.retain(|h| h.scid != scid);
		state.durable.splices.retain(|s| s.scid != scid);
		self.save(state);
	}

	pub(crate) fn channel_ready(
		&self, channel: ChannelId, user_channel_id: u128, peer: PublicKey,
		funding_txo: Option<OutPoint>,
	) {
		self.tick();
		let mut state = self.state.lock().unwrap();
		if state.faulted {
			return;
		}
		if state
			.durable
			.funding_lease
			.as_ref()
			.is_some_and(|lease| lease.matches_ready(channel, user_channel_id, peer, funding_txo))
		{
			state.durable.funding_lease = None;
			if !self.save(&mut state) {
				return;
			}
		}
		let splice_groups: Vec<_> = state
			.durable
			.splices
			.iter()
			.filter(|s| s.matches_ready(channel, peer, funding_txo))
			.map(|s| s.scid)
			.collect();
		for scid in splice_groups {
			self.forward_group(&mut state, scid, channel, peer);
		}
		let groups: HashSet<_> = state
			.durable
			.holds
			.iter()
			.filter(|h| {
				h.peer == peer.to_string()
					&& h.user_channel_id.map(u128::from) == Some(user_channel_id)
			})
			.map(|h| h.scid)
			.collect();
		for scid in groups {
			self.forward_group(&mut state, scid, channel, peer);
		}
	}

	/// Expire held payments. Call at least once per second while the node runs.
	pub(crate) fn tick(&self) {
		let mut state = self.state.lock().unwrap();
		let now = unix_now().unwrap_or(u64::MAX);
		let expired: HashSet<_> = state
			.durable
			.holds
			.iter()
			.filter(|h| {
				state.faulted
					|| h.deadline <= now
					|| self
						.channel_manager
						.intercepted_htlc_inbound_amount_msat(InterceptId(h.intercept_id))
						.is_none()
			})
			.map(|h| h.scid)
			.collect();
		for scid in &expired {
			self.fail_group(&mut state, *scid);
		}
		self.reconcile_funding_lease(&mut state);
		let start: Vec<_> = state
			.durable
			.splices
			.iter()
			.filter(|s| !s.started && s.collect_until <= now)
			.map(|s| s.scid)
			.collect();
		for scid in start {
			self.start_splice(&mut state, scid);
		}
		let before = state.durable.intents.len();
		state.durable.intents.retain(|i| i.expires_at > now);
		if !expired.is_empty() || before != state.durable.intents.len() {
			self.save(&mut state);
		}
	}
}

fn unix_now() -> Option<u64> {
	SystemTime::now().duration_since(UNIX_EPOCH).ok().map(|duration| duration.as_secs())
}

fn opening_fee(amount: u64, flat_sat: u64, ppm: u32) -> Option<u64> {
	let fee = u128::from(flat_sat) * 1000 + u128::from(amount) * u128::from(ppm) / 1_000_000;
	u64::try_from(fee).ok()
}

fn validate_durable(state: &DurableState) -> Result<(), ()> {
	if state.version == 1 {
		return validate_legacy_durable(state);
	}
	if ![2, 3].contains(&state.version)
		|| state.splices.len() > 1024
		|| state.intents.len() > 1024
		|| state.holds.len() > 1024
		|| state.fronted_sats > 2_100_000_000_000_000
	{
		return Err(());
	}
	if let Some(lease) = &state.funding_lease {
		if let Some(amount) = lease.allocation_sats() {
			if !(20_000..=100_000_000).contains(&amount) || amount > state.fronted_sats {
				return Err(());
			}
		}
		match lease {
			FundingLease::Open { peer, .. } if PublicKey::from_str(peer).is_err() => return Err(()),
			FundingLease::Splice { attempt, .. }
				if !attempt.started
					|| PublicKey::from_str(&attempt.peer).is_err()
					|| bitcoin::OutPoint::from_str(&attempt.old_funding_txo).is_err()
					|| attempt.new_funding_txo.as_ref().is_some_and(|txo| {
						txo == &attempt.old_funding_txo || bitcoin::OutPoint::from_str(txo).is_err()
					}) =>
			{
				return Err(())
			},
			_ => {},
		}
	}
	let mut scids = HashSet::new();
	let mut requests = HashSet::new();
	let mut hashes = HashSet::new();
	for intent in &state.intents {
		let request = JitAuthorization::decode(&intent.request).map_err(|_| ())?;
		let fee =
			opening_fee(request.max_amount_msat, intent.flat_fee_sat, intent.fee_ppm).ok_or(())?;
		let principal_sat =
			request.max_amount_msat / 1000 + u64::from(request.max_amount_msat % 1000 != 0);
		let minimum_funding = principal_sat.checked_add(intent.spare_sats).ok_or(())?;
		let has_parts = state.holds.iter().any(|h| h.scid == intent.scid);
		if PublicKey::from_str(&intent.peer).is_err()
			|| intent.request.len() > 128
			|| intent.request != request.encode()
			|| request.request_id != intent.request_id
			|| request.payment_hash.is_some_and(|hash| intent.payment_hash != Some(hash))
			|| (request.payment_hash.is_none()
				&& !intent.consumed
				&& !has_parts
				&& intent.payment_hash.is_some())
			|| ((intent.consumed || has_parts) && intent.payment_hash.is_none())
			|| request.expected_total_msat.unwrap_or(0) != intent.expected_msat
			|| request.max_amount_msat == 0
			|| request.max_amount_msat < intent.expected_msat
			|| request.target_remaining_inbound_sat != intent.spare_sats
			|| request.expiry_seconds == 0
			|| request.expiry_seconds > 86_400
			|| (request.accepts_skimmed_fee && !intent.skim)
			// Legacy single-part records selected skim when their exact expected
			// share rounded to zero fees. Preserve that ACK, but group_forwards
			// still requires consent for any actual nonzero deduction.
			|| (!request.accepts_skimmed_fee && intent.skim && opening_fee(
				if intent.expected_msat == 0 { request.max_amount_msat } else { intent.expected_msat },
				intent.flat_fee_sat, intent.fee_ppm,
			).ok_or(())? != 0)
			|| (intent.skim && fee >= request.max_amount_msat)
			|| intent.fee_ppm > 1_000_000
			|| intent.expires_at == 0
			|| intent.funding_sats < 20_000
			|| intent.funding_sats < minimum_funding
			|| intent.funding_sats > 100_000_000
			|| !scids.insert(intent.scid)
			|| !requests.insert((intent.peer.clone(), intent.request_id))
			|| intent.payment_hash.is_some_and(|hash| !hashes.insert(hash))
		{
			return Err(());
		}
	}
	let mut splice_scids = HashSet::new();
	let mut splice_channels = HashSet::new();
	for splice in &state.splices {
		let intent = state.intents.iter().find(|i| i.scid == splice.scid).ok_or(())?;
		if !splice_scids.insert(splice.scid)
			|| !splice_channels.insert(splice.channel_id)
			|| splice.peer != intent.peer
			|| splice.collect_until == 0
			|| splice.started != intent.consumed
			|| !state.holds.iter().any(|h| h.scid == splice.scid)
			|| bitcoin::OutPoint::from_str(&splice.old_funding_txo).is_err()
			|| splice.new_funding_txo.as_ref().is_some_and(|new| {
				!splice.started
					|| new == &splice.old_funding_txo
					|| bitcoin::OutPoint::from_str(new).is_err()
			}) {
			return Err(());
		}
	}
	let mut intercepts = HashSet::new();
	let mut tags = HashSet::new();
	let mut held_funding = 0u64;
	for hold in &state.holds {
		if !scids.contains(&hold.scid) || !intercepts.insert(hold.intercept_id) {
			return Err(());
		}
	}
	for intent in &state.intents {
		let parts: Vec<_> = state.holds.iter().filter(|h| h.scid == intent.scid).collect();
		if parts.is_empty() {
			continue;
		}
		if parts.len() > MAX_PARTS_PER_PAYMENT {
			return Err(());
		}
		let first = parts[0];
		let total = parts
			.iter()
			.try_fold(0u64, |sum, part| {
				if part.peer != intent.peer
					|| part.deadline == 0
					|| part.deadline > intent.expires_at
					|| part.deadline != first.deadline
					|| part.user_channel_id != first.user_channel_id
					|| part.outbound_msat == 0
					|| part.inbound_msat < part.outbound_msat
				{
					return None;
				}
				sum.checked_add(part.outbound_msat)
			})
			.ok_or(())?;
		let request = JitAuthorization::decode(&intent.request).map_err(|_| ())?;
		if total > request.max_amount_msat {
			return Err(());
		}
		if intent.consumed {
			let forwards = forwards_for_state(state, intent.scid)?;
			if parts.iter().zip(forwards).any(|(part, forward)| part.forward_msat != forward) {
				return Err(());
			}
			if splice_scids.contains(&intent.scid) {
				if first.user_channel_id.is_some() {
					return Err(());
				}
				held_funding = held_funding.checked_add(intent.funding_sats).ok_or(())?;
			}
			if let Some(tag) = first.user_channel_id {
				if !tags.insert(tag) {
					return Err(());
				}
				held_funding = held_funding.checked_add(intent.funding_sats).ok_or(())?;
			}
		} else if first.user_channel_id.is_some()
			|| parts.iter().any(|part| part.forward_msat != part.outbound_msat)
		{
			return Err(());
		}
	}
	if held_funding > state.fronted_sats {
		return Err(());
	}
	Ok(())
}

fn validate_legacy_durable(state: &DurableState) -> Result<(), ()> {
	if state.version != 1
		|| state.funding_lease.is_some()
		|| !state.splices.is_empty()
		|| state.intents.len() > 1024
		|| state.holds.len() > 1024
		|| state.fronted_sats > 2_100_000_000_000_000
	{
		return Err(());
	}
	let mut scids = HashSet::new();
	let mut requests = HashSet::new();
	let mut hashes = HashSet::new();
	for intent in &state.intents {
		// The request bytes are replayed idempotently, while the other fields
		// authorize native funding. Reject any disagreement across that boundary.
		let request = JitAuthorization::decode(&intent.request).map_err(|_| ())?;
		let fee =
			opening_fee(intent.expected_msat, intent.flat_fee_sat, intent.fee_ppm).ok_or(())?;
		let principal_sat =
			request.max_amount_msat / 1000 + u64::from(request.max_amount_msat % 1000 != 0);
		let minimum_funding = principal_sat.checked_add(intent.spare_sats).ok_or(())?;
		if PublicKey::from_str(&intent.peer).is_err()
			|| intent.request.len() > 128
			|| intent.request != request.encode()
			|| request.request_id != intent.request_id
			|| request.payment_hash.is_some_and(|hash| intent.payment_hash != Some(hash))
			|| (request.payment_hash.is_none() && !intent.consumed && intent.payment_hash.is_some())
			|| (intent.consumed && intent.payment_hash.is_none())
			|| request.expected_total_msat != Some(intent.expected_msat)
			|| request.max_amount_msat < intent.expected_msat
			|| request.target_remaining_inbound_sat != intent.spare_sats
			|| request.expiry_seconds == 0
			|| request.expiry_seconds > 86_400
			|| intent.skim != (request.accepts_skimmed_fee || fee == 0)
			|| (intent.skim && fee >= intent.expected_msat)
			|| intent.fee_ppm > 1_000_000
			|| intent.expected_msat == 0
			|| intent.expires_at == 0
			|| intent.funding_sats < 20_000
			|| intent.funding_sats < minimum_funding
			|| intent.funding_sats > 100_000_000
			|| !scids.insert(intent.scid)
			|| !requests.insert((intent.peer.clone(), intent.request_id))
			|| intent.payment_hash.is_some_and(|hash| !hashes.insert(hash))
		{
			return Err(());
		}
	}
	let mut intercepts = HashSet::new();
	let mut held_scids = HashSet::new();
	let mut channel_tags = HashSet::new();
	let mut held_funding = 0u64;
	for hold in &state.holds {
		let intent = state.intents.iter().find(|i| i.scid == hold.scid).ok_or(())?;
		let fee =
			opening_fee(intent.expected_msat, intent.flat_fee_sat, intent.fee_ppm).ok_or(())?;
		let forward_msat = if intent.skim {
			intent.expected_msat.checked_sub(fee).ok_or(())?
		} else {
			intent.expected_msat
		};
		if !intercepts.insert(hold.intercept_id)
			|| !held_scids.insert(hold.scid)
			|| hold.forward_msat != forward_msat
			|| hold.deadline == 0
			|| hold.deadline > intent.expires_at
			|| hold.peer != intent.peer
			|| !intent.consumed
		{
			return Err(());
		}
		if let Some(tag) = hold.user_channel_id {
			if !channel_tags.insert(tag) {
				return Err(());
			}
			held_funding = held_funding.checked_add(intent.funding_sats).ok_or(())?;
		}
	}
	if held_funding > state.fronted_sats {
		return Err(());
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	#[test]
	fn splice_handshake_requires_enabled_private_provider() {
		for enabled in [false, true] {
			for allow_splice_jit in [false, true] {
				for announced in [false, true] {
					let policy =
						super::JitServiceConfig { enabled, allow_splice_jit, ..Default::default() };
					let handshake = policy.private_splice_handshake(announced);
					assert_eq!(handshake.is_some(), enabled && allow_splice_jit && !announced);
					if let Some(handshake) = handshake {
						assert_eq!(
							handshake.max_inbound_htlc_value_in_flight_msat,
							Some(2_100_000_000_000_000_000)
						);
						assert_eq!(
							handshake.retain_counterparty_htlc_limit_for_splicing,
							Some(true)
						);
					}
				}
			}
		}
	}

	use std::future::Future;
	use std::pin::Pin;
	use std::str::FromStr;
	use std::sync::atomic::{AtomicBool, Ordering};
	use std::sync::Arc;

	use bitcoin::hashes::Hash;
	use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
	use bitcoin::{Amount, Network, OutPoint, Transaction, TxIn, TxOut, Txid};
	use lightning::io;
	use lightning::ln::msgs::{BaseMessageHandler, Init};
	use lightning::util::persist::{KVStore, KVStoreSync};
	use lightning_types::features::InitFeatures;
	use proptest::prelude::*;

	use super::{
		opening_fee, validate_durable, ChicoryService, DurableState, Hold, Intent,
		JitServiceConfig, RELAY_PEER_MESSAGES_PER_SECOND, STORAGE_NAMESPACE,
	};
	use crate::builder::NodeBuilder;
	use crate::chicory::wire::{
		Envelope, JitAck, JitAuthorization, JitQuote, JitQuoteRequest, RelayAddress, RelayFrame,
		DIRECT_FUNDING_RELAY, JIT_AUTHORIZATION, JIT_QUOTE_REQUEST, PROTOCOL_VERSION,
	};
	use crate::config::Config;
	use crate::io::test_utils::InMemoryStore;
	use crate::types::DynStore;
	use crate::Node;

	struct FailStore {
		inner: InMemoryStore,
		fail: AtomicBool,
	}

	impl FailStore {
		fn new() -> Self {
			Self { inner: InMemoryStore::new(), fail: AtomicBool::new(false) }
		}
	}

	impl KVStoreSync for FailStore {
		fn read(&self, p: &str, s: &str, k: &str) -> io::Result<Vec<u8>> {
			KVStoreSync::read(&self.inner, p, s, k)
		}
		fn write(&self, p: &str, s: &str, k: &str, bytes: Vec<u8>) -> io::Result<()> {
			if p == STORAGE_NAMESPACE && self.fail.load(Ordering::Relaxed) {
				Err(io::Error::new(io::ErrorKind::Other, "injected JIT persistence failure"))
			} else {
				KVStoreSync::write(&self.inner, p, s, k, bytes)
			}
		}
		fn remove(&self, p: &str, s: &str, k: &str, lazy: bool) -> io::Result<()> {
			KVStoreSync::remove(&self.inner, p, s, k, lazy)
		}
		fn list(&self, p: &str, s: &str) -> io::Result<Vec<String>> {
			KVStoreSync::list(&self.inner, p, s)
		}
	}

	impl KVStore for FailStore {
		fn read(
			&self, p: &str, s: &str, k: &str,
		) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send>> {
			let result = KVStoreSync::read(self, p, s, k);
			Box::pin(async move { result })
		}
		fn write(
			&self, p: &str, s: &str, k: &str, bytes: Vec<u8>,
		) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send>> {
			let result = KVStoreSync::write(self, p, s, k, bytes);
			Box::pin(async move { result })
		}
		fn remove(
			&self, p: &str, s: &str, k: &str, lazy: bool,
		) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send>> {
			let result = KVStoreSync::remove(self, p, s, k, lazy);
			Box::pin(async move { result })
		}
		fn list(
			&self, p: &str, s: &str,
		) -> Pin<Box<dyn Future<Output = io::Result<Vec<String>>> + Send>> {
			let result = KVStoreSync::list(self, p, s);
			Box::pin(async move { result })
		}
	}

	fn native_test_node(store: Arc<DynStore>, funded: bool) -> Node {
		let config = Config {
			network: Network::Regtest,
			include_untrusted_pending_in_spendable: true,
			..Config::default()
		};
		let mut builder = NodeBuilder::from_config(config);
		builder.set_chain_source_esplora("http://127.0.0.1:1".into(), None);
		builder.set_entropy_seed_bytes([42; 64]);
		builder.set_log_facade_logger();
		builder
			.set_chicory_service(JitServiceConfig { enabled: true, ..Default::default() })
			.unwrap();
		let node = builder.build_with_store(store).unwrap();
		if funded {
			// Credit a synthetic wallet transaction without starting a network
			// connection. Only service admission is exercised by these tests.
			let address = node.wallet.get_new_witness_address().unwrap();
			let tx = Transaction {
				version: bitcoin::transaction::Version::TWO,
				lock_time: bitcoin::absolute::LockTime::ZERO,
				input: vec![TxIn {
					previous_output: OutPoint { txid: Txid::all_zeros(), vout: 1 },
					..Default::default()
				}],
				output: vec![TxOut {
					value: Amount::from_sat(1_000_000),
					script_pubkey: address.script_pubkey(),
				}],
			};
			node.wallet.apply_mempool_txs(vec![(tx, 1)], vec![]).unwrap();
			assert!(node.wallet.get_witness_spendable_amount_sats(0).unwrap() >= 1_000_000);
		}
		node
	}

	fn connect(service: &ChicoryService) -> PublicKey {
		let peer = PublicKey::from_str(&intent(false).peer).unwrap();
		service.peer_connected(
			peer,
			&Init { features: InitFeatures::empty(), networks: None, remote_network_address: None },
		);
		peer
	}

	fn authorization() -> JitAuthorization {
		JitAuthorization {
			request_id: [1; 8],
			payment_hash: Some([2; 32]),
			max_amount_msat: 1_000_000,
			expected_total_msat: Some(1_000_000),
			target_remaining_inbound_sat: 0,
			expiry_seconds: 600,
			accepts_skimmed_fee: true,
		}
	}

	fn register(service: &ChicoryService, peer: PublicKey, auth: &JitAuthorization) -> JitAck {
		service.handle_message(
			peer,
			Envelope {
				version: PROTOCOL_VERSION,
				subtype: JIT_AUTHORIZATION,
				payload: auth.encode(),
			},
		);
		let responses = service.get_and_clear_pending_msg();
		assert_eq!(responses.len(), 1);
		JitAck::decode(&responses[0].1.payload).unwrap()
	}

	#[test]
	fn native_registration_is_idempotent_and_survives_service_restart() {
		let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let node = native_test_node(store.clone(), true);
		let service = node.chicory_service.as_ref().unwrap();
		let peer = connect(service);
		let auth = authorization();
		let mut too_long = auth.clone();
		too_long.expiry_seconds = 601;
		assert!(!register(service, peer, &too_long).accepted);
		let first = register(service, peer, &auth);
		assert!(first.accepted, "{:?}", first.reason);
		assert_eq!(register(service, peer, &auth).intercept_scid, first.intercept_scid);
		assert_eq!(service.state.lock().unwrap().durable.intents.len(), 1);
		let mut changed = auth.clone();
		changed.expected_total_msat = Some(999_999);
		assert!(!register(service, peer, &changed).accepted);
		service.peer_disconnected(peer);
		service.handle_message(
			peer,
			Envelope {
				version: PROTOCOL_VERSION,
				subtype: JIT_AUTHORIZATION,
				payload: auth.encode(),
			},
		);
		assert!(service.get_and_clear_pending_msg().is_empty());
		let restored = ChicoryService::new(
			service.policy.clone(),
			node.channel_manager.clone(),
			node.chain_monitor.clone(),
			node.wallet.clone(),
			store,
			node.config.clone(),
		)
		.unwrap();
		connect(&restored);
		assert_eq!(register(&restored, peer, &auth).intercept_scid, first.intercept_scid);
		assert!(restored.owns_scid(first.intercept_scid));
	}

	#[test]
	fn wildcard_authorization_binds_once_and_preserves_replay_after_restart() {
		let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let node = native_test_node(store.clone(), true);
		let service = node.chicory_service.as_ref().unwrap();
		let peer = connect(service);
		let auth = JitAuthorization { payment_hash: None, ..authorization() };
		let ack = register(service, peer, &auth);
		assert!(ack.accepted, "{:?}", ack.reason);
		assert_eq!(register(service, peer, &auth).intercept_scid, ack.intercept_scid);
		{
			let mut state = service.state.lock().unwrap();
			let now = super::unix_now().unwrap();
			assert_eq!(state.durable.intents[0].payment_hash, None);
			assert!(!state.durable.intents[0].consumed);
			assert!(super::append_part(
				&mut state.durable,
				&service.policy,
				ack.intercept_scid,
				[1; 32],
				[7; 32],
				999_999,
				1_000_000,
				now
			)
			.is_err());
			assert_eq!(state.durable.intents[0].payment_hash, None);
			assert_eq!(
				super::append_part(
					&mut state.durable,
					&service.policy,
					ack.intercept_scid,
					[1; 32],
					[7; 32],
					1_000_000,
					1_000_000,
					now
				),
				Ok(true)
			);
			super::freeze_group(&mut state.durable, ack.intercept_scid, None).unwrap();
			assert_eq!(state.durable.intents[0].payment_hash, Some([7; 32]));
			assert!(state.durable.intents[0].consumed);
			assert!(super::append_part(
				&mut state.durable,
				&service.policy,
				ack.intercept_scid,
				[2; 32],
				[8; 32],
				1_000_000,
				1_000_000,
				now
			)
			.is_err());
			assert!(service.save(&mut state));
		}
		let bytes = KVStoreSync::read(&*store, STORAGE_NAMESPACE, "", super::STORAGE_KEY).unwrap();
		let saved: DurableState = serde_json::from_slice(&bytes).unwrap();
		assert!(saved.intents[0].consumed);
		assert_eq!(saved.intents[0].payment_hash, Some([7; 32]));
		assert_eq!(saved.intents[0].request, auth.encode());
		let restored = ChicoryService::new(
			service.policy.clone(),
			node.channel_manager.clone(),
			node.chain_monitor.clone(),
			node.wallet.clone(),
			store,
			node.config.clone(),
		)
		.unwrap();
		connect(&restored);
		assert_eq!(register(&restored, peer, &auth).intercept_scid, ack.intercept_scid);
		let hash_bound = JitAuthorization { payment_hash: Some([7; 32]), ..auth };
		assert!(!register(&restored, peer, &hash_bound).accepted);
		assert!(node.list_channels().is_empty());
	}

	#[test]
	fn wildcard_records_require_atomic_binding_and_unique_bound_hashes() {
		let mut wildcard = intent(true);
		wildcard.request = JitAuthorization { payment_hash: None, ..authorization() }.encode();
		wildcard.payment_hash = None;
		let mut state =
			DurableState { version: 1, intents: vec![wildcard.clone()], ..Default::default() };
		assert!(validate_durable(&state).is_ok());
		state.intents[0].consumed = true;
		assert!(validate_durable(&state).is_err());
		state.intents[0].payment_hash = Some([7; 32]);
		assert!(validate_durable(&state).is_ok());
		state.intents[0].consumed = false;
		assert!(validate_durable(&state).is_err());
		state.intents[0] = wildcard.clone();
		wildcard.scid = 2;
		wildcard.request_id = [2; 8];
		wildcard.request =
			JitAuthorization { request_id: [2; 8], payment_hash: None, ..authorization() }.encode();
		state.intents.push(wildcard);
		assert!(validate_durable(&state).is_ok());
		for intent in &mut state.intents {
			intent.payment_hash = Some([7; 32]);
			intent.consumed = true;
		}
		assert!(validate_durable(&state).is_err());
	}

	#[test]
	fn quote_and_authorization_refuse_unfunded_wallet_without_allocating() {
		let node = native_test_node(Arc::new(InMemoryStore::new()), false);
		let service = node.chicory_service.as_ref().unwrap();
		let peer = connect(service);
		let request = JitQuoteRequest {
			request_id: [1; 8],
			max_amount_msat: 1_000_000,
			target_remaining_inbound_sat: 0,
		};
		service.handle_message(
			peer,
			Envelope {
				version: PROTOCOL_VERSION,
				subtype: JIT_QUOTE_REQUEST,
				payload: request.encode(),
			},
		);
		let responses = service.get_and_clear_pending_msg();
		assert!(!JitQuote::decode(&responses[0].1.payload).unwrap().accepted);
		assert!(!register(service, peer, &authorization()).accepted);
		let state = service.state.lock().unwrap();
		assert!(state.durable.intents.is_empty());
		assert_eq!(state.durable.fronted_sats, 0);
		assert!(node.list_channels().is_empty());
	}

	#[test]
	fn uncertain_write_never_acknowledges_and_disables_later_registration() {
		let store = Arc::new(FailStore::new());
		let node = native_test_node(store.clone(), true);
		let service = node.chicory_service.as_ref().unwrap();
		let peer = connect(service);
		store.fail.store(true, Ordering::Relaxed);
		assert!(!register(service, peer, &authorization()).accepted);
		store.fail.store(false, Ordering::Relaxed);
		assert!(!register(service, peer, &authorization()).accepted);
		assert!(service.state.lock().unwrap().faulted);
		assert!(node.list_channels().is_empty());
	}

	#[test]
	fn restart_clears_holds_without_replaying_or_refunding_funding_attempt() {
		let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let node = native_test_node(store.clone(), true);
		let service = node.chicory_service.as_ref().unwrap();
		let peer = connect(service);
		let ack = register(service, peer, &authorization());
		assert!(ack.accepted);
		{
			let mut state = service.state.lock().unwrap();
			state.durable.intents[0].consumed = true;
			state.durable.fronted_sats = 20_000;
			let deadline = state.durable.intents[0].expires_at;
			state.durable.holds.push(Hold {
				intercept_id: [3; 32],
				scid: ack.intercept_scid,
				peer: peer.to_string(),
				forward_msat: 1_000_000,
				outbound_msat: 1_000_000,
				inbound_msat: 1_000_000,
				deadline,
				user_channel_id: Some(123),
			});
			assert!(service.save(&mut state));
		}
		let restored = ChicoryService::new(
			service.policy.clone(),
			node.channel_manager.clone(),
			node.chain_monitor.clone(),
			node.wallet.clone(),
			store,
			node.config.clone(),
		)
		.unwrap();
		let state = restored.state.lock().unwrap();
		assert!(state.durable.holds.is_empty());
		assert!(state.durable.intents[0].consumed);
		assert_eq!(state.durable.fronted_sats, 20_000);
		assert!(node.list_channels().is_empty());
	}

	#[test]
	fn late_channel_ready_expires_holds_without_refunding_budget() {
		let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let node = native_test_node(store.clone(), true);
		let service = node.chicory_service.as_ref().unwrap();
		let peer = connect(service);
		let ack = register(service, peer, &authorization());
		assert!(ack.accepted);
		{
			let mut state = service.state.lock().unwrap();
			state.durable.intents[0].consumed = true;
			state.durable.intents[0].expires_at = 1;
			state.durable.fronted_sats = 20_000;
			state.durable.holds.push(Hold {
				intercept_id: [3; 32],
				scid: ack.intercept_scid,
				peer: peer.to_string(),
				forward_msat: 1_000_000,
				outbound_msat: 1_000_000,
				inbound_msat: 1_000_000,
				deadline: 1,
				user_channel_id: Some(123),
			});
			assert!(service.save(&mut state));
		}
		service.channel_ready(lightning::ln::types::ChannelId([4; 32]), 123, peer, None);
		let bytes = KVStoreSync::read(&*store, STORAGE_NAMESPACE, "", super::STORAGE_KEY).unwrap();
		let state: DurableState = serde_json::from_slice(&bytes).unwrap();
		assert!(state.holds.is_empty());
		assert!(state.intents.is_empty());
		assert_eq!(state.fronted_sats, 20_000);
	}

	fn intent(skim: bool) -> Intent {
		let request = JitAuthorization { accepts_skimmed_fee: skim, ..authorization() }.encode();
		Intent {
			peer: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
			request_id: [1; 8],
			request,
			scid: 1,
			payment_hash: Some([2; 32]),
			expected_msat: 1_000_000,
			funding_sats: 20_000,
			spare_sats: 0,
			expires_at: 100,
			skim,
			flat_fee_sat: 100,
			fee_ppm: 10_000,
			consumed: false,
		}
	}

	fn multipart_state(expected: Option<u64>, cap: u64, skim: bool) -> DurableState {
		let mut entry = intent(skim);
		entry.expected_msat = expected.unwrap_or(0);
		entry.payment_hash = None;
		entry.request = JitAuthorization {
			payment_hash: None,
			expected_total_msat: expected,
			max_amount_msat: cap,
			accepts_skimmed_fee: skim,
			..authorization()
		}
		.encode();
		DurableState { version: 2, intents: vec![entry], ..Default::default() }
	}

	fn splice_record(scid: u64, peer: String) -> super::SpliceFunding {
		super::SpliceFunding {
			scid,
			peer,
			channel_id: [9; 32],
			old_funding_txo: format!("{}:0", "11".repeat(32)),
			new_funding_txo: None,
			collect_until: 2,
			started: false,
		}
	}

	#[test]
	fn splice_readiness_requires_exact_candidate_channel_and_peer() {
		let peer = PublicKey::from_str(&intent(true).peer).unwrap();
		let channel = lightning::ln::types::ChannelId([9; 32]);
		let mut splice = splice_record(1, peer.to_string());
		let old = bitcoin::OutPoint::from_str(&splice.old_funding_txo).unwrap();
		let new = bitcoin::OutPoint::from_str(&format!("{}:1", "22".repeat(32))).unwrap();
		let other = bitcoin::OutPoint::from_str(&format!("{}:2", "33".repeat(32))).unwrap();
		assert_eq!(splice.bind_candidate(new), Ok(false));
		splice.started = true;
		assert_eq!(splice.bind_candidate(old), Ok(false));
		assert!(!splice.matches_ready(channel, peer, Some(old)));
		assert!(!splice.matches_ready(channel, peer, Some(new)));
		assert_eq!(splice.bind_candidate(new), Ok(true));
		assert_eq!(splice.bind_candidate(new), Ok(true));
		assert_eq!(splice.bind_candidate(other), Err(()));
		assert!(splice.matches_ready(channel, peer, Some(new)));
		assert!(!splice.matches_ready(channel, peer, None));
		assert!(!splice.matches_ready(channel, peer, Some(other)));
		assert!(!splice.matches_ready(lightning::ln::types::ChannelId([8; 32]), peer, Some(new)));
		let mut wrong_peer = splice.clone();
		wrong_peer.peer = "bad".into();
		assert!(!wrong_peer.matches_ready(channel, peer, Some(new)));
	}

	fn native_pending_open(
		node: &Node, peer: PublicKey, tag: u64,
	) -> lightning::ln::types::ChannelId {
		let init = Init {
			features: node.channel_manager.provided_init_features(peer),
			networks: None,
			remote_network_address: None,
		};
		node.channel_manager.peer_connected(peer, &init, false).unwrap();
		node.channel_manager.create_channel(peer, 20_000, 0, u128::from(tag), None, None).unwrap()
	}

	#[test]
	fn splice_admission_dry_run_excludes_unconfirmed_wallet_change() {
		let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let node = native_test_node(store, true);
		let service = node.chicory_service.as_ref().unwrap();
		let peer = connect(service);
		let channel_id = native_pending_open(&node, peer, 123);
		let mut channel = node.channel_manager.list_channels_with_counterparty(&peer).remove(0);
		assert_eq!(channel.channel_id, channel_id);
		channel.funding_txo =
			Some(lightning::chain::transaction::OutPoint { txid: Txid::all_zeros(), index: 0 });
		assert!(node.wallet.get_witness_spendable_amount_sats(0).unwrap() >= 1_000_000);
		assert!(service.select_splice_inputs(&channel, 50_000).is_err());
		assert_eq!(service.state.lock().unwrap().durable.fronted_sats, 0);
		assert!(service.state.lock().unwrap().durable.funding_lease.is_none());
	}

	#[test]
	fn manual_wallet_operations_exclude_jit_and_remain_fenced_by_native_funding() {
		let node = native_test_node(Arc::new(InMemoryStore::new()), true);
		let service = node.chicory_service.as_ref().unwrap();
		let peer = connect(service);
		let operation = service.begin_wallet_operation().unwrap();
		assert!(service.begin_wallet_operation().is_err());
		assert!(!register(service, peer, &authorization()).accepted);
		// Peer callbacks must not block on a mutex retained by the operation.
		service.peer_disconnected(peer);
		assert!(!service.state.lock().unwrap().connected.contains(&peer));
		drop(operation);
		assert!(service.begin_wallet_operation().is_ok());
		connect(service);
		let channel = node
			.with_chicory_wallet_operation(|| {
				assert!(service.begin_wallet_operation().is_err());
				native_pending_open(&node, peer, 123)
			})
			.unwrap();
		assert!(service.begin_wallet_operation().is_err());
		node.channel_manager
			.force_close_broadcasting_latest_txn(&channel, &peer, "test cancellation".into())
			.unwrap();
		assert!(service.begin_wallet_operation().is_ok());
		// A persisted JIT reservation must exclude the inverse ordering too.
		service.state.lock().unwrap().durable.funding_lease = Some(super::FundingLease::Recovery);
		assert!(node.with_chicory_wallet_operation(|| panic!("must not execute")).is_err());
		service.state.lock().unwrap().durable.funding_lease = None;
		service.state.lock().unwrap().faulted = true;
		assert!(service.begin_wallet_operation().is_err());
	}

	#[test]
	fn funding_lease_blocks_other_peer_after_timeout_and_restart_until_native_resolution() {
		let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let node = native_test_node(store.clone(), true);
		let service = node.chicory_service.as_ref().unwrap();
		let peer = connect(service);
		let other = PublicKey::from_secret_key(
			&Secp256k1::new(),
			&SecretKey::from_slice(&[44; 32]).unwrap(),
		);
		let ack = register(service, peer, &authorization());
		assert!(ack.accepted);
		{
			let mut state = service.state.lock().unwrap();
			super::append_part(
				&mut state.durable,
				&service.policy,
				ack.intercept_scid,
				[1; 32],
				[2; 32],
				1_000_000,
				1_000_000,
				super::unix_now().unwrap(),
			)
			.unwrap();
			super::freeze_group(&mut state.durable, ack.intercept_scid, Some(123)).unwrap();
			assert!(service.save(&mut state));
		}
		let channel = native_pending_open(&node, peer, 123);
		assert!(node.channel_manager.has_pending_funding_operation());
		{
			let mut state = service.state.lock().unwrap();
			service.fail_group(&mut state, ack.intercept_scid);
			assert!(state.durable.holds.is_empty());
			assert!(state.durable.funding_lease.is_some());
			assert!(service.funding_available(&state, other, 20_000).is_err());
		}
		service.peer_disconnected(peer);
		let restored = ChicoryService::new(
			service.policy.clone(),
			node.channel_manager.clone(),
			node.chain_monitor.clone(),
			node.wallet.clone(),
			store,
			node.config.clone(),
		)
		.unwrap();
		restored.peer_connected(
			other,
			&Init { features: InitFeatures::empty(), networks: None, remote_network_address: None },
		);
		assert!(restored.state.lock().unwrap().durable.funding_lease.is_some());
		let other_auth =
			JitAuthorization { request_id: [8; 8], payment_hash: Some([8; 32]), ..authorization() };
		assert!(!register(&restored, other, &other_auth).accepted);
		// A mismatched event while native funding is pending cannot lift the fence.
		restored.channel_closed(lightning::ln::types::ChannelId([8; 32]), 999, Some(other));
		assert!(restored.state.lock().unwrap().durable.funding_lease.is_some());
		node.channel_manager
			.force_close_broadcasting_latest_txn(&channel, &peer, "test cancellation".into())
			.unwrap();
		assert!(!node.channel_manager.has_pending_funding_operation());
		restored.channel_closed(channel, 123, Some(peer));
		assert!(restored.state.lock().unwrap().durable.funding_lease.is_none());
		assert!(register(&restored, other, &other_auth).accepted);
		assert_eq!(restored.state.lock().unwrap().durable.fronted_sats, 20_000);
	}

	#[test]
	fn older_journal_unknown_native_attempt_gets_recovery_fence() {
		let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let node = native_test_node(store.clone(), true);
		let service = node.chicory_service.as_ref().unwrap();
		let peer = connect(service);
		let channel = native_pending_open(&node, peer, 123);
		let mut legacy = DurableState { version: 2, fronted_sats: 20_000, ..Default::default() };
		service.persist(&legacy).unwrap();
		let restored = ChicoryService::new(
			service.policy.clone(),
			node.channel_manager.clone(),
			node.chain_monitor.clone(),
			node.wallet.clone(),
			store.clone(),
			node.config.clone(),
		)
		.unwrap();
		assert!(matches!(
			restored.state.lock().unwrap().durable.funding_lease,
			Some(super::FundingLease::Recovery)
		));
		assert_eq!(restored.state.lock().unwrap().durable.version, 3);
		node.channel_manager
			.force_close_broadcasting_latest_txn(&channel, &peer, "test cancellation".into())
			.unwrap();
		restored.tick();
		assert!(restored.state.lock().unwrap().durable.funding_lease.is_none());
		// A crash after writing a lease but before the native call is reconciled
		// from native state without replaying a funding operation.
		legacy.version = 3;
		legacy.funding_lease = Some(super::FundingLease::Open {
			scid: 1,
			peer: peer.to_string(),
			channel_tag: 123,
			allocation_sats: 20_000,
		});
		service.persist(&legacy).unwrap();
		let recovered = ChicoryService::new(
			service.policy.clone(),
			node.channel_manager.clone(),
			node.chain_monitor.clone(),
			node.wallet.clone(),
			store,
			node.config.clone(),
		)
		.unwrap();
		assert!(recovered.state.lock().unwrap().durable.funding_lease.is_none());
		assert_eq!(recovered.state.lock().unwrap().durable.fronted_sats, 20_000);
		assert!(node.list_channels().is_empty());
	}

	#[test]
	fn failed_funding_fence_release_write_disables_future_allocations() {
		let store = Arc::new(FailStore::new());
		let node = native_test_node(store.clone(), true);
		let service = node.chicory_service.as_ref().unwrap();
		let peer = connect(service);
		{
			let mut state = service.state.lock().unwrap();
			state.durable.fronted_sats = 20_000;
			state.durable.funding_lease = Some(super::FundingLease::Open {
				scid: 1,
				peer: peer.to_string(),
				channel_tag: 123,
				allocation_sats: 20_000,
			});
			assert!(service.save(&mut state));
		}
		store.fail.store(true, Ordering::Relaxed);
		service.tick();
		assert!(service.state.lock().unwrap().faulted);
		assert!(!register(service, peer, &authorization()).accepted);
		let bytes = KVStoreSync::read(&*store, STORAGE_NAMESPACE, "", super::STORAGE_KEY).unwrap();
		let persisted: DurableState = serde_json::from_slice(&bytes).unwrap();
		assert!(persisted.funding_lease.is_some());
	}

	#[test]
	fn splice_groups_charge_once_and_do_not_wait_for_previously_forwarded_share() {
		let mut state = multipart_state(Some(1_000_000), 1_000_000, true);
		super::append_part(
			&mut state,
			&JitServiceConfig::default(),
			1,
			[1; 32],
			[7; 32],
			600_000,
			600_000,
			1,
		)
		.unwrap();
		state.splices.push(splice_record(1, state.intents[0].peer.clone()));
		assert!(validate_durable(&state).is_ok());
		super::freeze_group(&mut state, 1, None).unwrap();
		assert_eq!(state.fronted_sats, 20_000);
		assert_eq!(state.holds[0].forward_msat, 494_000);
		assert!(state.splices[0].started);
		assert_eq!(super::reserved_funding(&state), Some(20_000));
		assert!(validate_durable(&state).is_ok());
		assert!(super::freeze_group(&mut state, 1, None).is_err());
		assert!(super::append_part(
			&mut state,
			&JitServiceConfig::default(),
			1,
			[2; 32],
			[7; 32],
			1,
			1,
			2
		)
		.is_err());
		assert_eq!(state.fronted_sats, 20_000);
	}

	#[test]
	fn splice_journal_rejects_incoherent_channel_and_funding_correlation() {
		let mut state = multipart_state(Some(1_000_000), 1_000_000, true);
		super::append_part(
			&mut state,
			&JitServiceConfig::default(),
			1,
			[1; 32],
			[7; 32],
			600_000,
			600_000,
			1,
		)
		.unwrap();
		state.splices.push(splice_record(1, state.intents[0].peer.clone()));
		super::freeze_group(&mut state, 1, None).unwrap();
		let mut changes = Vec::new();
		let mut changed = state.clone();
		changed.splices.push(changed.splices[0].clone());
		changes.push(changed);
		let mut changed = state.clone();
		changed.splices[0].peer = "bad".into();
		changes.push(changed);
		let mut changed = state.clone();
		changed.splices[0].started = false;
		changes.push(changed);
		let mut changed = state.clone();
		changed.splices[0].old_funding_txo = "bad".into();
		changes.push(changed);
		let mut changed = state.clone();
		changed.splices[0].new_funding_txo = Some(changed.splices[0].old_funding_txo.clone());
		changes.push(changed);
		let mut changed = state.clone();
		changed.holds[0].user_channel_id = Some(123);
		changes.push(changed);
		let mut changed = state.clone();
		changed.fronted_sats = 0;
		changes.push(changed);
		let mut changed = state.clone();
		changed.holds.clear();
		changes.push(changed);
		for changed in changes {
			assert!(validate_durable(&changed).is_err());
		}
	}

	#[test]
	fn interrupted_splice_journal_never_replays_funding_on_restart() {
		for started in [false, true] {
			let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
			let node = native_test_node(store.clone(), true);
			let service = node.chicory_service.as_ref().unwrap();
			let peer = connect(service);
			let ack = register(
				service,
				peer,
				&JitAuthorization { payment_hash: None, ..authorization() },
			);
			assert!(ack.accepted);
			{
				let mut state = service.state.lock().unwrap();
				let now = super::unix_now().unwrap();
				super::append_part(
					&mut state.durable,
					&service.policy,
					ack.intercept_scid,
					[1; 32],
					[7; 32],
					600_000,
					600_000,
					now,
				)
				.unwrap();
				state.durable.splices.push(splice_record(ack.intercept_scid, peer.to_string()));
				if started {
					super::freeze_group(&mut state.durable, ack.intercept_scid, None).unwrap();
					state.durable.splices[0].new_funding_txo =
						Some(format!("{}:1", "22".repeat(32)));
				}
				assert!(validate_durable(&state.durable).is_ok());
				assert!(service.save(&mut state));
			}
			let restored = ChicoryService::new(
				service.policy.clone(),
				node.channel_manager.clone(),
				node.chain_monitor.clone(),
				node.wallet.clone(),
				store,
				node.config.clone(),
			)
			.unwrap();
			let state = restored.state.lock().unwrap();
			assert!(state.durable.holds.is_empty());
			assert!(state.durable.splices.is_empty());
			assert!(state.durable.intents[0].consumed);
			assert_eq!(state.durable.fronted_sats, if started { 20_000 } else { 0 });
			assert!(node.list_channels().is_empty());
		}
	}

	#[test]
	fn splice_hook_requires_both_explicit_provider_opt_ins() {
		for enabled in [false, true] {
			for allow_splice_jit in [false, true] {
				let mut builder = NodeBuilder::from_config(Config {
					network: Network::Regtest,
					..Default::default()
				});
				builder.set_entropy_seed_bytes([43; 64]);
				builder.set_log_facade_logger();
				builder
					.set_chicory_service(JitServiceConfig {
						enabled,
						allow_splice_jit,
						..Default::default()
					})
					.unwrap();
				let node = builder.build_with_store(Arc::new(InMemoryStore::new())).unwrap();
				assert_eq!(
					node.channel_manager.get_current_config().intercept_liquidity_shortfalls,
					enabled && allow_splice_jit
				);
			}
		}
	}

	#[test]
	fn multipart_accumulation_binds_hash_and_allocates_only_once() {
		let policy = JitServiceConfig::default();
		let mut state = multipart_state(Some(1_000_000), 1_000_000, true);
		assert_eq!(
			super::append_part(&mut state, &policy, 1, [1; 32], [7; 32], 400_000, 400_000, 1),
			Ok(false)
		);
		assert_eq!(state.intents[0].payment_hash, Some([7; 32]));
		assert!(!state.intents[0].consumed);
		assert_eq!(state.fronted_sats, 0);
		assert!(validate_durable(&state).is_ok());
		assert!(super::append_part(&mut state, &policy, 1, [1; 32], [7; 32], 400_000, 400_000, 2)
			.is_err());
		assert!(super::append_part(&mut state, &policy, 1, [2; 32], [8; 32], 600_000, 600_000, 2)
			.is_err());
		assert!(super::append_part(&mut state, &policy, 1, [2; 32], [7; 32], 599_999, 600_000, 2)
			.is_err());
		assert_eq!(state.holds.len(), 1);
		assert_eq!(
			super::append_part(&mut state, &policy, 1, [2; 32], [7; 32], 600_000, 600_000, 2),
			Ok(true)
		);
		assert_eq!(state.holds[0].deadline, state.holds[1].deadline);
		assert!(validate_durable(&state).is_ok());
		super::freeze_group(&mut state, 1, Some(123)).unwrap();
		assert_eq!(
			state.holds.iter().map(|h| h.forward_msat).collect::<Vec<_>>(),
			vec![400_000, 490_000]
		);
		assert_eq!(state.fronted_sats, 20_000);
		assert_eq!(super::reserved_funding(&state), Some(20_000));
		assert!(validate_durable(&state).is_ok());
		assert!(super::freeze_group(&mut state, 1, Some(456)).is_err());
		assert!(super::append_part(&mut state, &policy, 1, [3; 32], [7; 32], 1, 1, 3).is_err());
		assert_eq!(state.fronted_sats, 20_000);
		let mut damaged = state.clone();
		damaged.holds[1].user_channel_id = Some(456);
		assert!(validate_durable(&damaged).is_err());
		damaged = state.clone();
		damaged.holds[0].forward_msat -= 1;
		assert!(validate_durable(&damaged).is_err());
	}

	#[test]
	fn multipart_fee_rounding_matches_skim_and_hop_reference() {
		for skim in [false, true] {
			let mut state = multipart_state(Some(1_000_000), 1_000_000, skim);
			state.intents[0].fee_ppm = 1;
			let policy = JitServiceConfig::default();
			super::append_part(&mut state, &policy, 1, [1; 32], [7; 32], 550_001, 500_001, 1)
				.unwrap();
			super::append_part(&mut state, &policy, 1, [2; 32], [7; 32], 549_999, 499_999, 2)
				.unwrap();
			super::freeze_group(&mut state, 1, None).unwrap();
			let sum: u64 = state.holds.iter().map(|h| h.forward_msat).sum();
			assert_eq!(sum, if skim { 899_999 } else { 1_000_000 });
			assert_eq!(state.fronted_sats, 0);
			assert!(validate_durable(&state).is_ok());
		}
		let mut state = multipart_state(Some(200_000), 1_000_000, true);
		let policy = JitServiceConfig::default();
		super::append_part(&mut state, &policy, 1, [1; 32], [7; 32], 100_000, 100_000, 1).unwrap();
		super::append_part(&mut state, &policy, 1, [2; 32], [7; 32], 100_000, 100_000, 2).unwrap();
		assert!(super::freeze_group(&mut state, 1, Some(123)).is_err());
		assert_eq!(state.fronted_sats, 0);
		assert!(!state.intents[0].consumed);
	}

	#[test]
	fn completing_group_at_global_part_limit_can_fund() {
		let node = native_test_node(Arc::new(InMemoryStore::new()), true);
		let template = node.chicory_service.as_ref().unwrap();
		for limit in [1, 16] {
			let policy =
				JitServiceConfig { enabled: true, max_held_htlcs: limit, ..Default::default() };
			let service = ChicoryService::new(
				policy,
				node.channel_manager.clone(),
				node.chain_monitor.clone(),
				node.wallet.clone(),
				Arc::new(InMemoryStore::new()),
				node.config.clone(),
			)
			.unwrap();
			let peer = connect(&service);
			let ack = register(
				&service,
				peer,
				&JitAuthorization { payment_hash: None, ..authorization() },
			);
			assert!(ack.accepted);
			let mut state = service.state.lock().unwrap();
			for id in 0..limit {
				let amount = 1_000_000 / limit as u64;
				let ready = super::append_part(
					&mut state.durable,
					&service.policy,
					ack.intercept_scid,
					[id as u8; 32],
					[7; 32],
					amount,
					amount,
					super::unix_now().unwrap(),
				)
				.unwrap();
				assert_eq!(ready, id + 1 == limit);
			}
			assert_eq!(state.durable.holds.len(), limit);
			assert!(service.funding_available(&state, peer, 20_000).is_ok());
			assert!(service.admission(&state, &peer.to_string(), 1_000_000, 0).is_err());
			super::freeze_group(&mut state.durable, ack.intercept_scid, Some(123)).unwrap();
			assert_eq!(super::reserved_funding(&state.durable), Some(20_000));
		}
		assert!(template.state.lock().unwrap().durable.holds.is_empty());
	}

	#[test]
	fn multipart_share_caps_and_fixed_deadline_are_enforced() {
		for expected in [None, Some(400_000)] {
			let mut state = multipart_state(expected, 1_000_000, true);
			assert_eq!(
				super::append_part(
					&mut state,
					&JitServiceConfig::default(),
					1,
					[1; 32],
					[7; 32],
					600_000,
					600_000,
					1
				),
				Ok(true)
			);
			super::freeze_group(&mut state, 1, None).unwrap();
			assert_eq!(state.holds[0].forward_msat, 494_000);
			assert!(validate_durable(&state).is_ok());
		}
		let policy = JitServiceConfig { max_held_htlcs: 32, ..Default::default() };
		let mut state = multipart_state(Some(1_000_000), 1_000_000, true);
		for id in 0..16 {
			assert_eq!(
				super::append_part(&mut state, &policy, 1, [id; 32], [7; 32], 1, 1, 1),
				Ok(false)
			);
		}
		assert!(super::append_part(&mut state, &policy, 1, [17; 32], [7; 32], 1, 1, 2).is_err());
		let policy = JitServiceConfig { max_held_htlcs: 1, ..Default::default() };
		let mut state = multipart_state(Some(1_000_000), 1_000_000, true);
		super::append_part(&mut state, &policy, 1, [1; 32], [7; 32], 400_000, 400_000, 1).unwrap();
		assert!(super::append_part(&mut state, &policy, 1, [2; 32], [7; 32], 1, 1, 2).is_err());
		let policy = JitServiceConfig::default();
		assert!(super::append_part(&mut state, &policy, 1, [2; 32], [7; 32], 600_001, 600_001, 2)
			.is_err());
		assert!(super::append_part(&mut state, &policy, 1, [2; 32], [7; 32], 1, 1, 61).is_err());
		assert_eq!(
			super::append_part(&mut state, &policy, 1, [2; 32], [7; 32], 1, 1, 60),
			Ok(false)
		);
		assert_eq!(state.holds[1].deadline, 61);
	}

	#[test]
	fn multipart_restart_fails_gathering_and_frozen_groups_without_refunding() {
		for frozen in [false, true] {
			let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
			let node = native_test_node(store.clone(), true);
			let service = node.chicory_service.as_ref().unwrap();
			let peer = connect(service);
			let auth = JitAuthorization { payment_hash: None, ..authorization() };
			let ack = register(service, peer, &auth);
			assert!(ack.accepted);
			{
				let mut state = service.state.lock().unwrap();
				let now = super::unix_now().unwrap();
				super::append_part(
					&mut state.durable,
					&service.policy,
					ack.intercept_scid,
					[1; 32],
					[7; 32],
					400_000,
					400_000,
					now,
				)
				.unwrap();
				if frozen {
					super::append_part(
						&mut state.durable,
						&service.policy,
						ack.intercept_scid,
						[2; 32],
						[7; 32],
						600_000,
						600_000,
						now,
					)
					.unwrap();
					super::freeze_group(&mut state.durable, ack.intercept_scid, Some(123)).unwrap();
				}
				assert!(validate_durable(&state.durable).is_ok());
				assert!(service.save(&mut state));
			}
			let restored = ChicoryService::new(
				service.policy.clone(),
				node.channel_manager.clone(),
				node.chain_monitor.clone(),
				node.wallet.clone(),
				store,
				node.config.clone(),
			)
			.unwrap();
			let state = restored.state.lock().unwrap();
			assert!(state.durable.holds.is_empty());
			assert!(state.durable.intents[0].consumed);
			assert_eq!(state.durable.intents[0].payment_hash, Some([7; 32]));
			assert_eq!(state.durable.fronted_sats, if frozen { 20_000 } else { 0 });
			assert!(node.list_channels().is_empty());
		}
	}

	#[test]
	fn omitted_share_authorization_and_failed_gathering_write_never_fund() {
		let store = Arc::new(FailStore::new());
		let node = native_test_node(store.clone(), true);
		let service = node.chicory_service.as_ref().unwrap();
		let peer = connect(service);
		let auth =
			JitAuthorization { expected_total_msat: None, payment_hash: None, ..authorization() };
		let ack = register(service, peer, &auth);
		assert!(ack.accepted);
		{
			let mut state = service.state.lock().unwrap();
			super::append_part(
				&mut state.durable,
				&service.policy,
				ack.intercept_scid,
				[1; 32],
				[7; 32],
				400_000,
				400_000,
				super::unix_now().unwrap(),
			)
			.unwrap();
			store.fail.store(true, Ordering::Relaxed);
			assert!(!service.save(&mut state));
			service.fail_group(&mut state, ack.intercept_scid);
			assert!(state.faulted);
			assert!(state.durable.holds.is_empty());
			assert_eq!(state.durable.fronted_sats, 0);
		}
		assert!(node.list_channels().is_empty());
	}

	fn relay_service(node: &Node) -> ChicoryService {
		let service = node.chicory_service.as_ref().unwrap();
		ChicoryService::new(
			JitServiceConfig { relay_enabled: true, ..service.policy.clone() },
			node.channel_manager.clone(),
			node.chain_monitor.clone(),
			node.wallet.clone(),
			service.kv_store.clone(),
			node.config.clone(),
		)
		.unwrap()
	}

	fn relay_target(service: &ChicoryService) -> PublicKey {
		let target = PublicKey::from_secret_key(
			&Secp256k1::new(),
			&SecretKey::from_slice(&[3; 32]).unwrap(),
		);
		service.peer_connected(
			target,
			&Init { features: InitFeatures::empty(), networks: None, remote_network_address: None },
		);
		target
	}

	fn relay_envelope(address: RelayAddress, subtype: u16, payload: Vec<u8>) -> Envelope {
		Envelope {
			version: PROTOCOL_VERSION,
			subtype: DIRECT_FUNDING_RELAY,
			payload: RelayFrame { subtype, payload, address }.encode().unwrap(),
		}
	}

	#[test]
	fn relay_authenticates_origin_and_rejects_spoofing_and_recursion() {
		let node = native_test_node(Arc::new(InMemoryStore::new()), false);
		let service = relay_service(&node);
		let sender = connect(&service);
		let target = relay_target(&service);
		service.handle_message(
			sender,
			relay_envelope(RelayAddress::To(target.serialize()), 16, vec![7; 5]),
		);
		let responses = service.get_and_clear_pending_msg();
		assert_eq!(responses.len(), 1);
		assert_eq!(responses[0].0, target);
		let forwarded = RelayFrame::decode(&responses[0].1.payload).unwrap();
		assert_eq!(forwarded.address, RelayAddress::From(sender.serialize()));
		assert_eq!(forwarded.payload, vec![7; 5]);
		service.handle_message(
			sender,
			relay_envelope(RelayAddress::From(target.serialize()), 16, vec![]),
		);
		service.handle_message(
			sender,
			relay_envelope(RelayAddress::To(target.serialize()), DIRECT_FUNDING_RELAY, vec![]),
		);
		service.handle_message(
			sender,
			relay_envelope(RelayAddress::To(sender.serialize()), 16, vec![]),
		);
		let mut unknown = relay_envelope(RelayAddress::To(target.serialize()), 16, vec![]);
		unknown.version = 2;
		service.handle_message(sender, unknown);
		assert!(service.get_and_clear_pending_msg().is_empty());
		service.peer_disconnected(target);
		service.handle_message(
			sender,
			relay_envelope(RelayAddress::To(target.serialize()), 16, vec![]),
		);
		assert!(service.get_and_clear_pending_msg().is_empty());
	}

	#[test]
	fn relay_requires_explicit_enablement_and_bounds_each_peer() {
		let node = native_test_node(Arc::new(InMemoryStore::new()), false);
		let disabled = node.chicory_service.as_ref().unwrap();
		let sender = connect(disabled);
		let target = relay_target(disabled);
		disabled.handle_message(
			sender,
			relay_envelope(RelayAddress::To(target.serialize()), 16, vec![]),
		);
		assert!(disabled.get_and_clear_pending_msg().is_empty());
		let service = relay_service(&node);
		connect(&service);
		relay_target(&service);
		for _ in 0..RELAY_PEER_MESSAGES_PER_SECOND + 1 {
			service.handle_message(
				sender,
				relay_envelope(RelayAddress::To(target.serialize()), 16, vec![]),
			);
		}
		assert_eq!(service.get_and_clear_pending_msg().len(), RELAY_PEER_MESSAGES_PER_SECOND);
		let service = relay_service(&node);
		connect(&service);
		relay_target(&service);
		for _ in 0..5 {
			service.handle_message(
				sender,
				relay_envelope(RelayAddress::To(target.serialize()), 16, vec![1; 32_000]),
			);
		}
		assert_eq!(service.get_and_clear_pending_msg().len(), 4);
	}

	#[test]
	fn removed_offline_protocol_is_not_served_or_advertised() {
		let node = native_test_node(Arc::new(InMemoryStore::new()), false);
		let service = node.chicory_service.as_ref().unwrap();
		let peer = connect(service);
		for subtype in [80, 81] {
			service.handle_message(
				peer,
				Envelope {
					version: PROTOCOL_VERSION,
					subtype,
					payload: br#"{"id":"0123456789abcdef0123456789abcdef","op":"quote"}"#.to_vec(),
				},
			);
		}
		assert!(service.get_and_clear_pending_msg().is_empty());
		assert!(service.state.lock().unwrap().durable.intents.is_empty());
		let features = node.channel_manager.provided_init_features(peer);
		for bit in [440, 441, 442, 443, 444, 445] {
			assert_eq!(
				features.le_flags().get(bit / 8).copied().unwrap_or(0) & (1 << (bit % 8)),
				0,
				"Removed offline protocol feature bit {bit} must not be advertised"
			);
		}
	}

	#[test]
	fn defaults_require_explicit_opt_in_and_validate() {
		let config = JitServiceConfig::default();
		assert!(!config.enabled);
		assert!(!config.allow_confirmed_v2);
		assert_eq!(config.inbound_splice_minimum_depth, 6);
		assert!(!config.reuse_funding_key_on_splice);
		assert!(config.validate().is_ok());
		for inbound_splice_minimum_depth in [0, 145, u32::MAX] {
			assert!(JitServiceConfig { inbound_splice_minimum_depth, ..config.clone() }
				.validate()
				.is_err());
		}
		for inbound_splice_minimum_depth in [1, 144] {
			assert!(JitServiceConfig { inbound_splice_minimum_depth, ..config.clone() }
				.validate()
				.is_ok());
		}
	}

	#[test]
	fn confirmed_v2_opt_in_is_independent_of_jit_funding() {
		for allow_confirmed_v2 in [false, true] {
			let mut builder =
				NodeBuilder::from_config(Config { network: Network::Regtest, ..Config::default() });
			builder.set_chain_source_esplora("http://127.0.0.1:1".into(), None);
			builder.set_entropy_seed_bytes([41; 64]);
			builder.set_log_facade_logger();
			builder
				.set_chicory_service(JitServiceConfig {
					allow_confirmed_v2,
					reuse_funding_key_on_splice: allow_confirmed_v2,
					..Default::default()
				})
				.unwrap();
			let node = builder.build_with_store(Arc::new(InMemoryStore::new())).unwrap();
			let native_config = node.channel_manager.get_current_config();
			assert_eq!(native_config.accept_inbound_channels_v2, allow_confirmed_v2);
			assert_eq!(
				native_config.channel_handshake_config.reuse_funding_key_on_splice,
				allow_confirmed_v2
			);
			assert!(!native_config.intercept_liquidity_shortfalls);
			assert_eq!(native_config.minimum_inbound_splice_depth, Some(6));
			assert!(!native_config.accept_intercept_htlcs);
			assert_eq!(
				node.channel_manager.provided_init_features(node.node_id()).supports_dual_fund(),
				allow_confirmed_v2
			);
		}
	}

	#[test]
	fn funding_uses_checked_rounded_arithmetic() {
		let config = JitServiceConfig::default();
		assert_eq!(config.funding_amount(10_000_001, 0), Ok(20_001));
		assert!(config.funding_amount(1, u64::MAX).is_err());
		assert!(config.funding_amount(u64::MAX, 0).is_err());
		assert!(config.funding_amount(0, 0).is_err());
	}

	#[test]
	fn single_part_groups_keep_fee_and_principal_checks() {
		for skim in [false, true] {
			for inbound in [999_999, 1_000_000, 1_109_999, 1_110_000] {
				let mut state = multipart_state(Some(1_000_000), 1_000_000, skim);
				let accepted = super::append_part(
					&mut state,
					&JitServiceConfig::default(),
					1,
					[1; 32],
					[7; 32],
					inbound,
					1_000_000,
					1,
				)
				.is_ok() && super::freeze_group(&mut state, 1, None).is_ok();
				assert_eq!(accepted, inbound >= if skim { 1_000_000 } else { 1_110_000 });
				if accepted {
					assert_eq!(state.holds[0].forward_msat, if skim { 890_000 } else { 1_000_000 });
				}
			}
		}
	}

	#[test]
	fn corrupt_or_ambiguous_persisted_state_is_rejected() {
		let mut state =
			DurableState { version: 1, intents: vec![intent(false)], ..Default::default() };
		assert!(validate_durable(&state).is_ok());
		state.intents.push(intent(false));
		assert!(validate_durable(&state).is_err());
		state.intents.clear();
		state.version = 4;
		assert!(validate_durable(&state).is_err());
	}

	#[test]
	fn persisted_authorization_fields_and_hold_limits_must_agree() {
		let mut state = DurableState {
			version: 1,
			fronted_sats: 20_000,
			intents: vec![intent(true)],
			..Default::default()
		};
		state.intents[0].consumed = true;
		state.holds.push(Hold {
			intercept_id: [3; 32],
			scid: 1,
			peer: state.intents[0].peer.clone(),
			forward_msat: 890_000,
			outbound_msat: 1_000_000,
			inbound_msat: 1_000_000,
			deadline: 99,
			user_channel_id: Some(123),
		});
		assert!(validate_durable(&state).is_ok());
		let mut malformed = Vec::new();
		let mut changed = state.clone();
		changed.intents[0].payment_hash = Some([9; 32]);
		malformed.push(changed);
		let mut changed = state.clone();
		changed.intents[0].expected_msat = 2_000_000;
		malformed.push(changed);
		let mut changed = state.clone();
		changed.intents[0].skim = false;
		malformed.push(changed);
		let mut changed = state.clone();
		changed.intents[0].request.push(0);
		malformed.push(changed);
		let mut changed = state.clone();
		changed.intents[0].funding_sats = 19_999;
		malformed.push(changed);
		let mut changed = state.clone();
		changed.holds[0].deadline = 101;
		malformed.push(changed);
		let mut changed = state.clone();
		changed.holds[0].forward_msat += 1;
		malformed.push(changed);
		let mut changed = state.clone();
		changed.fronted_sats = 19_999;
		malformed.push(changed);
		let mut changed = state.clone();
		let mut duplicate = changed.holds[0].clone();
		duplicate.intercept_id = [4; 32];
		changed.holds.push(duplicate);
		malformed.push(changed);
		for state in malformed {
			assert!(validate_durable(&state).is_err());
		}
	}

	#[test]
	fn constructor_refuses_damaged_authorization_without_rewriting_it() {
		let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let node = native_test_node(store.clone(), true);
		let service = node.chicory_service.as_ref().unwrap();
		let peer = connect(service);
		assert!(register(service, peer, &authorization()).accepted);
		let mut damaged = service.state.lock().unwrap().durable.clone();
		damaged.intents[0].payment_hash = Some([9; 32]);
		let bytes = serde_json::to_vec(&damaged).unwrap();
		KVStoreSync::write(&*store, STORAGE_NAMESPACE, "", super::STORAGE_KEY, bytes.clone())
			.unwrap();
		let result = ChicoryService::new(
			service.policy.clone(),
			node.channel_manager.clone(),
			node.chain_monitor.clone(),
			node.wallet.clone(),
			store.clone(),
			node.config.clone(),
		);
		assert!(matches!(result, Err(crate::builder::BuildError::ReadFailed)));
		assert_eq!(
			KVStoreSync::read(&*store, STORAGE_NAMESPACE, "", super::STORAGE_KEY).unwrap(),
			bytes
		);
		assert!(node.list_channels().is_empty());
	}

	proptest! {
		#[test]
		fn fees_match_wide_integer_reference(amount in any::<u64>(), flat in any::<u64>(), ppm in any::<u32>()) {
			let expected = u128::from(flat) * 1000 + u128::from(amount) * u128::from(ppm) / 1_000_000;
			prop_assert_eq!(opening_fee(amount, flat, ppm), u64::try_from(expected).ok());
		}

		#[test]
		fn accepted_forward_never_exceeds_inbound(inbound in any::<u64>(), skim in any::<bool>()) {
			let mut state = multipart_state(Some(1_000_000), 1_000_000, skim);
			if super::append_part(&mut state, &JitServiceConfig::default(), 1, [1;32], [7;32], inbound, 1_000_000, 1).is_ok()
				&& super::freeze_group(&mut state, 1, None).is_ok() {
				prop_assert!(state.holds[0].forward_msat <= inbound);
				prop_assert!(state.holds[0].forward_msat > 0);
			}
		}
	}
}
