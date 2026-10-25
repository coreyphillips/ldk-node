//! Native custody barriers for the concurrent FFOR settler.
//!
//! Lock order is the ordinary channel peer lock followed by `ffor_runtime`.
//! No channel operation, monitor call, or preimage claim is made while holding
//! `ffor_runtime`. Its durable view advances only from actual monitor completion.

use super::*;
use crate::ln::ffor::{self, Action, PreparedTransition, SlotState, Upstream};
use crate::ln::ffor_monitor::{FforJournal, FforPersistenceToken};
use core::fmt;
use alloc::collections::BTreeSet;
#[cfg(feature = "std")]
use crate::util::time::Instant;

// Closed homes are retained for custody and replay, so admission stops at this
// global lifetime ceiling rather than evicting an obligation or an old hash.
const MAX_FFOR_HOMES: usize = 128;

/// Explicit local limits for the experimental concurrent FFOR settler.
/// Configuration is disabled by default. Existing durable obligations are still
/// replayed when disabled, so changing policy cannot discard a funded voucher.
#[derive(Clone, Debug)]
pub struct FforPolicy {
	/// Permit new signed epochs on compatible private anchor channels.
	pub enabled: bool,
	/// Maximum vouchers in one epoch, between one and 483.
	pub max_slots: u16,
	/// Maximum total reserved amount in one epoch, in millisatoshis.
	pub max_budget_msat: u64,
	/// Maximum lifetime from the current tip to voucher expiry.
	pub max_epoch_blocks: u32,
	/// Minimum signed base fee for delegated receipts.
	pub fee_base_msat: u32,
	/// Minimum signed proportional fee in millionths.
	pub fee_ppm: u32,
}
/// Public, secret-free view of a durably persisted offline reservation.
/// This is operational status, never authorization to settle or release custody.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FforEpochStatus {
	/// The native home channel identity.
	pub channel_id: ChannelId,
	/// The signed epoch identity.
	pub epoch_id: [u8; 32],
	/// The last durable phase, expressed as an uppercase protocol name.
	pub phase: String,
	/// Number of immutable vouchers in this epoch.
	pub slot_count: u16,
	/// Amount still represented by vouchers without durable removal evidence.
	pub reserved_msat: u64,
	/// Vouchers whose delegated settlement is in progress.
	pub settling_count: u16,
	/// Vouchers whose delegated settlement is durably complete.
	pub settled_count: u16,
	/// Whether additional custody transitions are waiting for persistence.
	pub persistence_pending: bool,
}

impl Default for FforPolicy {
	fn default() -> Self {
		Self { enabled: false, max_slots: 16, max_budget_msat: 100_000_000,
			max_epoch_blocks: 2016, fee_base_msat: 0, fee_ppm: 0 }
	}
}

/// An authenticated FFOR custom message. Payload diagnostics are redacted because
/// settlement receipts may contain payment preimages. Forward only to `peer`.
#[derive(Clone)]
pub struct FforMessage {
	/// The authenticated channel counterparty.
	pub peer: PublicKey,
	/// The BOLT custom message type.
	pub message_type: u16,
	/// Canonical signed body, excluding the two-byte message type.
	pub payload: Vec<u8>,
}
impl fmt::Debug for FforMessage {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("FforMessage").field("peer", &self.peer)
			.field("message_type", &self.message_type).field("bytes", &self.payload.len()).finish()
	}
}

/// A receipt whose custody transition has completed native monitor persistence.
/// It must only be given to the authenticated peer named by the query.
#[derive(Clone)]
pub struct FforReceipt {
	/// The one-based immutable voucher slot.
	pub slot: u16,
	/// The payment preimage for the settled voucher.
	pub preimage: [u8; 32],
}
impl fmt::Debug for FforReceipt {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("FforReceipt").field("slot", &self.slot).finish()
	}
}

struct PendingTransition {
	token: FforPersistenceToken,
	journal: FforJournal,
	actions: Vec<Action>,
}
struct ReplayGate { validated: bool, required: Option<([u8; 32], u64)>, ready: bool, messages: Vec<MessageSendEvent> }

struct Home {
	funding_txo: OutPoint,
	current: FforJournal,
	durable: Option<FforJournal>,
	persisted_update_id: u64,
	pending: BTreeMap<u64, PendingTransition>,
}

pub(super) struct FforRuntime {
	policy: FforPolicy,
	progress_running: bool,
	replay_gates: BTreeMap<ChannelId, ReplayGate>,
	homes: BTreeMap<ChannelId, Home>,
	messages: Vec<FforMessage>,
	/// Native voucher results are processed after leaving peer locks and monitor
	/// event loops, preserving the ordinary persistence and replay boundaries.
	results: Vec<(ChannelId, [u8; 32], u16, Option<PaymentPreimage>)>,
	chain_results: BTreeMap<(ChannelId, [u8; 32], u16), (ffor::ChainRemoval, PaymentCompleteUpdate)>,
	chain_released: BTreeSet<(ChannelId, [u8; 32], u16)>,
	/// One native upstream monitor operation per immutable delegated binding.
	/// Rebuilt by replay after restart, never used as durable settlement evidence.
	claims_inflight: BTreeSet<(ChannelId, [u8; 32], u16)>,
	requests: BTreeMap<ChannelId, (PublicKey, ffor::SignedMessage)>,
	started: BTreeMap<ChannelId, u64>,
	sync_rate: BTreeMap<ChannelId, (u64, u8)>,
	after_send: Vec<(FforPersistenceToken, Action)>,
	#[cfg(feature = "std")]
	clock_origin: Instant,
}
impl FforRuntime {
	pub(super) fn new() -> Self {
		Self { policy: FforPolicy::default(), progress_running: false, replay_gates: BTreeMap::new(), homes: BTreeMap::new(), messages: Vec::new(), results: Vec::new(), chain_results: BTreeMap::new(), chain_released: BTreeSet::new(), claims_inflight: BTreeSet::new(), requests: BTreeMap::new(), started: BTreeMap::new(), sync_rate: BTreeMap::new(), after_send: Vec::new(),
			#[cfg(feature = "std")] clock_origin: Instant::now(), }
	}

	fn now(&self) -> u64 {
		#[cfg(feature = "std")] { Instant::now().duration_since(self.clock_origin).as_secs() }
		#[cfg(not(feature = "std"))] { 0 }
	}

	pub(super) fn restore(&mut self, journal: FforJournal, funding_txo: OutPoint, update_id: u64) -> Result<(), DecodeError> {
		journal.validate().map_err(|_| DecodeError::InvalidValue)?;
		let channel = ChannelId(journal.epoch.channel_id);
		if self.homes.contains_key(&channel) || self.homes.len() >= MAX_FFOR_HOMES { return Err(DecodeError::InvalidValue); }
		self.homes.insert(channel, Home { funding_txo, current: journal.clone(), durable: Some(journal),
			persisted_update_id: update_id, pending: BTreeMap::new() });
		Ok(())
	}
}

fn unavailable() -> APIError {
	APIError::APIMisuseError { err: "FFOR transition is not admissible in the current native state".to_owned() }
}

impl<M: Deref, T: Deref, ES: Deref, NS: Deref, SP: Deref, F: Deref, R: Deref, MR: Deref, L: Deref>
	ChannelManager<M, T, ES, NS, SP, F, R, MR, L>
where M::Target: chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
	T::Target: BroadcasterInterface, ES::Target: EntropySource, NS::Target: NodeSigner,
	SP::Target: SignerProvider, F::Target: FeeEstimator, R::Target: Router,
	MR::Target: MessageRouter, L::Target: Logger,
{
	/// Set explicit settler limits before connecting peers. Disabling new epochs
	/// does not suppress replay of already durable incoming claims.
	pub fn set_ffor_policy(&self, policy: FforPolicy) -> Result<(), APIError> {
		if policy.max_slots == 0 || policy.max_slots as usize > ffor::MAX_SLOTS
			|| policy.max_budget_msat == 0 || !(1008..=5040).contains(&policy.max_epoch_blocks)
			|| policy.enabled && (!cfg!(feature = "std") || !self.node_signer.supports_ffor_settler()) { return Err(unavailable()); }
		let changes_features = self.ffor_runtime.lock().unwrap().policy.enabled != policy.enabled;
		if changes_features && self.per_peer_state.read().unwrap().values().any(|peer| peer.lock().unwrap().is_connected) {
			return Err(APIError::APIMisuseError { err: "Configure FFOR features before connecting peers".to_owned() });
		}
		self.ffor_runtime.lock().unwrap().policy = policy;
		Ok(())
	}

	/// Whether this node is configured to sign the concurrent settler protocol.
	/// Peer-specific admission additionally requires both negotiated FFOR feature pairs.
	pub fn ffor_settler_enabled(&self) -> bool {
		self.ffor_runtime.lock().unwrap().policy.enabled && self.node_signer.supports_ffor_settler()
	}

	/// List durable offline reservation summaries without exposing preimages or transcripts.
	/// The result includes closed homes retained for replay protection. It is a point-in-time
	/// administrative view and must not be used to authorize a protocol transition.
	pub fn list_ffor_epochs(&self) -> Vec<FforEpochStatus> {
		let runtime = self.ffor_runtime.lock().unwrap();
		runtime.homes.iter().filter_map(|(channel_id, home)| {
			let epoch = &home.durable.as_ref()?.epoch;
			let phase = match epoch.phase {
				ffor::Phase::Negotiating => "NEGOTIATING",
				ffor::Phase::VouchersCommitted => "VOUCHERS_COMMITTED",
				ffor::Phase::Active => "ACTIVE",
				ffor::Phase::Draining => "DRAINING",
				ffor::Phase::Closed => "CLOSED",
				ffor::Phase::Aborted => "ABORTED",
			};
			Some(FforEpochStatus {
				channel_id: *channel_id, epoch_id: epoch.epoch_id, phase: phase.to_owned(),
				slot_count: epoch.slots.len() as u16,
				reserved_msat: epoch.slots.iter()
					.filter(|slot| slot.removal.is_none() && slot.chain_removal.is_none())
					.map(|slot| slot.entry.amount_msat).sum(),
				settling_count: epoch.slots.iter().filter(|slot| slot.state == SlotState::Settling).count() as u16,
				settled_count: epoch.slots.iter().filter(|slot| slot.state == SlotState::Settled).count() as u16,
				persistence_pending: !home.pending.is_empty(),
			})
		}).collect()
	}

	pub(super) fn ffor_transport_enabled(&self) -> bool {
		let runtime = self.ffor_runtime.lock().unwrap();
		self.node_signer.supports_ffor_settler() && (runtime.policy.enabled || !runtime.homes.is_empty())
	}

	/// Return receipts only from native durable custody for the exact authenticated
	/// peer, channel and epoch. A pending SETTLING transition is never a receipt.
	pub fn settled_ffor_receipts(&self, peer: &PublicKey, channel: &ChannelId, epoch: &[u8; 32])
		-> Result<Vec<FforReceipt>, APIError> {
		let runtime = self.ffor_runtime.lock().unwrap();
		let journal = runtime.homes.get(channel).and_then(|home| home.durable.as_ref()).ok_or_else(unavailable)?;
		if journal.epoch.remote_node != *peer || journal.epoch.epoch_id != *epoch { return Err(unavailable()); }
		Ok(journal.epoch.slots.iter().filter(|slot| slot.state == SlotState::Settled)
			.map(|slot| FforReceipt { slot: slot.entry.slot, preimage: slot.preimage }).collect())
	}

	/// Drain signed messages whose custody updates have completed. Callers must
	/// preserve this order when sending them to each authenticated counterparty.
	pub fn get_and_clear_pending_ffor_messages(&self) -> Vec<FforMessage> {
		let (messages, actions) = { let mut runtime = self.ffor_runtime.lock().unwrap();
			(mem::take(&mut runtime.messages), mem::take(&mut runtime.after_send)) };
		// PeerManager polls this queue on every processing pass. An empty poll
		// must not wake that same processor or mark an unchanged manager dirty.
		if messages.is_empty() && actions.is_empty() { return messages; }
		let _guard = PersistenceNotifierGuard::notify_on_drop(self);
		// PeerManager drains normal BOLT messages before this custom queue. These
		// actions can only create normal messages for the following event loop.
		for (token, action) in actions {
			match action {
				Action::OfferVouchers => { let _ = self.ffor_offer_vouchers(&token); },
				Action::ExitQuiescence => self.ffor_exit_quiescence(&token),
				Action::CancelSetupVouchers => self.ffor_cancel_setup(&token),
				_ => {},
			}
		}
		for message in &messages {
			if message.message_type == ffor::Kind::ActivateAck as u16 && message.payload.len() >= 32 {
				let channel = ChannelId(message.payload[..32].try_into().unwrap());
				if let Some(previous) = self.ffor_current(&channel) {
					if previous.epoch.activation_ack_pending {
						if let Ok(transition) = ffor::activation_ack_sent(&previous) { let _ = self.persist_ffor_transition(transition); }
					}
				}
			}
		}
		for message in &messages {
			if message.payload.len() >= 32 { self.ffor_refresh_replay_gate(ChannelId(message.payload[..32].try_into().unwrap())); }
		}
		messages
	}

	pub(super) fn ffor_monitor_update_persisted(&self, channel: ChannelId, update_id: u64) {
		if let Some(home) = self.ffor_runtime.lock().unwrap().homes.get_mut(&channel) {
			home.persisted_update_id = cmp::max(home.persisted_update_id, update_id);
		}
	}

	fn ffor_current(&self, channel: &ChannelId) -> Option<FforJournal> {
		self.ffor_runtime.lock().unwrap().homes.get(channel).map(|home| home.current.clone())
	}

	/// Stage custody under the native peer lock, then submit exactly its native
	/// monitor update. A blocked update leaves the completion token queued until
	/// the actual persisted update watermark covers it.
	fn persist_ffor_transition(&self, transition: PreparedTransition) -> Result<(), APIError> {
		let peer = transition.journal.epoch.remote_node;
		let channel = ChannelId(transition.journal.epoch.channel_id);
		let per_peer_state = self.per_peer_state.read().unwrap();
		let peer_mutex = per_peer_state.get(&peer).ok_or_else(unavailable)?;
		let mut peer_state_lock = peer_mutex.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		{
			let runtime = self.ffor_runtime.lock().unwrap();
			if let Some(home) = runtime.homes.get(&channel) {
				transition.journal.validate_transition(Some(&home.current)).map_err(|_| unavailable())?;
				if home.pending.len() >= 2 * ffor::MAX_SLOTS + 32 { return Err(unavailable()); }
			} else {
				if runtime.homes.len() >= MAX_FFOR_HOMES { return Err(unavailable()); }
				transition.journal.validate_transition(None).map_err(|_| unavailable())?;
			}
		}
		if let Some(chan) = peer_state.channel_by_id.get_mut(&channel).and_then(Channel::as_funded_mut) {
			let funding = chan.funding.get_funding_txo().ok_or_else(unavailable)?;
			let (update, token) = chan.persist_ffor_journal(transition.journal.clone(), &self.logger).map_err(|_| unavailable())?;
			self.ffor_stage(funding, token.clone(), transition);
			peer_state.monitor_update_blocked_actions.entry(channel).or_default()
				.push(MonitorUpdateCompletionAction::FforJournalPersisted { token });
			if let Some(update) = update {
				handle_new_monitor_update!(self, funding, update, peer_state_lock, peer_state, per_peer_state, chan);
			}
		} else {
			let funding = self.ffor_runtime.lock().unwrap().homes.get(&channel).map(|home| home.funding_txo).ok_or_else(unavailable)?;
			let next_id = peer_state.closed_channel_monitor_update_ids.get_mut(&channel).ok_or_else(unavailable)?;
			*next_id = next_id.checked_add(1).ok_or_else(unavailable)?;
			let token = FforPersistenceToken { channel_id: channel, epoch_id: transition.journal.epoch.epoch_id,
				revision: transition.journal.revision, update_id: *next_id };
			let update = ChannelMonitorUpdate { update_id: *next_id, channel_id: Some(channel),
				updates: vec![ChannelMonitorUpdateStep::FforJournal { journal: transition.journal.clone() }] };
			self.ffor_stage(funding, token.clone(), transition);
			peer_state.monitor_update_blocked_actions.entry(channel).or_default()
				.push(MonitorUpdateCompletionAction::FforJournalPersisted { token });
			handle_new_monitor_update!(self, funding, update, peer_state_lock, peer_state, per_peer_state, peer, channel, POST_CHANNEL_CLOSE);
		}
		Ok(())
	}

	fn ffor_stage(&self, funding_txo: OutPoint, token: FforPersistenceToken, transition: PreparedTransition) {
		let mut runtime = self.ffor_runtime.lock().unwrap();
		runtime.chain_released.retain(|(channel, epoch, _)| *channel != token.channel_id || *epoch == token.epoch_id);
		runtime.claims_inflight.retain(|(channel, epoch, _)| *channel != token.channel_id || *epoch == token.epoch_id);
		let home = runtime.homes.entry(token.channel_id).or_insert_with(|| Home {
			funding_txo, current: transition.journal.clone(), durable: None,
			persisted_update_id: token.update_id.saturating_sub(1), pending: BTreeMap::new(),
		});
		home.current = transition.journal.clone();
		home.pending.insert(token.revision, PendingTransition { token, journal: transition.journal, actions: transition.after_persistence });
	}

	pub(super) fn ffor_journal_persisted(&self, token: FforPersistenceToken) {
		let (peer, actions, retry) = {
			let mut runtime = self.ffor_runtime.lock().unwrap();
			let Some(home) = runtime.homes.get_mut(&token.channel_id) else { return; };
			let peer = home.current.epoch.remote_node;
			if home.persisted_update_id < token.update_id { (peer, Vec::new(), true) }
			else if let Some(pending) = home.pending.remove(&token.revision) {
				if pending.token != token { return; }
				if home.durable.as_ref().map_or(true, |old| old.revision < pending.journal.revision) {
					home.durable = Some(pending.journal);
				}
				(peer, pending.actions, false)
			} else { (peer, Vec::new(), false) }
		};
		if retry {
			let peers = self.per_peer_state.read().unwrap();
			if let Some(lock) = peers.get(&peer) {
				lock.lock().unwrap().monitor_update_blocked_actions.entry(token.channel_id).or_default()
					.push(MonitorUpdateCompletionAction::FforJournalPersisted { token });
			}
			return;
		}
		self.ffor_apply_actions(&token, actions);
		self.ffor_refresh_replay_gate(token.channel_id);
		self.ffor_release_chain_results();
	}

	fn ffor_apply_actions(&self, token: &FforPersistenceToken, actions: Vec<Action>) {
		for action in actions {
			match action {
				Action::ClaimUpstream { slot, upstream } => self.ffor_claim_upstream(token, slot, upstream),
				Action::Send(message) => {
					let mut runtime = self.ffor_runtime.lock().unwrap();
					let valid = runtime.homes.get(&token.channel_id).and_then(|home| home.durable.as_ref())
						.is_some_and(|journal| journal.epoch.epoch_id == token.epoch_id
							&& (journal.epoch.messages.contains(&message)
								|| journal.epoch.abort.as_ref().is_some_and(|abort| abort.local && abort.message == message))
							&& (!matches!(journal.epoch.phase, ffor::Phase::Aborted) || message.kind == ffor::Kind::Abort));
					if valid {
						let peer = runtime.homes[&token.channel_id].current.epoch.remote_node;
						let wire = message.encode();
						// At most five outbound kinds per admitted home. Replace the
						// same kind/epoch rather than accumulate duplicate requests.
						runtime.messages.retain(|queued| queued.peer != peer || queued.message_type != message.kind as u16
							|| queued.payload.get(..32) != Some(&message.channel_id[..]));
						runtime.messages.push(FforMessage { peer, message_type: message.kind as u16, payload: wire[2..].to_vec() });
						debug_assert!(runtime.messages.len() <= 5 * MAX_FFOR_HOMES);
					}
				},
				Action::OfferVouchers | Action::ExitQuiescence | Action::CancelSetupVouchers => {
					let mut runtime = self.ffor_runtime.lock().unwrap();
					// Reconnect can prepare the same deferred effect under a newer
					// revision before the custom transport drains. Retain one newest
					// token for each effect and home, keeping all required effect kinds.
					if runtime.after_send.iter().any(|(old, existing)| old.channel_id == token.channel_id
						&& existing == &action && old.revision >= token.revision) { continue; }
					runtime.after_send.retain(|(old, existing)| old.channel_id != token.channel_id || existing != &action);
					runtime.after_send.push((token.clone(), action));
					debug_assert!(runtime.after_send.len() <= 3 * MAX_FFOR_HOMES);
				},
			}
		}
	}

	fn ffor_claim_upstream(&self, token: &FforPersistenceToken, slot: u16, upstream: Upstream) {
		let preimage = {
			let mut runtime = self.ffor_runtime.lock().unwrap();
			let Some(home) = runtime.homes.get(&token.channel_id) else { return; };
			let Some(journal) = &home.durable else { return; };
			if home.persisted_update_id < token.update_id || !journal.proves_settling_token(token, slot, &upstream) { return; }
			let Some(item) = journal.epoch.slots.get(usize::from(slot).saturating_sub(1)) else { return; };
			// A staged SETTLED transition already has its upstream persistence proof.
			// Waiting for that home write must not create another upstream update.
			if home.current.epoch.slots.iter().any(|entry| entry.entry.slot == slot
				&& entry.state == SlotState::Settled) { return; }
			let preimage = PaymentPreimage(item.preimage);
			if !runtime.claims_inflight.insert((token.channel_id, token.epoch_id, slot)) { return; }
			preimage
		};
		// Never hold a home lock while touching the upstream channel. The ordinary
		// native claim routine also supports closed upstream monitors and restart.
		let source = HTLCClaimSource { counterparty_node_id: upstream.counterparty_node_id,
			funding_txo: upstream.funding_txo, channel_id: ChannelId(upstream.channel_id), htlc_id: upstream.htlc_id };
		let home_channel = token.channel_id;
		let epoch = token.epoch_id;
		self.claim_mpp_part(source, preimage, None, None, |_, _| {
			(Some(MonitorUpdateCompletionAction::FforUpstreamClaimed { home_channel, epoch, slot,
				upstream_peer: upstream.counterparty_node_id, upstream_funding: upstream.funding_txo,
				upstream_channel: ChannelId(upstream.channel_id), upstream_htlc_id: upstream.htlc_id }), None)
		});
	}

	pub(super) fn ffor_upstream_claimed(&self, home_channel: ChannelId, epoch: [u8; 32], slot: u16, upstream: Upstream) {
		self.ffor_runtime.lock().unwrap().claims_inflight.remove(&(home_channel, epoch, slot));
		let Some(previous) = self.ffor_current(&home_channel) else { return; };
		if previous.epoch.epoch_id != epoch { return; }
		if let Ok(transition) = ffor::settlement_completed(&previous, slot, &upstream) {
			let _ = self.persist_ffor_transition(transition);
		}
	}

	pub(super) fn replay_ffor_claims(&self) {
		let claims: Vec<_> = self.ffor_runtime.lock().unwrap().homes.iter().filter_map(|(channel, home)| {
			let journal = home.durable.as_ref()?;
			Some((FforPersistenceToken { channel_id: *channel, epoch_id: journal.epoch.epoch_id,
				revision: journal.revision, update_id: home.persisted_update_id }, ffor::replay_settling(journal)))
		}).collect();
		for (token, actions) in claims { self.ffor_apply_actions(&token, actions); }
	}

	pub(super) fn ffor_voucher_result(&self, channel: ChannelId, epoch: [u8; 32], slot: u16, preimage: Option<PaymentPreimage>) {
		let mut runtime = self.ffor_runtime.lock().unwrap();
		if !runtime.results.iter().any(|item| item.0 == channel && item.1 == epoch && item.2 == slot && item.3 == preimage) {
			runtime.results.push((channel, epoch, slot, preimage));
		}
	}
	pub(super) fn ffor_voucher_finalized(&self, channel: ChannelId, epoch: [u8; 32], slot: u16) {
		let preimage = {
			let runtime = self.ffor_runtime.lock().unwrap();
			let Some(home) = runtime.homes.get(&channel) else { return; };
			if home.current.epoch.epoch_id != epoch { return; }
			let Some(entry) = home.current.epoch.slots.iter().find(|entry| entry.entry.slot == slot) else { return; };
			PaymentPreimage(entry.preimage)
		};
		self.ffor_voucher_result(channel, epoch, slot, Some(preimage));
	}
	pub(super) fn ffor_chain_result(&self, channel: ChannelId, epoch: [u8; 32], slot: u16,
		peer: PublicKey, funding_txo: OutPoint, evidence: ffor::ChainRemoval) {
		let mut runtime = self.ffor_runtime.lock().unwrap();
		let Some(home) = runtime.homes.get(&channel) else { return; };
		if home.current.epoch.epoch_id != epoch || home.current.epoch.remote_node != peer
			|| !home.current.epoch.slots.iter().any(|entry| entry.entry.slot == slot) { return; }
		let key = (channel, epoch, slot);
		if runtime.chain_released.contains(&key) { return; }
		if runtime.chain_results.get(&key).is_some_and(|(old, _)| old != &evidence) { return; }
		let release = PaymentCompleteUpdate { counterparty_node_id: peer, channel_funding_outpoint: funding_txo,
			channel_id: channel, htlc_id: SentHTLCId::FforVoucher { channel_id: channel, epoch_id: epoch, slot } };
		runtime.chain_results.insert(key, (evidence, release));
		debug_assert!(runtime.chain_results.len() <= MAX_FFOR_HOMES * ffor::MAX_SLOTS);
	}

	fn ffor_record_chain_results(&self) {
		let results: Vec<_> = self.ffor_runtime.lock().unwrap().chain_results.iter()
			.map(|(key, (proof, _))| (*key, proof.clone())).collect();
		for ((channel, epoch, slot), proof) in results {
			let previous = {
				let runtime = self.ffor_runtime.lock().unwrap();
				let Some(home) = runtime.homes.get(&channel) else { continue; };
				if home.current.epoch.epoch_id != epoch
					|| !home.durable.as_ref().is_some_and(|durable| durable.revision == home.current.revision) { continue; }
				home.current.clone()
			};
			if previous.epoch.slots.iter().any(|entry| entry.entry.slot == slot && entry.chain_removal.as_ref() == Some(&proof)) { continue; }
			if let Ok(transition) = ffor::prepare_chain_resolution(&previous, slot, proof) {
				let _ = self.persist_ffor_transition(transition);
			}
		}
		self.ffor_release_chain_results();
	}

	fn ffor_release_chain_results(&self) {
		let releases = {
			let mut runtime = self.ffor_runtime.lock().unwrap();
			let ready: Vec<_> = runtime.chain_results.iter().filter_map(|(key, (proof, _))| {
				let journal = runtime.homes.get(&key.0)?.durable.as_ref()?;
				(journal.epoch.epoch_id == key.1 && journal.epoch.slots.iter().any(|entry|
					entry.entry.slot == key.2 && entry.chain_removal.as_ref() == Some(proof))).then_some(*key)
			}).collect();
			ready.into_iter().filter_map(|key| {
				let (_, release) = runtime.chain_results.remove(&key)?;
				runtime.chain_released.insert(key);
				Some(release)
			}).collect::<Vec<_>>()
		};
		// The native monitor repeats these proofs until its payment-complete
		// update is saved, covering a crash between these two durable writes.
		for release in releases {
			self.handle_post_event_actions([EventCompletionAction::ReleasePaymentCompleteChannelMonitorUpdate(release)]);
		}
	}

	/// Whether the current authenticated connection negotiated the complete
	/// concurrent settler profile. Historical feature bytes are never sufficient.
	pub fn supports_ffor_settler(&self, peer: &PublicKey) -> bool {
		if !self.ffor_settler_enabled() { return false; }
		self.ffor_peer_negotiated(peer)
	}

	fn ffor_peer_negotiated(&self, peer: &PublicKey) -> bool {
		if !self.ffor_transport_enabled() { return false; }
		let peers = self.per_peer_state.read().unwrap();
		peers.get(peer).is_some_and(|lock| {
			let state = lock.lock().unwrap();
			let flags = state.latest_features.le_flags();
			let has_pair = |odd: usize| flags.get(odd / 8).is_some_and(|byte| byte & (3 << (odd - 1) % 8) != 0);
			state.is_connected && has_pair(561) && has_pair(563)
		})
	}

	/// Admit an authenticated signed custom frame. Setup and activation may wait
	/// for native quiescence; successful return does not imply an emitted reply.
	/// The native monitor remains the authority for every secret-bearing effect.
	pub fn handle_ffor_message(&self, peer: &PublicKey, message_type: u16, payload: &[u8]) -> Result<(), APIError> {
		let _guard = PersistenceNotifierGuard::notify_on_drop(self);
		if payload.len() > ffor::MAX_BODY { return Err(unavailable()); }
		let mut wire = message_type.to_be_bytes().to_vec();
		wire.extend_from_slice(payload);
		let message = ffor::SignedMessage::decode(&wire).map_err(|_| unavailable())?;
		message.verify(&self.secp_ctx, peer).map_err(|_| unavailable())?;
		let channel = ChannelId(message.channel_id);
		if message.kind == ffor::Kind::Init && !self.supports_ffor_settler(peer) { return Err(unavailable()); }
		{
			let peers = self.per_peer_state.read().unwrap();
			let state = peers.get(peer).ok_or_else(unavailable)?.lock().unwrap();
			if !state.is_connected { return Err(unavailable()); }
			let runtime = self.ffor_runtime.lock().unwrap();
			if let Some(home) = runtime.homes.get(&channel) {
				if home.current.epoch.remote_node != *peer { return Err(unavailable()); }
			} else if message.kind != ffor::Kind::Init || !state.channel_by_id.get(&channel).and_then(Channel::as_funded)
				.is_some_and(|chan| !chan.context.should_announce()) { return Err(unavailable()); }
		}
		{
			let mut runtime = self.ffor_runtime.lock().unwrap();
			if !runtime.homes.contains_key(&channel) && runtime.homes.len() + runtime.requests.len() >= MAX_FFOR_HOMES {
				return Err(unavailable());
			}
			if let Some((_, old)) = runtime.requests.get(&channel) {
				return if old == &message { Ok(()) } else { Err(unavailable()) };
			}
			if message.kind == ffor::Kind::Sync {
				let now = runtime.now();
				let rate = runtime.sync_rate.entry(channel).or_insert((now, 0));
				if rate.0 != now { *rate = (now, 0); }
				if rate.1 >= 8 { return Err(unavailable()); }
				rate.1 += 1;
			}
			if !matches!(message.kind, ffor::Kind::Init | ffor::Kind::Activate | ffor::Kind::Sync | ffor::Kind::Close | ffor::Kind::Abort) {
				return Err(unavailable());
			}
			let now = runtime.now();
			runtime.started.entry(channel).or_insert(now);
			runtime.requests.insert(channel, (*peer, message));
		}
		self.ffor_progress();
		Ok(())
	}

	/// Runs without a peer lock. Requests remain queued only while waiting for
	/// native quiescence or a preceding custody update to become durable.
	pub(super) fn ffor_progress(&self) {
		let requests = {
			let mut runtime = self.ffor_runtime.lock().unwrap();
			if runtime.progress_running { return; }
			runtime.progress_running = true;
			mem::take(&mut runtime.requests)
		};
		for (channel, (peer, message)) in requests {
			match self.ffor_process_message(peer, &message) {
				Ok(true) => {},
				Ok(false) => { self.ffor_runtime.lock().unwrap().requests.entry(channel).or_insert((peer, message)); },
				Err(_) => {
					if let Some(old) = self.ffor_current(&channel) {
						if matches!(old.epoch.phase, ffor::Phase::Negotiating | ffor::Phase::VouchersCommitted) {
							if let Ok(abort) = ffor::prepare_abort(&old, 7, &*self.node_signer) { let _ = self.persist_ffor_transition(abort); }
						}
					} else {
						self.ffor_runtime.lock().unwrap().started.remove(&channel);
					}
				},
			}
		}
		let results = mem::take(&mut self.ffor_runtime.lock().unwrap().results);
		for (channel, epoch, slot, preimage) in results {
			let Some(previous) = self.ffor_current(&channel) else { continue; };
			if previous.epoch.epoch_id != epoch { continue; }
			if let Some(preimage) = preimage {
				if previous.epoch.slots.iter().any(|entry| entry.entry.slot == slot
					&& entry.redeemed && entry.preimage == preimage.0) { continue; }
				if let Ok(transition) = ffor::prepare_voucher_result(&previous, slot, Some(preimage.0), None) {
					if self.persist_ffor_transition(transition).is_err() { self.ffor_voucher_result(channel, epoch, slot, Some(preimage)); }
				}
			}
		}
		self.ffor_record_removals();
		self.ffor_record_chain_results();
		let expired: Vec<_> = {
			let runtime = self.ffor_runtime.lock().unwrap();
			let now = runtime.now();
			runtime.started.iter().filter(|(_, start)| now.saturating_sub(**start) >= 60).map(|(channel, _)| *channel).collect()
		};
		for channel in expired {
			let mut keep = false;
			if let Some(previous) = self.ffor_current(&channel) {
				if matches!(previous.epoch.phase, ffor::Phase::Negotiating | ffor::Phase::VouchersCommitted) {
					keep = ffor::prepare_abort(&previous, 7, &*self.node_signer).ok()
						.map_or(true, |transition| self.persist_ffor_transition(transition).is_err());
				}
			}
			if !keep {
				let pending_peer = {
					let mut runtime = self.ffor_runtime.lock().unwrap();
					runtime.started.remove(&channel);
					let request = runtime.requests.remove(&channel);
					if !runtime.homes.contains_key(&channel) { request.map(|(peer, _)| peer) } else { None }
				};
				// A timed-out initial STFU cannot be undone locally. Disconnect so
				// native reconnect recovery resets both participants coherently.
				if let Some(peer) = pending_peer {
					if let Some(lock) = self.per_peer_state.read().unwrap().get(&peer) {
						lock.lock().unwrap().pending_msg_events.push(MessageSendEvent::HandleError {
							node_id: peer, action: msgs::ErrorAction::DisconnectPeer { msg: None },
						});
					}
				}
			}
		}
		self.ffor_runtime.lock().unwrap().progress_running = false;
	}

	// Native two-view evidence is the only authority for retiring a voucher.
	// Processing one removal per home avoids constructing concurrent revisions.
	fn ffor_record_removals(&self) {
		let homes: Vec<_> = self.ffor_runtime.lock().unwrap().homes.values()
			.filter(|home| home.durable.as_ref().is_some_and(|durable| durable.revision == home.current.revision))
			.map(|home| home.current.clone()).collect();
		for previous in homes {
			let evidence = {
				let peers = self.per_peer_state.read().unwrap();
				let Some(lock) = peers.get(&previous.epoch.remote_node) else { continue; };
				let state = lock.lock().unwrap();
				let Some(chan) = state.channel_by_id.get(&ChannelId(previous.epoch.channel_id)).and_then(Channel::as_funded) else { continue; };
				previous.epoch.slots.iter().filter(|slot| slot.removal.is_none()).find_map(|slot| {
					chan.ffor_voucher_removal(slot.entry.slot, slot.redeemed, &self.logger)
						.map(|proof| (slot.entry.slot, proof))
				})
			};
			if let Some((slot, proof)) = evidence {
				if let Ok(transition) = ffor::prepare_voucher_result(&previous, slot, None, Some(proof)) {
					let _ = self.persist_ffor_transition(transition);
				}
			}
		}
	}

	fn ffor_process_message(&self, peer: PublicKey, message: &ffor::SignedMessage) -> Result<bool, APIError> {
		let channel = ChannelId(message.channel_id);
		let (previous, durable, policy) = {
			let runtime = self.ffor_runtime.lock().unwrap();
			(runtime.homes.get(&channel).map(|home| home.current.clone()),
			 runtime.homes.get(&channel).and_then(|home| home.durable.clone()), runtime.policy.clone())
		};
		if let Some(durable) = &durable {
			if let Ok(action) = ffor::replay_response(durable, message) {
				let update_id = self.ffor_runtime.lock().unwrap().homes[&channel].persisted_update_id;
				self.ffor_apply_actions(&FforPersistenceToken { channel_id: channel, epoch_id: durable.epoch.epoch_id,
					revision: durable.revision, update_id }, vec![action]);
				return Ok(true);
			}
		}
		if previous.as_ref().map(|j| j.revision) != durable.as_ref().map(|j| j.revision) { return Ok(false); }
		let transition = match message.kind {
			ffor::Kind::Init | ffor::Kind::Activate => {
				let negotiated = self.ffor_peer_negotiated(&peer);
				let peers = self.per_peer_state.read().unwrap();
				let mut state = peers.get(&peer).ok_or_else(unavailable)?.lock().unwrap();
				let chan = state.channel_by_id.get_mut(&channel).and_then(Channel::as_funded_mut).ok_or_else(unavailable)?;
				if message.kind == ffor::Kind::Activate && !chan.is_ffor_quiescent() {
					if let Some(msg) = chan.request_ffor_quiescence(&self.logger).map_err(|_| unavailable())? {
						state.pending_msg_events.push(MessageSendEvent::SendStfu { node_id: peer, msg });
					}
					return Ok(false);
				}
				if message.kind == ffor::Kind::Init {
					if !policy.enabled || !negotiated { return Err(unavailable()); }
					let terms = message.settler_terms().map_err(|_| unavailable())?;
					let context = chan.ffor_setup_context(self.best_block.read().unwrap().height, negotiated, terms.amounts_msat.len(), &self.fee_estimator);
					let policy = ffor::Policy { max_slots: policy.max_slots, max_budget_msat: policy.max_budget_msat,
						max_epoch_blocks: policy.max_epoch_blocks, min_fee_base_msat: policy.fee_base_msat, min_fee_ppm: policy.fee_ppm };
					ffor::prepare_setup(previous.as_ref(), message.clone(), &context, &policy, &*self.node_signer, &*self.entropy_source).map_err(|_| unavailable())?
				} else {
					let previous = previous.as_ref().ok_or_else(unavailable)?;
					let snapshot = chan.ffor_commitment_snapshot(&previous.epoch, &self.logger).map_err(|_| unavailable())?;
					if previous.epoch.phase == ffor::Phase::Negotiating {
						let transition = ffor::vouchers_committed(previous, snapshot).map_err(|_| unavailable())?;
						drop(state); drop(peers);
						self.persist_ffor_transition(transition)?;
						return Ok(false);
					}
					ffor::prepare_activate(previous, message.clone(), &snapshot, self.best_block.read().unwrap().height, &*self.node_signer).map_err(|_| unavailable())?
				}
			},
			ffor::Kind::Sync => ffor::prepare_sync(previous.as_ref().ok_or_else(unavailable)?, message, &*self.node_signer).map_err(|_| unavailable())?,
			ffor::Kind::Close => ffor::prepare_close(previous.as_ref().ok_or_else(unavailable)?, message.clone(), &*self.node_signer).map_err(|_| unavailable())?,
			ffor::Kind::Abort => ffor::prepare_peer_abort(previous.as_ref().ok_or_else(unavailable)?, message.clone()).map_err(|_| unavailable())?,
			_ => return Err(unavailable()),
		};
		self.persist_ffor_transition(transition)?;
		Ok(true)
	}

	fn ffor_offer_vouchers(&self, token: &FforPersistenceToken) -> Result<(), APIError> {
		let previous = self.ffor_current(&token.channel_id).ok_or_else(unavailable)?;
		if previous.epoch.epoch_id != token.epoch_id || previous.epoch.phase != ffor::Phase::Negotiating
			|| previous.epoch.slots.iter().any(|slot| slot.chain_removal.is_some()) { return Err(unavailable()); }
		let peer = previous.epoch.remote_node;
		let mut onions = Vec::with_capacity(previous.epoch.slots.len());
		for slot in &previous.epoch.slots {
			let path = Path { hops: vec![crate::routing::router::RouteHop {
				pubkey: peer, node_features: NodeFeatures::empty(), short_channel_id: 0,
				channel_features: ChannelFeatures::empty(), fee_msat: slot.entry.amount_msat,
				cltv_expiry_delta: slot.entry.expiry, maybe_announced_channel: false,
			}], blinded_tail: None };
			let fields = RecipientOnionFields::secret_only(PaymentSecret(ffor::voucher_secret(&previous.epoch.epoch_id, slot.entry.slot).map_err(|_| unavailable())?));
			let (payloads, amount, expiry) = onion_utils::build_onion_payloads(&path, slot.entry.amount_msat, &fields, 0, &None, None, None)?;
			if amount != slot.entry.amount_msat || expiry != slot.entry.expiry { return Err(unavailable()); }
			let secret = loop { if let Ok(secret) = SecretKey::from_slice(&self.entropy_source.get_secure_random_bytes()) { break secret; } };
			let keys = onion_utils::construct_onion_keys(&self.secp_ctx, &path, &secret);
			onions.push(onion_utils::construct_onion_packet(payloads, keys, self.entropy_source.get_secure_random_bytes(), &PaymentHash(slot.entry.payment_hash)).map_err(|_| unavailable())?);
		}
		let peers = self.per_peer_state.read().unwrap();
		let mut state = peers.get(&peer).ok_or_else(unavailable)?.lock().unwrap();
		let chan = state.channel_by_id.get_mut(&token.channel_id).and_then(Channel::as_funded_mut).ok_or_else(unavailable)?;
		chan.queue_ffor_vouchers(onions, &self.fee_estimator, &self.logger).map_err(|_| unavailable())?;
		Ok(())
	}

	fn ffor_exit_quiescence(&self, token: &FforPersistenceToken) {
		let Some(previous) = self.ffor_current(&token.channel_id) else { return; };
		if previous.epoch.epoch_id != token.epoch_id { return; }
		let peers = self.per_peer_state.read().unwrap();
		if let Some(lock) = peers.get(&previous.epoch.remote_node) {
			if let Some(chan) = lock.lock().unwrap().channel_by_id.get_mut(&token.channel_id).and_then(Channel::as_funded_mut) { chan.exit_quiescence(); }
		}
	}

	pub(super) fn ffor_known_hash(&self, hash: &PaymentHash) -> bool {
		self.ffor_runtime.lock().unwrap().homes.values().any(|home| home.current.contains_payment_hash(&hash.0))
	}

	/// Classify retained voucher hashes before ordinary forwarding, including when
	/// the receiver is disconnected. Only native committed upstream adds reach it.
	pub(super) fn process_ffor_forward(&self, scid: u64, payment: &PendingAddHTLCInfo) -> Option<Result<(), APIError>> {
		let previous = {
			let runtime = self.ffor_runtime.lock().unwrap();
			runtime.homes.values().find(|home| home.current.contains_payment_hash(&payment.forward_info.payment_hash.0)).map(|home| home.current.clone())
		}?;
		Some((|| {
			let channel = ChannelId(previous.epoch.channel_id);
			let slot = ffor::identify_slot(&previous, &payment.forward_info.payment_hash.0).ok_or_else(unavailable)?;
			let upstream = Upstream { counterparty_node_id: payment.prev_counterparty_node_id, funding_txo: payment.prev_funding_outpoint,
				channel_id: payment.prev_channel_id.0, htlc_id: payment.prev_htlc_id };
			if let Ok(action) = ffor::replay_claim(&previous, slot, &upstream) {
				let token = {
					let runtime = self.ffor_runtime.lock().unwrap();
					let home = &runtime.homes[&channel];
					let durable = home.durable.as_ref().ok_or_else(unavailable)?;
					FforPersistenceToken { channel_id: channel, epoch_id: durable.epoch.epoch_id, revision: durable.revision, update_id: home.persisted_update_id }
				};
				self.ffor_apply_actions(&token, vec![action]);
				return Ok(());
			}
			let target = self.short_to_chan_info.read().unwrap().get(&scid).cloned();
			if target != Some((previous.epoch.remote_node, channel)) { return Err(unavailable()); }
			let delta = {
				let peers = self.per_peer_state.read().unwrap();
				let state = peers.get(&previous.epoch.remote_node).ok_or_else(unavailable)?.lock().unwrap();
				state.channel_by_id.get(&channel).and_then(Channel::as_funded).ok_or_else(unavailable)?.context.get_cltv_expiry_delta() as u32
			};
			let incoming_cltv = payment.forward_info.routing.incoming_cltv_expiry().ok_or_else(unavailable)?;
			check_incoming_htlc_cltv(self.best_block.read().unwrap().height.saturating_add(1), payment.forward_info.outgoing_cltv_value, incoming_cltv).map_err(|_| unavailable())?;
			let blinded = matches!(payment.forward_info.routing, PendingHTLCRouting::Forward { blinded: Some(_), .. });
			let context = ffor::DelegationContext { upstream, payment_hash: payment.forward_info.payment_hash.0,
				irrevocably_committed: true, current_height: self.best_block.read().unwrap().height,
				incoming_cltv, forwarding_delta: delta, incoming_msat: payment.forward_info.incoming_amt_msat.ok_or_else(unavailable)?,
				forward: if blinded { ffor::ForwardAmount::Blinded } else { ffor::ForwardAmount::Plaintext(payment.forward_info.outgoing_amt_msat) },
				verified_advertised_fee: None };
			let transition = ffor::prepare_settlement(&previous, slot, &context).map_err(|_| unavailable())?;
			self.persist_ffor_transition(transition)
		})())
	}

	pub(super) fn ffor_disconnected(&self, peer: PublicKey) {
		let homes: Vec<_> = {
			let mut runtime = self.ffor_runtime.lock().unwrap();
			runtime.requests.retain(|_, (target, _)| *target != peer);
			runtime.messages.retain(|message| message.peer != peer);
			let channels: Vec<_> = runtime.homes.iter().filter(|(_, home)| home.current.epoch.remote_node == peer).map(|(channel, _)| *channel).collect();
			for channel in channels { runtime.replay_gates.remove(&channel); }
			runtime.homes.values().filter(|home| home.current.epoch.remote_node == peer).map(|home| home.current.clone()).collect()
		};
		for previous in homes {
			if let Ok(Some(transition)) = ffor::prepare_disconnect(&previous, &*self.node_signer) { let _ = self.persist_ffor_transition(transition); }
		}
	}

	pub(super) fn ffor_peer_connected(&self, peer: PublicKey) {
		let mut runtime = self.ffor_runtime.lock().unwrap();
		let channels: Vec<_> = runtime.homes.iter().filter(|(_, home)| home.current.epoch.remote_node == peer).map(|(id, _)| *id).collect();
		for channel in channels { runtime.replay_gates.insert(channel, ReplayGate { validated: false, required: None, ready: false, messages: Vec::new() }); }
	}

	/// Called only after the ordinary BOLT counter checks succeeded. Normal
	/// channel replay is held by the connection gate until this journal and any
	/// owed custom ACK have crossed their own native persistence/send barriers.
	pub(super) fn ffor_reestablished(&self, peer: PublicKey, message: &msgs::ChannelReestablish) {
		let Some(previous) = self.ffor_current(&message.channel_id) else { return; };
		if previous.epoch.remote_node != peer { return; }
		let metadata = message.ffor_epoch.as_ref().and_then(|bytes| ffor::Reestablish::decode(bytes).ok());
		let negotiated = self.ffor_peer_negotiated(&peer);
		if let Ok(transition) = ffor::prepare_reestablish(&previous, metadata.as_ref(), negotiated, &*self.node_signer) {
			let required = (transition.journal.epoch.epoch_id, transition.journal.revision);
			if self.persist_ffor_transition(transition).is_ok() {
				let mut runtime = self.ffor_runtime.lock().unwrap();
				let gate = runtime.replay_gates.entry(message.channel_id)
					.or_insert(ReplayGate { validated: false, required: None, ready: false, messages: Vec::new() });
				gate.required = Some(required);
				gate.validated = true;
				drop(runtime);
				self.ffor_refresh_replay_gate(message.channel_id);
			}
		}
	}

	fn ffor_refresh_replay_gate(&self, channel: ChannelId) {
		let mut runtime = self.ffor_runtime.lock().unwrap();
		let required = runtime.replay_gates.get(&channel).and_then(|gate| gate.required);
		let ready = runtime.homes.get(&channel).is_some_and(|home| home.durable.as_ref().is_some_and(|journal| {
			required.is_some_and(|(epoch, revision)| epoch == journal.epoch.epoch_id && journal.revision >= revision)
				&& journal.revision == home.current.revision && !journal.epoch.capability_hold
				&& !journal.epoch.activation_mismatch && !journal.epoch.activation_ack_pending
		})) && !runtime.messages.iter().any(|message| message.payload.get(..32) == Some(&channel.0[..])
			&& matches!(message.message_type, 55047 | 55049 | 55053));
		if let Some(gate) = runtime.replay_gates.get_mut(&channel) { gate.ready = gate.validated && ready; }
	}

	pub(super) fn ffor_filter_replay_events(&self, events: &mut Vec<MessageSendEvent>) {
		let mut runtime = self.ffor_runtime.lock().unwrap();
		if runtime.replay_gates.is_empty() { return; }
		let mut released = Vec::new();
		for gate in runtime.replay_gates.values_mut().filter(|gate| gate.ready) { released.append(&mut gate.messages); }
		let mut current = mem::take(events);
		let mut overflowed = BTreeSet::new();
		for event in current.drain(..) {
			let channel = match &event {
				MessageSendEvent::UpdateHTLCs { updates, .. } => updates.commitment_signed.first().map(|msg| msg.channel_id),
				MessageSendEvent::SendRevokeAndACK { msg, .. } => Some(msg.channel_id),
				MessageSendEvent::SendShutdown { msg, .. } => Some(msg.channel_id),
				MessageSendEvent::SendClosingSigned { msg, .. } => Some(msg.channel_id),
				MessageSendEvent::SendStfu { msg, .. } => Some(msg.channel_id),
				_ => None,
			};
			if channel.is_some_and(|id| overflowed.contains(&id)) { continue; }
			if let Some(gate) = channel.and_then(|id| runtime.replay_gates.get_mut(&id)).filter(|gate| !gate.ready) {
				if gate.messages.len() >= 32 {
					// Stop this connection before releasing an unvalidated stream.
					// Native channel state replays its commitments on reconnect.
					gate.messages.clear();
					gate.validated = false;
					overflowed.insert(channel.unwrap());
				} else { gate.messages.push(event); }
			} else { released.push(event); }
		}
		for channel in overflowed {
			if let Some(home) = runtime.homes.get(&channel) {
				released.push(MessageSendEvent::HandleError { node_id: home.current.epoch.remote_node,
					action: msgs::ErrorAction::DisconnectPeer { msg: None } });
			}
		}
		*events = released;
	}

	fn ffor_cancel_setup(&self, token: &FforPersistenceToken) {
		let Some(previous) = self.ffor_current(&token.channel_id) else { return; };
		if previous.epoch.epoch_id != token.epoch_id { return; }
		let peers = self.per_peer_state.read().unwrap();
		if let Some(lock) = peers.get(&previous.epoch.remote_node) {
			if let Some(chan) = lock.lock().unwrap().channel_by_id.get_mut(&token.channel_id).and_then(Channel::as_funded_mut) {
				let _ = chan.cancel_ffor_setup_vouchers();
			}
		}
	}

}

#[cfg(test)]
#[path = "ffor_manager_tests.rs"]
pub(crate) mod tests;
