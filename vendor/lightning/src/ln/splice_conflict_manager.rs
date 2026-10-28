//! Authenticated, bounded splice-conflict recovery with native persistence gates.

use super::*;
use crate::ln::splice_conflict::{SpliceConflictRecord, MAX_RETIRED_SPLICES};

#[cfg(test)]
#[path = "splice_conflict_manager_tests.rs"]
mod tests;

const MAX_CONFLICT_CHANNELS: usize = 128;
const MAX_CONFLICT_RESPONSES: usize = MAX_CONFLICT_CHANNELS * MAX_RETIRED_SPLICES;

/// A native splice candidate admitted for independent chain verification.
#[derive(Clone, Debug)]
pub struct SpliceConflictCandidate {
	/// The authenticated channel.
	pub channel_id: ChannelId,
	/// The channel counterparty that initiated quiescence.
	pub counterparty_node_id: PublicKey,
	/// Exact candidate whose external input may have been spent elsewhere.
	pub transaction: Transaction,
	/// The current shared funding input, which is never eligible for rollback.
	pub shared_funding_outpoint: bitcoin::OutPoint,
	/// The exact native tip against which proof must be independently verified.
	pub best_block: BestBlock,
}

/// A conflict response ready to enqueue on the authenticated peer transport.
#[derive(Clone, Debug)]
pub struct SpliceConflictResponse {
	/// The only peer that may receive this response.
	pub counterparty_node_id: PublicKey,
	/// The affected channel.
	pub channel_id: ChannelId,
	/// Exact retired or refused candidate.
	pub splice_txid: Txid,
	/// True only after native monitor persistence completed the retirement.
	pub agreed: bool,
	/// Bounded human-readable refusal reason, empty on agreement.
	pub reason: String,
}

struct ConflictHome {
	records: Vec<SpliceConflictRecord>,
	persisted_update_id: u64,
}
struct QueuedResponse {
	response: SpliceConflictResponse,
	generation: u64,
}
pub(super) struct SpliceConflictRuntime {
	homes: BTreeMap<ChannelId, ConflictHome>,
	responses: BTreeMap<(ChannelId, Txid), QueuedResponse>,
	pending: BTreeMap<(ChannelId, Txid), u64>,
}
impl SpliceConflictRuntime {
	pub(super) fn new() -> Self {
		Self { homes: BTreeMap::new(), responses: BTreeMap::new(), pending: BTreeMap::new() }
	}
	pub(super) fn restore(
		&mut self, channel: ChannelId, peer: PublicKey, records: Vec<SpliceConflictRecord>,
		update_id: u64,
	) -> Result<(), DecodeError> {
		if records.is_empty() {
			return Ok(());
		}
		if self.homes.len() >= MAX_CONFLICT_CHANNELS
			|| self.homes.contains_key(&channel)
			|| records.len() > MAX_RETIRED_SPLICES
			|| records.iter().any(|record| {
				record.channel_id != channel
					|| record.counterparty_node_id != peer
					|| record.update_id > update_id
			}) {
			return Err(DecodeError::InvalidValue);
		}
		let mut ids = new_hash_set();
		if records.iter().any(|record| !ids.insert(record.splice_txid)) {
			return Err(DecodeError::InvalidValue);
		}
		self.homes.insert(channel, ConflictHome { records, persisted_update_id: update_id });
		Ok(())
	}
}

fn conflict_unavailable() -> APIError {
	APIError::APIMisuseError {
		err: "Splice conflict recovery is not admissible in the current native state".to_owned(),
	}
}

impl<
		M: Deref,
		T: Deref,
		ES: Deref,
		NS: Deref,
		SP: Deref,
		F: Deref,
		R: Deref,
		MR: Deref,
		L: Deref,
	> ChannelManager<M, T, ES, NS, SP, F, R, MR, L>
where
	M::Target: chain::Watch<<SP::Target as SignerProvider>::EcdsaSigner>,
	T::Target: BroadcasterInterface,
	ES::Target: EntropySource,
	NS::Target: NodeSigner,
	SP::Target: SignerProvider,
	F::Target: FeeEstimator,
	R::Target: Router,
	MR::Target: MessageRouter,
	L::Target: Logger,
{
	/// Inspect a candidate only after authenticating its peer and native quiescence.
	/// This does not authorize retirement or mutate funding state.
	pub fn splice_conflict_candidate(
		&self, channel_id: &ChannelId, peer: &PublicKey, splice_txid: Txid,
	) -> Result<SpliceConflictCandidate, APIError> {
		let best_block = *self.best_block.read().unwrap();
		let peers = self.per_peer_state.read().unwrap();
		let state = peers.get(peer).ok_or_else(conflict_unavailable)?.lock().unwrap();
		if !state.is_connected {
			return Err(conflict_unavailable());
		}
		let chan = state
			.channel_by_id
			.get(channel_id)
			.and_then(Channel::as_funded)
			.ok_or_else(conflict_unavailable)?;
		let transaction =
			chan.splice_conflict_candidate(splice_txid).map_err(|_| conflict_unavailable())?;
		let funding = chan.funding.get_funding_txo().ok_or_else(conflict_unavailable)?;
		Ok(SpliceConflictCandidate {
			channel_id: *channel_id,
			counterparty_node_id: *peer,
			transaction,
			shared_funding_outpoint: funding.into_bitcoin_outpoint(),
			best_block,
		})
	}

	/// Retire an unconfirmed candidate only using independently verified chain evidence.
	/// The caller must obtain the transaction and active-chain confirmation from its
	/// trusted chain source and serialize this call with its chain notifications to
	/// ChannelManager and ChainMonitor. Peer assertions are not chain evidence.
	pub fn revert_conflicted_splice(
		&self, channel_id: &ChannelId, peer: &PublicKey, splice_txid: Txid,
		conflict_transaction: Transaction, input_index: u16, confirmation_height: u32,
		confirmation_hash: BlockHash, verified_tip: BestBlock,
	) -> Result<(), APIError> {
		let _guard = PersistenceNotifierGuard::notify_on_drop(self);
		if verified_tip != *self.best_block.read().unwrap()
			|| confirmation_height == 0
			|| verified_tip.height.checked_sub(confirmation_height).map_or(true, |depth| depth < 5)
			|| conflict_transaction.compute_txid() == splice_txid
		{
			return Err(conflict_unavailable());
		}
		let per_peer_state = self.per_peer_state.read().unwrap();
		let mut peer_state_lock =
			per_peer_state.get(peer).ok_or_else(conflict_unavailable)?.lock().unwrap();
		let peer_state = &mut *peer_state_lock;
		if !peer_state.is_connected {
			return Err(conflict_unavailable());
		}
		let chan = peer_state
			.channel_by_id
			.get_mut(channel_id)
			.and_then(Channel::as_funded_mut)
			.ok_or_else(conflict_unavailable)?;
		if verified_tip != *self.best_block.read().unwrap() {
			return Err(conflict_unavailable());
		}
		let candidate =
			chan.splice_conflict_candidate(splice_txid).map_err(|_| conflict_unavailable())?;
		let funding_txo = chan.funding.get_funding_txo().ok_or_else(conflict_unavailable)?;
		let input = candidate
			.input
			.get(usize::from(input_index))
			.ok_or_else(conflict_unavailable)?
			.previous_output;
		if input == funding_txo.into_bitcoin_outpoint()
			|| input.is_null()
			|| !conflict_transaction.input.iter().any(|entry| entry.previous_output == input)
			|| conflict_transaction
				.input
				.iter()
				.any(|entry| entry.previous_output == funding_txo.into_bitcoin_outpoint())
		{
			return Err(conflict_unavailable());
		}
		let key = (*channel_id, splice_txid);
		{
			let mut runtime = self.splice_conflict_runtime.lock().unwrap();
			if runtime.pending.contains_key(&key) {
				return Ok(());
			}
			if runtime.responses.len() + runtime.pending.len() >= MAX_CONFLICT_RESPONSES
				|| !runtime.homes.contains_key(channel_id)
					&& runtime.homes.len() >= MAX_CONFLICT_CHANNELS
			{
				return Err(conflict_unavailable());
			}
			let home = runtime
				.homes
				.entry(*channel_id)
				.or_insert_with(|| ConflictHome { records: Vec::new(), persisted_update_id: 0 });
			if home.records.len() >= MAX_RETIRED_SPLICES
				|| home.records.iter().any(|record| record.splice_txid == splice_txid)
			{
				return Err(conflict_unavailable());
			}
			runtime.pending.insert(key, 0);
		}
		let record = SpliceConflictRecord {
			channel_id: *channel_id,
			counterparty_node_id: *peer,
			splice_txid,
			conflict_txid: conflict_transaction.compute_txid(),
			input_index,
			confirmation_height,
			confirmation_hash,
			verified_tip,
			update_id: 0,
		};
		let result = chan.retire_conflicted_splice(record, conflict_transaction, &self.logger);
		let (update, record) = match result {
			Ok(result) => result,
			Err(_) => {
				let mut runtime = self.splice_conflict_runtime.lock().unwrap();
				runtime.pending.remove(&key);
				if runtime.homes.get(channel_id).is_some_and(|home| home.records.is_empty()) {
					runtime.homes.remove(channel_id);
				}
				return Err(conflict_unavailable());
			},
		};
		// Retirement must still reach its monitor even if a native implementation
		// bug lost the response binding. Generation zero cannot release a pause.
		let generation = chan.splice_conflict_response_generation(splice_txid).unwrap_or(0);
		{
			let mut runtime = self.splice_conflict_runtime.lock().unwrap();
			runtime.pending.insert(key, generation);
			runtime.homes.get_mut(channel_id).unwrap().records.push(record.clone());
		}
		peer_state
			.monitor_update_blocked_actions
			.entry(*channel_id)
			.or_default()
			.push(MonitorUpdateCompletionAction::SpliceConflictPersisted { record });
		if let Some(update) = update {
			handle_new_monitor_update!(
				self,
				funding_txo,
				update,
				peer_state_lock,
				peer_state,
				per_peer_state,
				chan
			);
		}
		Ok(())
	}

	/// Replay an exact persisted decision without reclassifying or altering funding.
	pub fn replay_splice_conflict_response(
		&self, channel_id: &ChannelId, peer: &PublicKey, splice_txid: Txid, conflict_txid: Txid,
		input_index: u16,
	) -> Result<bool, APIError> {
		let record = {
			let runtime = self.splice_conflict_runtime.lock().unwrap();
			let Some(home) = runtime.homes.get(channel_id) else {
				return Ok(false);
			};
			let Some(record) = home.records.iter().find(|record| record.splice_txid == splice_txid)
			else {
				return Ok(false);
			};
			if record.counterparty_node_id != *peer
				|| record.conflict_txid != conflict_txid
				|| record.input_index != input_index
			{
				return Err(conflict_unavailable());
			}
			if home.persisted_update_id < record.update_id {
				return Ok(true);
			}
			record.clone()
		};
		self.queue_splice_conflict_response(channel_id, peer, splice_txid, true, String::new())?;
		debug_assert_eq!(record.splice_txid, splice_txid);
		Ok(true)
	}

	/// Queue a bounded refusal for an owned candidate and its current peer pause.
	pub fn reject_splice_conflict_request(
		&self, channel_id: &ChannelId, peer: &PublicKey, splice_txid: Txid, reason: String,
	) -> Result<(), APIError> {
		self.splice_conflict_candidate(channel_id, peer, splice_txid)?;
		self.queue_splice_conflict_response(channel_id, peer, splice_txid, false, reason)
	}

	fn queue_splice_conflict_response(
		&self, channel_id: &ChannelId, peer: &PublicKey, splice_txid: Txid, agreed: bool,
		reason: String,
	) -> Result<(), APIError> {
		let peers = self.per_peer_state.read().unwrap();
		let mut state = peers.get(peer).ok_or_else(conflict_unavailable)?.lock().unwrap();
		if !state.is_connected {
			return Err(conflict_unavailable());
		}
		let chan = state
			.channel_by_id
			.get_mut(channel_id)
			.and_then(Channel::as_funded_mut)
			.ok_or_else(conflict_unavailable)?;
		let mut runtime = self.splice_conflict_runtime.lock().unwrap();
		let key = (*channel_id, splice_txid);
		if runtime.pending.contains_key(&key) {
			return Ok(());
		}
		if let Some(old) = runtime.responses.get(&key) {
			if old.response.agreed != agreed {
				return Err(conflict_unavailable());
			}
		} else if runtime.responses.len() + runtime.pending.len() >= MAX_CONFLICT_RESPONSES {
			return Err(conflict_unavailable());
		}
		let generation =
			chan.bind_splice_conflict_response(splice_txid).ok_or_else(conflict_unavailable)?;
		let mut reason = reason;
		let mut end = cmp::min(reason.len(), 128);
		while !reason.is_char_boundary(end) {
			end -= 1;
		}
		reason.truncate(end);
		runtime.responses.insert(
			key,
			QueuedResponse {
				response: SpliceConflictResponse {
					counterparty_node_id: *peer,
					channel_id: *channel_id,
					splice_txid,
					agreed,
					reason,
				},
				generation,
			},
		);
		self.event_persist_notifier.notify();
		Ok(())
	}

	/// Drain responses into the custom-message transport before allowing a matching
	/// native pause to end. Call this after draining ordinary native messages.
	pub fn get_and_clear_pending_splice_conflict_responses(&self) -> Vec<SpliceConflictResponse> {
		let responses = mem::take(&mut self.splice_conflict_runtime.lock().unwrap().responses);
		let mut result = Vec::with_capacity(responses.len());
		let peers = self.per_peer_state.read().unwrap();
		for (key, queued) in responses {
			let response = queued.response;
			let Some(lock) = peers.get(&response.counterparty_node_id) else {
				continue;
			};
			let mut state = lock.lock().unwrap();
			if !state.is_connected {
				continue;
			}
			let Some(chan) =
				state.channel_by_id.get_mut(&response.channel_id).and_then(Channel::as_funded_mut)
			else {
				continue;
			};
			if chan.complete_splice_conflict_response(response.splice_txid, queued.generation) {
				result.push(response);
			} else if chan.splice_conflict_response_generation(response.splice_txid)
				== Some(queued.generation)
			{
				// A later native monitor update may temporarily block releasing this
				// same pause. Retain its response until that update completes.
				self.splice_conflict_runtime
					.lock()
					.unwrap()
					.responses
					.insert(key, QueuedResponse { response, generation: queued.generation });
			}
		}
		result
	}

	pub(super) fn splice_conflict_monitor_persisted(&self, channel: ChannelId, update_id: u64) {
		if let Some(home) = self.splice_conflict_runtime.lock().unwrap().homes.get_mut(&channel) {
			home.persisted_update_id = cmp::max(home.persisted_update_id, update_id);
		}
	}

	pub(super) fn splice_conflict_persisted(&self, record: SpliceConflictRecord) {
		let mut runtime = self.splice_conflict_runtime.lock().unwrap();
		let Some(home) = runtime.homes.get(&record.channel_id) else {
			return;
		};
		if !home.records.iter().any(|saved| saved == &record) {
			return;
		}
		if home.persisted_update_id < record.update_id {
			drop(runtime);
			let peers = self.per_peer_state.read().unwrap();
			if let Some(lock) = peers.get(&record.counterparty_node_id) {
				lock.lock()
					.unwrap()
					.monitor_update_blocked_actions
					.entry(record.channel_id)
					.or_default()
					.push(MonitorUpdateCompletionAction::SpliceConflictPersisted { record });
			}
			return;
		}
		let key = (record.channel_id, record.splice_txid);
		let Some(generation) = runtime.pending.remove(&key) else {
			return;
		};
		runtime.responses.insert(
			key,
			QueuedResponse {
				generation,
				response: SpliceConflictResponse {
					counterparty_node_id: record.counterparty_node_id,
					channel_id: record.channel_id,
					splice_txid: record.splice_txid,
					agreed: true,
					reason: String::new(),
				},
			},
		);
		self.event_persist_notifier.notify();
	}
}
