//! Bounded splice conflict verification. Peer identifiers only select evidence.
//!
//! Native prechecks bind the authenticated peer, channel, quiescence owner and
//! current candidate before any chain lookup. The native commit method rechecks
//! those facts and the exact chain tip after the await, then gates acknowledgments
//! on durable monitor state. Queue state never grants rollback authority.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{OutPoint, Transaction, Txid};
use lightning::chain::BestBlock;
use lightning::ln::types::ChannelId;
use tokio::sync::Notify;

use super::conflict::SpliceConflictRequest;
use crate::chain::{ChainSource, ConfirmedTransaction};
use crate::types::{ChainMonitor, ChannelManager};

const MAX_CONCURRENT: usize = 2;
const MAX_QUEUED: usize = 32;
const MAX_RECENT_CHANNELS: usize = 1024;
const MAX_FRAMES_PER_SECOND: usize = 64;
const RETRY_DELAY: Duration = Duration::from_secs(30);
const QUEUE_LIFETIME: Duration = Duration::from_secs(30);
const PROOF_TIMEOUT: Duration = Duration::from_secs(15);
const REFUSAL: &str = "Splice conflict could not be independently confirmed.";

#[cfg(test)]
mod tests;

struct Candidate {
	transaction: Transaction,
	shared_funding_outpoint: OutPoint,
	best_block: BestBlock,
}

/// The native implementation, rather than this queue, owns all channel policy
/// and monitor persistence. This small boundary also supports race tests.
trait Backend: Send + Sync {
	fn replay(&self, peer: &PublicKey, request: &SpliceConflictRequest) -> Result<bool, ()>;
	fn candidate(&self, peer: &PublicKey, request: &SpliceConflictRequest)
		-> Result<Candidate, ()>;
	fn reject(&self, peer: &PublicKey, request: &SpliceConflictRequest);
	fn monitor_at_tip(&self, request: &SpliceConflictRequest, tip: BestBlock) -> bool;
	fn revert(
		&self, peer: &PublicKey, request: &SpliceConflictRequest, proof: ConfirmedTransaction,
	) -> Result<(), ()>;
}

struct NativeBackend {
	manager: Arc<ChannelManager>,
	monitor: Arc<ChainMonitor>,
}

impl Backend for NativeBackend {
	fn replay(&self, peer: &PublicKey, request: &SpliceConflictRequest) -> Result<bool, ()> {
		self.manager
			.replay_splice_conflict_response(
				&ChannelId(request.channel_id),
				peer,
				Txid::from_byte_array(request.splice_txid),
				Txid::from_byte_array(request.conflict_txid),
				request.input_index,
			)
			.map_err(|_| ())
	}
	fn candidate(
		&self, peer: &PublicKey, request: &SpliceConflictRequest,
	) -> Result<Candidate, ()> {
		let candidate = self
			.manager
			.splice_conflict_candidate(
				&ChannelId(request.channel_id),
				peer,
				Txid::from_byte_array(request.splice_txid),
			)
			.map_err(|_| ())?;
		Ok(Candidate {
			transaction: candidate.transaction,
			shared_funding_outpoint: candidate.shared_funding_outpoint,
			best_block: candidate.best_block,
		})
	}
	fn reject(&self, peer: &PublicKey, request: &SpliceConflictRequest) {
		let _ = self.manager.reject_splice_conflict_request(
			&ChannelId(request.channel_id),
			peer,
			Txid::from_byte_array(request.splice_txid),
			REFUSAL.to_owned(),
		);
	}
	fn monitor_at_tip(&self, request: &SpliceConflictRequest, tip: BestBlock) -> bool {
		// A monitor registered during a sync may not have been included in that
		// batch's listener snapshot. Drop its read guard before native update.
		self.monitor
			.get_monitor(ChannelId(request.channel_id))
			.is_ok_and(|monitor| monitor.current_best_block() == tip)
	}
	fn revert(
		&self, peer: &PublicKey, request: &SpliceConflictRequest, proof: ConfirmedTransaction,
	) -> Result<(), ()> {
		self.manager
			.revert_conflicted_splice(
				&ChannelId(request.channel_id),
				peer,
				Txid::from_byte_array(request.splice_txid),
				proof.transaction,
				request.input_index,
				proof.height,
				proof.block_hash,
				proof.tip,
			)
			.map_err(|_| ())
	}
}

trait ProofSource: Send + Sync {
	/// Serializes final native mutation with every CM and monitor chain callback.
	/// False means a previous chain application batch did not finish completely.
	fn application_gate(&self) -> Arc<tokio::sync::Mutex<bool>>;
	fn proof<'a>(
		&'a self, txid: Txid, tip: BestBlock,
	) -> Pin<Box<dyn Future<Output = Result<ConfirmedTransaction, ()>> + Send + 'a>>;
}
impl ProofSource for ChainSource {
	fn application_gate(&self) -> Arc<tokio::sync::Mutex<bool>> {
		self.chain_apply_gate()
	}
	fn proof<'a>(
		&'a self, txid: Txid, tip: BestBlock,
	) -> Pin<Box<dyn Future<Output = Result<ConfirmedTransaction, ()>> + Send + 'a>> {
		Box::pin(async move { self.confirmed_transaction(txid, tip).await.map_err(|_| ()) })
	}
}

struct Job {
	peer: PublicKey,
	request: SpliceConflictRequest,
	admitted: Instant,
}
#[derive(Default)]
struct State {
	accepting: bool,
	queue: VecDeque<Job>,
	pending: HashSet<[u8; 32]>,
	active: usize,
	recent: HashMap<[u8; 32], Instant>,
	frame_window: Option<(Instant, usize)>,
}

pub(crate) struct ConflictService {
	backend: Arc<dyn Backend>,
	state: Mutex<State>,
	notify: Notify,
}

/// Dropping a processing future releases queue capacity, including during node
/// shutdown. The retry credit remains spent across cancellation and reconnect.
struct Lease<'a> {
	service: &'a ConflictService,
	job: Job,
}
impl Drop for Lease<'_> {
	fn drop(&mut self) {
		let mut state = self.service.state.lock().unwrap();
		state.active -= 1;
		state.pending.remove(&self.job.request.channel_id);
		drop(state);
		self.service.notify.notify_one();
	}
}

impl ConflictService {
	pub(crate) fn new(
		channel_manager: Arc<ChannelManager>, chain_monitor: Arc<ChainMonitor>,
	) -> Self {
		Self {
			backend: Arc::new(NativeBackend { manager: channel_manager, monitor: chain_monitor }),
			state: Mutex::new(State::default()),
			notify: Notify::new(),
		}
	}
	pub(crate) fn start(&self) {
		self.state.lock().unwrap().accepting = true;
	}
	pub(crate) fn stop(&self) {
		let mut state = self.state.lock().unwrap();
		state.accepting = false;
		while let Some(job) = state.queue.pop_front() {
			state.pending.remove(&job.request.channel_id);
		}
	}

	pub(crate) fn submit(&self, peer: PublicKey, payload: &[u8]) {
		let Ok(request) = SpliceConflictRequest::decode(payload) else {
			return;
		};
		{
			let mut state = self.state.lock().unwrap();
			if !state.accepting || state.pending.contains(&request.channel_id) {
				return;
			}
			let now = Instant::now();
			let (started, frames) = state.frame_window.get_or_insert((now, 0));
			if now.duration_since(*started) >= Duration::from_secs(1) {
				*started = now;
				*frames = 0;
			}
			if *frames >= MAX_FRAMES_PER_SECOND {
				return;
			}
			*frames += 1;
		}
		match self.backend.replay(&peer, &request) {
			Ok(true) | Err(()) => return,
			Ok(false) => {},
		}
		let Ok(candidate) = self.backend.candidate(&peer, &request) else {
			return;
		};
		if !valid_input(&request, &candidate) {
			self.backend.reject(&peer, &request);
			return;
		}
		let now = Instant::now();
		let mut state = self.state.lock().unwrap();
		if !state.accepting || state.pending.contains(&request.channel_id) {
			return;
		}
		state.recent.retain(|_, previous| now.duration_since(*previous) < RETRY_DELAY);
		if state.queue.len() >= MAX_QUEUED
			|| state.recent.len() >= MAX_RECENT_CHANNELS
			|| state.recent.contains_key(&request.channel_id)
		{
			drop(state);
			self.backend.reject(&peer, &request);
			return;
		}
		state.recent.insert(request.channel_id, now);
		state.pending.insert(request.channel_id);
		state.queue.push_back(Job { peer, request, admitted: now });
		drop(state);
		self.notify.notify_one();
	}

	fn take(&self) -> Option<Lease<'_>> {
		let mut state = self.state.lock().unwrap();
		if !state.accepting || state.active >= MAX_CONCURRENT {
			return None;
		}
		let job = state.queue.pop_front()?;
		state.active += 1;
		let more = !state.queue.is_empty();
		drop(state);
		if more {
			self.notify.notify_one();
		}
		Some(Lease { service: self, job })
	}

	pub(crate) async fn handle_next(&self, source: &ChainSource) {
		self.process_next(source).await;
	}
	async fn process_next(&self, source: &dyn ProofSource) {
		self.process_next_with_timeout(source, PROOF_TIMEOUT).await;
	}
	async fn process_next_with_timeout(&self, source: &dyn ProofSource, timeout: Duration) {
		let lease = loop {
			let notified = self.notify.notified();
			tokio::pin!(notified);
			notified.as_mut().enable();
			if let Some(lease) = self.take() {
				break lease;
			}
			notified.await;
		};
		let Job { peer, request, admitted } = &lease.job;
		if admitted.elapsed() >= QUEUE_LIFETIME {
			self.backend.reject(peer, request);
			return;
		}
		// Candidate state can change while queued. Never start an arbitrary lookup
		// merely because the same request was admissible earlier.
		let Ok(candidate) = self.backend.candidate(peer, request) else {
			return;
		};
		if !valid_input(request, &candidate) {
			self.backend.reject(peer, request);
			return;
		}
		let proof = tokio::time::timeout(
			timeout,
			source.proof(Txid::from_byte_array(request.conflict_txid), candidate.best_block),
		)
		.await;
		if !self.state.lock().unwrap().accepting {
			return;
		}
		let Ok(Ok(proof)) = proof else {
			self.backend.reject(peer, request);
			return;
		};
		let expected_input =
			candidate.transaction.input[request.input_index as usize].previous_output;
		if proof.transaction.compute_txid().to_byte_array() != request.conflict_txid
			|| proof.tip != candidate.best_block
			|| proof.height == 0
			|| proof.tip.height.checked_sub(proof.height).map_or(true, |depth| depth < 5)
			|| !proof.transaction.input.iter().any(|input| input.previous_output == expected_input)
		{
			self.backend.reject(peer, request);
			return;
		}
		// Proof requests never hold the chain application gate. Only the final
		// synchronous native recheck and monitor application share its critical
		// section with chain synchronization. Native code rechecks the exact tip.
		let gate = source.application_gate();
		let Ok(guard) = tokio::time::timeout(timeout, gate.lock()).await else {
			self.backend.reject(peer, request);
			return;
		};
		if !self.state.lock().unwrap().accepting {
			return;
		}
		if !*guard || !self.backend.monitor_at_tip(request, proof.tip) {
			drop(guard);
			self.backend.reject(peer, request);
			return;
		}
		let result = self.backend.revert(peer, request, proof);
		drop(guard);
		if result.is_err() {
			self.backend.reject(peer, request);
		}
	}
}

fn valid_input(request: &SpliceConflictRequest, candidate: &Candidate) -> bool {
	request.splice_txid != request.conflict_txid
		&& candidate.transaction.compute_txid().to_byte_array() == request.splice_txid
		&& candidate.transaction.input.get(request.input_index as usize).is_some_and(|input| {
			input.previous_output != candidate.shared_funding_outpoint
				&& !input.previous_output.is_null()
		})
}
