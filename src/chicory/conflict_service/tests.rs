use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bitcoin::blockdata::constants::genesis_block;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{BlockHash, Network, ScriptBuf};

struct MockNative {
	peer: PublicKey,
	candidate: Transaction,
	conflict: Transaction,
	shared: OutPoint,
	tip: BestBlock,
	available: AtomicBool,
	replay: AtomicBool,
	refuse_commit: AtomicBool,
	monitor_current: AtomicBool,
	lookups: AtomicUsize,
	rejections: AtomicUsize,
	commits: AtomicUsize,
	application_gate: Arc<tokio::sync::Mutex<bool>>,
}
impl MockNative {
	fn new() -> Arc<Self> {
		let mut candidate = genesis_block(Network::Regtest).txdata.remove(0);
		candidate.input[0].previous_output =
			OutPoint { txid: Txid::from_byte_array([1; 32]), vout: 0 };
		candidate.input[0].script_sig = ScriptBuf::new();
		let shared = candidate.input[0].previous_output;
		let mut remote = candidate.input[0].clone();
		remote.previous_output = OutPoint { txid: Txid::from_byte_array([2; 32]), vout: 1 };
		candidate.input.push(remote.clone());
		let mut conflict = candidate.clone();
		conflict.input = vec![remote];
		Arc::new(Self {
			peer: PublicKey::from_secret_key(
				&Secp256k1::new(),
				&SecretKey::from_slice(&[2; 32]).unwrap(),
			),
			candidate,
			conflict,
			shared,
			tip: BestBlock::new(BlockHash::from_byte_array([3; 32]), 100),
			available: AtomicBool::new(true),
			replay: AtomicBool::new(false),
			refuse_commit: AtomicBool::new(false),
			monitor_current: AtomicBool::new(true),
			lookups: AtomicUsize::new(0),
			rejections: AtomicUsize::new(0),
			commits: AtomicUsize::new(0),
			application_gate: Arc::new(tokio::sync::Mutex::new(true)),
		})
	}
	fn request(&self, channel: u8) -> SpliceConflictRequest {
		SpliceConflictRequest {
			channel_id: [channel; 32],
			splice_txid: self.candidate.compute_txid().to_byte_array(),
			conflict_txid: self.conflict.compute_txid().to_byte_array(),
			input_index: 1,
		}
	}
	fn service(self: &Arc<Self>) -> Arc<ConflictService> {
		let service = Arc::new(ConflictService {
			backend: self.clone(),
			state: Mutex::new(State::default()),
			notify: Notify::new(),
		});
		service.start();
		service
	}
}
impl Backend for MockNative {
	fn replay(&self, peer: &PublicKey, request: &SpliceConflictRequest) -> Result<bool, ()> {
		if peer != &self.peer || request.channel_id == [0; 32] {
			return Err(());
		}
		Ok(self.replay.load(Ordering::Acquire))
	}
	fn candidate(
		&self, peer: &PublicKey, request: &SpliceConflictRequest,
	) -> Result<Candidate, ()> {
		self.lookups.fetch_add(1, Ordering::AcqRel);
		if peer != &self.peer
			|| request.channel_id == [0; 32]
			|| !self.available.load(Ordering::Acquire)
		{
			return Err(());
		}
		Ok(Candidate {
			transaction: self.candidate.clone(),
			shared_funding_outpoint: self.shared,
			best_block: self.tip,
		})
	}
	fn reject(&self, _: &PublicKey, _: &SpliceConflictRequest) {
		self.rejections.fetch_add(1, Ordering::AcqRel);
	}
	fn monitor_at_tip(&self, _: &SpliceConflictRequest, tip: BestBlock) -> bool {
		assert!(self.application_gate.try_lock().is_err(), "Monitor precheck must hold chain gate");
		self.monitor_current.load(Ordering::Acquire) && tip == self.tip
	}
	fn revert(
		&self, _: &PublicKey, _: &SpliceConflictRequest, _: ConfirmedTransaction,
	) -> Result<(), ()> {
		assert!(self.application_gate.try_lock().is_err(), "Native commit must hold chain gate");
		if self.refuse_commit.load(Ordering::Acquire) {
			return Err(());
		}
		self.commits.fetch_add(1, Ordering::AcqRel);
		Ok(())
	}
}

struct MockProof {
	native: Arc<MockNative>,
	calls: AtomicUsize,
	started: Notify,
	release: Notify,
	block: AtomicBool,
	fail: AtomicBool,
	wrong_tip: AtomicBool,
	wrong_tx: AtomicBool,
	shallow: AtomicBool,
}
impl MockProof {
	fn new(native: &Arc<MockNative>, block: bool) -> Arc<Self> {
		Arc::new(Self {
			native: Arc::clone(native),
			calls: AtomicUsize::new(0),
			started: Notify::new(),
			release: Notify::new(),
			block: AtomicBool::new(block),
			fail: AtomicBool::new(false),
			wrong_tip: AtomicBool::new(false),
			wrong_tx: AtomicBool::new(false),
			shallow: AtomicBool::new(false),
		})
	}
}
impl ProofSource for MockProof {
	fn application_gate(&self) -> Arc<tokio::sync::Mutex<bool>> {
		Arc::clone(&self.native.application_gate)
	}
	fn proof<'a>(
		&'a self, txid: Txid, tip: BestBlock,
	) -> Pin<Box<dyn Future<Output = Result<ConfirmedTransaction, ()>> + Send + 'a>> {
		Box::pin(async move {
			assert_eq!(txid, self.native.conflict.compute_txid());
			assert_eq!(tip, self.native.tip);
			self.calls.fetch_add(1, Ordering::AcqRel);
			self.started.notify_one();
			if self.block.load(Ordering::Acquire) {
				self.release.notified().await;
			}
			if self.fail.load(Ordering::Acquire) {
				return Err(());
			}
			Ok(ConfirmedTransaction {
				transaction: if self.wrong_tx.load(Ordering::Acquire) {
					self.native.candidate.clone()
				} else {
					self.native.conflict.clone()
				},
				block_hash: BlockHash::from_byte_array([4; 32]),
				height: if self.shallow.load(Ordering::Acquire) { 96 } else { 95 },
				tip: if self.wrong_tip.load(Ordering::Acquire) {
					BestBlock::new(BlockHash::all_zeros(), 100)
				} else {
					tip
				},
			})
		})
	}
}

#[test]
fn malformed_unknown_peer_and_invalid_input_never_enter_chain_queue() {
	let native = MockNative::new();
	let service = native.service();
	service.submit(native.peer, &[0; 97]);
	service.submit(native.peer, &native.request(0).encode());
	let other =
		PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[3; 32]).unwrap());
	service.submit(other, &native.request(1).encode());
	assert_eq!(native.lookups.load(Ordering::Acquire), 0);
	for index in [0, 2, u16::MAX] {
		let mut request = native.request(1);
		request.input_index = index;
		service.submit(native.peer, &request.encode());
	}
	assert!(service.state.lock().unwrap().queue.is_empty());
	assert_eq!(native.rejections.load(Ordering::Acquire), 3);
}

#[test]
fn queue_deduplicates_and_bounds_capacity_with_reconnect_safe_retry_credit() {
	let native = MockNative::new();
	let service = native.service();
	for channel in 1..=33 {
		service.submit(native.peer, &native.request(channel).encode());
	}
	assert_eq!(service.state.lock().unwrap().queue.len(), MAX_QUEUED);
	assert_eq!(native.rejections.load(Ordering::Acquire), 1);
	let mut invalid_duplicate = native.request(1);
	invalid_duplicate.input_index = u16::MAX;
	service.submit(native.peer, &invalid_duplicate.encode());
	assert_eq!(native.rejections.load(Ordering::Acquire), 1, "Do not disrupt admitted STFU");
	service.stop();
	assert!(service.state.lock().unwrap().pending.is_empty());
	service.start();
	service.submit(native.peer, &native.request(1).encode());
	assert!(service.state.lock().unwrap().queue.is_empty());
	assert_eq!(native.rejections.load(Ordering::Acquire), 2);
	// A native durable receipt needs no chain query and can replay during cooldown.
	native.replay.store(true, Ordering::Release);
	service.submit(native.peer, &native.request(1).encode());
	assert_eq!(native.rejections.load(Ordering::Acquire), 2);
}

#[tokio::test]
async fn queue_rechecks_candidate_and_expiry_before_chain_lookup() {
	let native = MockNative::new();
	let service = native.service();
	let source = MockProof::new(&native, false);
	service.submit(native.peer, &native.request(1).encode());
	native.available.store(false, Ordering::Release);
	service.process_next(source.as_ref()).await;
	assert_eq!(source.calls.load(Ordering::Acquire), 0);
	native.available.store(true, Ordering::Release);
	service.submit(native.peer, &native.request(2).encode());
	service.state.lock().unwrap().queue.front_mut().unwrap().admitted =
		Instant::now() - QUEUE_LIFETIME;
	service.process_next(source.as_ref()).await;
	assert_eq!(source.calls.load(Ordering::Acquire), 0);
	assert_eq!(native.rejections.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn chain_proof_rejection_and_native_state_race_never_commit() {
	for failure in 0..7 {
		let mut native = MockNative::new();
		if failure == 5 {
			Arc::get_mut(&mut native).unwrap().conflict.input[0].previous_output =
				OutPoint { txid: Txid::from_byte_array([9; 32]), vout: 0 };
		}
		let service = native.service();
		let source = MockProof::new(&native, false);
		source.fail.store(failure == 0, Ordering::Release);
		source.wrong_tip.store(failure == 1, Ordering::Release);
		native.refuse_commit.store(failure == 2, Ordering::Release);
		source.wrong_tx.store(failure == 3, Ordering::Release);
		source.shallow.store(failure == 4, Ordering::Release);
		native.monitor_current.store(failure != 6, Ordering::Release);
		service.submit(native.peer, &native.request(1).encode());
		service.process_next(source.as_ref()).await;
		assert_eq!(source.calls.load(Ordering::Acquire), 1);
		assert_eq!(native.commits.load(Ordering::Acquire), 0);
		assert_eq!(native.rejections.load(Ordering::Acquire), 1);
		assert_eq!(service.state.lock().unwrap().active, 0);
	}
}

#[tokio::test]
async fn two_concurrent_proofs_and_cancellation_release_processing_capacity() {
	let native = MockNative::new();
	let service = native.service();
	let source = MockProof::new(&native, true);
	let mut tasks = Vec::new();
	for channel in 1..=3 {
		service.submit(native.peer, &native.request(channel).encode());
		let worker_service = Arc::clone(&service);
		let worker_source = Arc::clone(&source);
		tasks.push(tokio::spawn(async move {
			worker_service.process_next(worker_source.as_ref()).await;
		}));
		if channel <= 2 {
			source.started.notified().await;
		}
	}
	for _ in 0..20 {
		tokio::task::yield_now().await;
	}
	assert_eq!(source.calls.load(Ordering::Acquire), 2);
	assert_eq!(service.state.lock().unwrap().active, 2);
	tasks[0].abort();
	let _ = (&mut tasks[0]).await;
	for _ in 0..20 {
		tokio::task::yield_now().await;
	}
	assert_eq!(source.calls.load(Ordering::Acquire), 3);
	assert_eq!(service.state.lock().unwrap().active, 2);
	service.stop();
	source.release.notify_waiters();
	for task in tasks.into_iter().skip(1) {
		task.await.unwrap();
	}
	assert_eq!(
		native.commits.load(Ordering::Acquire),
		0,
		"Stopping cannot release a proof into rollback"
	);
	let state = service.state.lock().unwrap();
	assert_eq!(state.active, 0);
	assert!(state.pending.is_empty());
}

#[tokio::test]
async fn exact_verified_conflict_reaches_native_commit_once() {
	let native = MockNative::new();
	let service = native.service();
	let source = MockProof::new(&native, false);
	service.submit(native.peer, &native.request(1).encode());
	service.submit(native.peer, &native.request(1).encode());
	service.process_next(source.as_ref()).await;
	assert_eq!(source.calls.load(Ordering::Acquire), 1);
	assert_eq!(native.commits.load(Ordering::Acquire), 1);
	assert_eq!(native.rejections.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn proof_timeout_cancels_lookup_and_keeps_retry_credit() {
	let native = MockNative::new();
	let service = native.service();
	let source = MockProof::new(&native, true);
	service.submit(native.peer, &native.request(1).encode());
	service.process_next_with_timeout(source.as_ref(), Duration::from_millis(1)).await;
	assert_eq!(source.calls.load(Ordering::Acquire), 1);
	assert_eq!(native.commits.load(Ordering::Acquire), 0);
	assert_eq!(native.rejections.load(Ordering::Acquire), 1);
	assert_eq!(service.state.lock().unwrap().active, 0);
	service.submit(native.peer, &native.request(1).encode());
	assert!(service.state.lock().unwrap().queue.is_empty());
	assert_eq!(native.rejections.load(Ordering::Acquire), 2);
}

#[tokio::test]
async fn chain_application_serializes_commit_but_not_proof_lookup() {
	let native = MockNative::new();
	let service = native.service();
	let source = MockProof::new(&native, true);
	let application = native.application_gate.lock().await;
	service.submit(native.peer, &native.request(1).encode());
	let worker_service = Arc::clone(&service);
	let worker_source = Arc::clone(&source);
	let task = tokio::spawn(async move {
		worker_service.process_next(worker_source.as_ref()).await;
	});
	// The network proof starts while a chain application batch owns the gate.
	tokio::time::timeout(Duration::from_secs(1), source.started.notified()).await.unwrap();
	source.release.notify_one();
	for _ in 0..20 {
		tokio::task::yield_now().await;
	}
	assert_eq!(native.commits.load(Ordering::Acquire), 0);
	assert_eq!(service.state.lock().unwrap().active, 1);
	drop(application);
	task.await.unwrap();
	assert_eq!(native.commits.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn incomplete_chain_application_and_gate_timeout_refuse_commit() {
	let native = MockNative::new();
	let service = native.service();
	let source = MockProof::new(&native, false);
	*native.application_gate.lock().await = false;
	service.submit(native.peer, &native.request(1).encode());
	service.process_next(source.as_ref()).await;
	assert_eq!(native.commits.load(Ordering::Acquire), 0);
	assert_eq!(native.rejections.load(Ordering::Acquire), 1);
	let mut application = native.application_gate.lock().await;
	*application = true;
	service.submit(native.peer, &native.request(2).encode());
	service.process_next_with_timeout(source.as_ref(), Duration::from_millis(1)).await;
	assert_eq!(native.commits.load(Ordering::Acquire), 0);
	assert_eq!(native.rejections.load(Ordering::Acquire), 2);
	assert_eq!(service.state.lock().unwrap().active, 0);
	drop(application);
	// Only a complete subsequent batch clears the fail-closed hold.
	service.submit(native.peer, &native.request(3).encode());
	service.process_next(source.as_ref()).await;
	assert_eq!(native.commits.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn cancelling_worker_waiting_for_chain_application_releases_lease() {
	let native = MockNative::new();
	let service = native.service();
	let source = MockProof::new(&native, false);
	let application = native.application_gate.lock().await;
	service.submit(native.peer, &native.request(1).encode());
	let worker_service = Arc::clone(&service);
	let worker_source = Arc::clone(&source);
	let task = tokio::spawn(async move {
		worker_service.process_next(worker_source.as_ref()).await;
	});
	tokio::time::timeout(Duration::from_secs(1), source.started.notified()).await.unwrap();
	for _ in 0..20 {
		tokio::task::yield_now().await;
	}
	task.abort();
	assert!(task.await.unwrap_err().is_cancelled());
	assert_eq!(service.state.lock().unwrap().active, 0);
	assert!(service.state.lock().unwrap().pending.is_empty());
	drop(application);
	assert_eq!(native.commits.load(Ordering::Acquire), 0);
	assert!(native.application_gate.try_lock().is_ok());
}

#[tokio::test]
async fn stopping_while_waiting_for_chain_application_cannot_commit() {
	let native = MockNative::new();
	let service = native.service();
	let source = MockProof::new(&native, false);
	let application = native.application_gate.lock().await;
	service.submit(native.peer, &native.request(1).encode());
	let worker_service = Arc::clone(&service);
	let worker_source = Arc::clone(&source);
	let task = tokio::spawn(async move {
		worker_service.process_next(worker_source.as_ref()).await;
	});
	tokio::time::timeout(Duration::from_secs(1), source.started.notified()).await.unwrap();
	service.stop();
	drop(application);
	task.await.unwrap();
	assert_eq!(native.commits.load(Ordering::Acquire), 0);
	assert_eq!(native.rejections.load(Ordering::Acquire), 0);
	assert_eq!(service.state.lock().unwrap().active, 0);
	assert!(service.state.lock().unwrap().pending.is_empty());
}

#[test]
fn malformed_candidate_flood_has_a_global_precheck_budget() {
	let native = MockNative::new();
	let service = native.service();
	let mut request = native.request(1);
	request.input_index = u16::MAX;
	for _ in 0..1000 {
		service.submit(native.peer, &request.encode());
	}
	assert_eq!(native.lookups.load(Ordering::Acquire), MAX_FRAMES_PER_SECOND);
	assert_eq!(native.rejections.load(Ordering::Acquire), MAX_FRAMES_PER_SECOND);
	assert!(service.state.lock().unwrap().queue.is_empty());
}
