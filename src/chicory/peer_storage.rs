//! BOLT 1 peer-storage compatibility for Beignet's padded recovery blobs.
//!
//! Only authenticated peers with an established channel may consume a storage
//! slot. Retrieval is always addressed to that same authenticated public key,
//! including after a restart or channel closure. Bytes remain opaque, are never
//! logged, and are persisted before replacing any queued retrieval response.
//! All channel state and channel messages remain owned by LDK's ChannelManager.

#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::constants::ChainHash;
use bitcoin::secp256k1::PublicKey;
use lightning::io;
use lightning::ln::msgs::{self, BaseMessageHandler, ChannelMessageHandler, MessageSendEvent};
use lightning::ln::types::ChannelId;
use lightning::util::persist::KVStoreSync;
use lightning_types::features::{InitFeatures, NodeFeatures};

use crate::types::{ChannelManager, DynStore};

const NAMESPACE: &str = "chicory_peer_storage";
const MAX_BLOB_BYTES: usize = 65_531;
const MAX_STORED_PEERS: usize = 1_024;
// Beignet normally refreshes its recovery capsule once per minute, with a
// fresh resend on reconnect. Allow short initialization/reconnect bursts while
// bounding synchronous disk writes from authenticated channel peers.
const PEER_WRITE_BURST: u32 = 8;
const PEER_WRITE_INTERVAL: Duration = Duration::from_secs(1);
const GLOBAL_WRITE_BURST: u32 = 64;
const GLOBAL_WRITE_INTERVAL: Duration = Duration::from_micros(62_500);

/// Delegates Lightning channel operations while storing full-size peer backups.
pub(crate) struct PeerStorageChannelHandler {
	manager: Arc<ChannelManager>,
	enabled: bool,
	// The dispatch lock prevents the manager's reconnect retrieval from escaping
	// before its durable replacement is queued. Lock order is dispatch, manager,
	// blobs. Incoming storage checks the manager before acquiring blobs.
	dispatch: Mutex<()>,
	blobs: Mutex<PeerBlobs>,
}

impl PeerStorageChannelHandler {
	/// Keep native behavior unless the operator explicitly enables this service.
	pub(crate) fn new(manager: Arc<ChannelManager>, store: Arc<DynStore>, enabled: bool) -> Self {
		Self {
			manager,
			enabled,
			dispatch: Mutex::new(()),
			blobs: Mutex::new(PeerBlobs::new(store)),
		}
	}
}

struct PeerBlobs {
	store: Arc<DynStore>,
	// Only the key index is cached. Reconnects read the durable bytes themselves.
	keys: Option<HashSet<String>>,
	pending: HashMap<PublicKey, Vec<u8>>,
	// Only established channel peers can add a warning, one pending per peer.
	warnings: HashSet<PublicKey>,
	write_limits: WriteLimits,
}

struct WriteBudget {
	// A duration represents fractional write credits without floating point.
	credit: Duration,
	updated_at: Instant,
}

impl WriteBudget {
	fn full(now: Instant, interval: Duration, burst: u32) -> Self {
		Self { credit: interval * burst, updated_at: now }
	}

	fn refill(&mut self, now: Instant, interval: Duration, burst: u32) {
		self.credit = self
			.credit
			.saturating_add(now.saturating_duration_since(self.updated_at))
			.min(interval * burst);
		self.updated_at = self.updated_at.max(now);
	}
}

struct WriteLimits {
	global: WriteBudget,
	peers: HashMap<PublicKey, WriteBudget>,
}

impl WriteLimits {
	fn new(now: Instant) -> Self {
		Self {
			global: WriteBudget::full(now, GLOBAL_WRITE_INTERVAL, GLOBAL_WRITE_BURST),
			peers: HashMap::new(),
		}
	}

	fn allow(&mut self, peer: PublicKey, now: Instant) -> bool {
		self.global.refill(now, GLOBAL_WRITE_INTERVAL, GLOBAL_WRITE_BURST);
		if self.global.credit < GLOBAL_WRITE_INTERVAL {
			return false;
		}
		if !self.peers.contains_key(&peer) && self.peers.len() >= MAX_STORED_PEERS {
			// Only forget fully replenished budgets. Disconnect/reconnect cannot
			// reset a depleted budget, and transient failures cannot grow the map.
			self.peers.retain(|_, budget| {
				budget.refill(now, PEER_WRITE_INTERVAL, PEER_WRITE_BURST);
				budget.credit < PEER_WRITE_INTERVAL * PEER_WRITE_BURST
			});
			if self.peers.len() >= MAX_STORED_PEERS {
				return false;
			}
		}
		let budget = self
			.peers
			.entry(peer)
			.or_insert_with(|| WriteBudget::full(now, PEER_WRITE_INTERVAL, PEER_WRITE_BURST));
		budget.refill(now, PEER_WRITE_INTERVAL, PEER_WRITE_BURST);
		if budget.credit < PEER_WRITE_INTERVAL {
			return false;
		}
		// Count attempts before accessing the store, including failed writes.
		// Rejected peer floods do not consume other peers' global allowance.
		budget.credit -= PEER_WRITE_INTERVAL;
		self.global.credit -= GLOBAL_WRITE_INTERVAL;
		true
	}
}

impl PeerBlobs {
	fn new(store: Arc<DynStore>) -> Self {
		Self {
			store,
			keys: None,
			pending: HashMap::new(),
			warnings: HashSet::new(),
			write_limits: WriteLimits::new(Instant::now()),
		}
	}

	fn read(&self, peer: PublicKey) -> io::Result<Option<Vec<u8>>> {
		match KVStoreSync::read(&*self.store, NAMESPACE, "", &peer.to_string()) {
			Ok(data) if data.len() <= MAX_BLOB_BYTES => Ok(Some(data)),
			Ok(_) => {
				Err(io::Error::new(io::ErrorKind::InvalidData, "peer backup exceeds size limit"))
			},
			Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
			Err(error) => Err(error),
		}
	}

	fn receive(&mut self, peer: PublicKey, data: Vec<u8>, eligible: bool) -> io::Result<bool> {
		self.receive_at(peer, data, eligible, Instant::now())
	}

	fn receive_at(
		&mut self, peer: PublicKey, data: Vec<u8>, eligible: bool, now: Instant,
	) -> io::Result<bool> {
		if !eligible || data.len() > MAX_BLOB_BYTES {
			return Ok(false);
		}
		if !self.write_limits.allow(peer, now) {
			// A warning explicitly rejects this update. Neither durable bytes nor
			// queued recovery data are replaced by an unpersisted version.
			self.warning(peer);
			return Ok(false);
		}
		if self.keys.is_none() {
			let keys = KVStoreSync::list(&*self.store, NAMESPACE, "")?;
			// Never grow an unbounded in-memory index from malformed persisted data.
			if keys.len() > MAX_STORED_PEERS {
				return Err(io::Error::new(
					io::ErrorKind::InvalidData,
					"peer backup slot limit exceeded",
				));
			}
			self.keys = Some(keys.into_iter().collect());
		}
		let key = peer.to_string();
		let keys = self.keys.as_mut().expect("key index initialized above");
		if !keys.contains(&key) && keys.len() >= MAX_STORED_PEERS {
			return Ok(false);
		}
		// KVStoreSync guarantees durable ordered writes. Keep no newer replacement
		// in memory if the persistence boundary rejects the write.
		KVStoreSync::write(&*self.store, NAMESPACE, "", &key, data.clone())?;
		keys.insert(key);
		if let Some(pending) = self.pending.get_mut(&peer) {
			*pending = data;
		}
		Ok(true)
	}

	fn queue_retrieval(&mut self, peer: PublicKey) -> io::Result<()> {
		if let Some(data) = self.read(peer)? {
			if !self.pending.contains_key(&peer) && self.pending.len() >= MAX_STORED_PEERS {
				return Err(io::Error::new(
					io::ErrorKind::WouldBlock,
					"peer backup response queue full",
				));
			}
			self.pending.insert(peer, data);
		}
		Ok(())
	}

	fn warning(&mut self, peer: PublicKey) {
		if self.warnings.len() < MAX_STORED_PEERS {
			self.warnings.insert(peer);
		}
	}

	fn merge_events(&mut self, native: Vec<MessageSendEvent>) -> Vec<MessageSendEvent> {
		let replaced: HashSet<_> = self.pending.keys().copied().collect();
		let mut events = Vec::with_capacity(native.len() + self.pending.len());
		// Recovery data must arrive before channel_reestablish so the peer can
		// restore its channel state before processing channel messages.
		for (node_id, data) in self.pending.drain() {
			events.push(MessageSendEvent::SendPeerStorageRetrieval {
				node_id,
				msg: msgs::PeerStorageRetrieval { data },
			});
		}
		for event in native {
			if matches!(&event, MessageSendEvent::SendPeerStorageRetrieval { node_id, .. } if replaced.contains(node_id))
			{
				continue;
			}
			events.push(event);
		}
		for node_id in self.warnings.drain() {
			events.push(MessageSendEvent::HandleError {
				node_id,
				action: msgs::ErrorAction::SendWarningMessage {
					msg: msgs::WarningMessage {
						channel_id: ChannelId([0; 32]),
						data: "Peer backup was not stored; storage is unavailable or a limit was reached.".to_owned(),
					},
					log_level: lightning::util::logger::Level::Warn,
				},
			});
		}
		events
	}
}

impl BaseMessageHandler for PeerStorageChannelHandler {
	fn get_and_clear_pending_msg_events(&self) -> Vec<MessageSendEvent> {
		if !self.enabled {
			return self.manager.get_and_clear_pending_msg_events();
		}
		let _dispatch = self.dispatch.lock().unwrap();
		let native = self.manager.get_and_clear_pending_msg_events();
		self.blobs.lock().unwrap().merge_events(native)
	}

	fn peer_disconnected(&self, peer: PublicKey) {
		if !self.enabled {
			return self.manager.peer_disconnected(peer);
		}
		let _dispatch = self.dispatch.lock().unwrap();
		self.manager.peer_disconnected(peer);
		let mut blobs = self.blobs.lock().unwrap();
		blobs.pending.remove(&peer);
		blobs.warnings.remove(&peer);
	}

	fn provided_node_features(&self) -> NodeFeatures {
		self.manager.provided_node_features()
	}
	fn provided_init_features(&self, peer: PublicKey) -> InitFeatures {
		self.manager.provided_init_features(peer)
	}

	fn peer_connected(
		&self, peer: PublicKey, message: &msgs::Init, inbound: bool,
	) -> Result<(), ()> {
		if !self.enabled {
			return self.manager.peer_connected(peer, message, inbound);
		}
		let _dispatch = self.dispatch.lock().unwrap();
		self.manager.peer_connected(peer, message, inbound)?;
		let queued = self.blobs.lock().unwrap().queue_retrieval(peer);
		if queued.is_err() {
			// A failed durable read must never fall back to a possibly older native
			// backup. BaseMessageHandler will not call disconnected after Err.
			self.manager.peer_disconnected(peer);
			self.blobs.lock().unwrap().pending.remove(&peer);
			return Err(());
		}
		Ok(())
	}
}

// The compiler checks each delegation against ChannelMessageHandler's concrete
// signatures. No message translation, channel state, or cryptography lives here.
macro_rules! delegate_borrowed {
	($($method:ident($message:ident)),+ $(,)?) => {
		$(fn $method(&self, peer: PublicKey, message: &msgs::$message) {
			self.manager.$method(peer, message);
		})+
	};
}

impl ChannelMessageHandler for PeerStorageChannelHandler {
	delegate_borrowed! {
		handle_open_channel(OpenChannel),
		handle_open_channel_v2(OpenChannelV2),
		handle_accept_channel(AcceptChannel),
		handle_accept_channel_v2(AcceptChannelV2),
		handle_funding_created(FundingCreated),
		handle_funding_signed(FundingSigned),
		handle_channel_ready(ChannelReady),
		handle_shutdown(Shutdown),
		handle_closing_signed(ClosingSigned),
		handle_stfu(Stfu),
		handle_splice_init(SpliceInit),
		handle_splice_ack(SpliceAck),
		handle_splice_locked(SpliceLocked),
		handle_tx_add_input(TxAddInput),
		handle_tx_add_output(TxAddOutput),
		handle_tx_remove_input(TxRemoveInput),
		handle_tx_remove_output(TxRemoveOutput),
		handle_tx_complete(TxComplete),
		handle_tx_signatures(TxSignatures),
		handle_tx_init_rbf(TxInitRbf),
		handle_tx_ack_rbf(TxAckRbf),
		handle_tx_abort(TxAbort),
		handle_update_add_htlc(UpdateAddHTLC),
		handle_update_fail_htlc(UpdateFailHTLC),
		handle_update_fail_malformed_htlc(UpdateFailMalformedHTLC),
		handle_commitment_signed(CommitmentSigned),
		handle_revoke_and_ack(RevokeAndACK),
		handle_update_fee(UpdateFee),
		handle_announcement_signatures(AnnouncementSignatures),
		handle_channel_reestablish(ChannelReestablish),
		handle_channel_update(ChannelUpdate),
		handle_error(ErrorMessage),
	}

	fn handle_peer_storage(&self, peer: PublicKey, message: msgs::PeerStorage) {
		if !self.enabled {
			return self.manager.handle_peer_storage(peer, message);
		}
		// Channel-ready remains true while disconnected, unlike is_usable.
		// Negotiations and unfunded channel requests cannot allocate storage.
		let eligible = self
			.manager
			.list_channels_with_counterparty(&peer)
			.iter()
			.any(|channel| channel.is_channel_ready && channel.funding_txo.is_some());
		if !eligible {
			return;
		}
		// Failure preserves the old durable value. A bounded warning informs the
		// peer without disclosing opaque bytes, paths, or storage backend details.
		let mut blobs = self.blobs.lock().unwrap();
		if !matches!(blobs.receive(peer, message.data, true), Ok(true)) {
			blobs.warning(peer);
		}
	}

	fn handle_peer_storage_retrieval(&self, peer: PublicKey, message: msgs::PeerStorageRetrieval) {
		self.manager.handle_peer_storage_retrieval(peer, message);
	}

	fn handle_update_fulfill_htlc(&self, peer: PublicKey, message: msgs::UpdateFulfillHTLC) {
		self.manager.handle_update_fulfill_htlc(peer, message);
	}

	fn handle_commitment_signed_batch(
		&self, peer: PublicKey, channel_id: ChannelId, batch: Vec<msgs::CommitmentSigned>,
	) {
		self.manager.handle_commitment_signed_batch(peer, channel_id, batch);
	}

	fn get_chain_hashes(&self) -> Option<Vec<ChainHash>> {
		self.manager.get_chain_hashes()
	}
	fn message_received(&self) {
		self.manager.message_received();
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::io::test_utils::{random_storage_path, InMemoryStore};
	use crate::Builder;
	use bitcoin::secp256k1::{Secp256k1, SecretKey};
	use lightning::util::persist::KVStore;
	use std::future::Future;
	use std::pin::Pin;
	use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

	struct FailingStore {
		inner: InMemoryStore,
		fail: AtomicBool,
		write_attempts: AtomicUsize,
	}

	impl KVStoreSync for FailingStore {
		fn read(&self, primary: &str, secondary: &str, key: &str) -> io::Result<Vec<u8>> {
			KVStoreSync::read(&self.inner, primary, secondary, key)
		}
		fn write(
			&self, primary: &str, secondary: &str, key: &str, bytes: Vec<u8>,
		) -> io::Result<()> {
			self.write_attempts.fetch_add(1, Ordering::SeqCst);
			if self.fail.load(Ordering::SeqCst) {
				return Err(io::Error::new(io::ErrorKind::Other, "injected write failure"));
			}
			KVStoreSync::write(&self.inner, primary, secondary, key, bytes)
		}
		fn remove(&self, primary: &str, secondary: &str, key: &str, lazy: bool) -> io::Result<()> {
			KVStoreSync::remove(&self.inner, primary, secondary, key, lazy)
		}
		fn list(&self, primary: &str, secondary: &str) -> io::Result<Vec<String>> {
			KVStoreSync::list(&self.inner, primary, secondary)
		}
	}

	impl KVStore for FailingStore {
		fn read(
			&self, primary: &str, secondary: &str, key: &str,
		) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send>> {
			let result = KVStoreSync::read(self, primary, secondary, key);
			Box::pin(async move { result })
		}
		fn write(
			&self, primary: &str, secondary: &str, key: &str, bytes: Vec<u8>,
		) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send>> {
			let result = KVStoreSync::write(self, primary, secondary, key, bytes);
			Box::pin(async move { result })
		}
		fn remove(
			&self, primary: &str, secondary: &str, key: &str, lazy: bool,
		) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send>> {
			let result = KVStoreSync::remove(self, primary, secondary, key, lazy);
			Box::pin(async move { result })
		}
		fn list(
			&self, primary: &str, secondary: &str,
		) -> Pin<Box<dyn Future<Output = io::Result<Vec<String>>> + Send>> {
			let result = KVStoreSync::list(self, primary, secondary);
			Box::pin(async move { result })
		}
	}

	fn peer(value: u16) -> PublicKey {
		let mut secret = [0; 32];
		secret[30..].copy_from_slice(&value.to_be_bytes());
		PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&secret).unwrap())
	}

	fn retrieval(peer: PublicKey, data: Vec<u8>) -> MessageSendEvent {
		MessageSendEvent::SendPeerStorageRetrieval {
			node_id: peer,
			msg: msgs::PeerStorageRetrieval { data },
		}
	}

	fn data_for(events: Vec<MessageSendEvent>, peer: PublicKey) -> Vec<Vec<u8>> {
		events
			.into_iter()
			.filter_map(|event| match event {
				MessageSendEvent::SendPeerStorageRetrieval { node_id, msg } if node_id == peer => {
					Some(msg.data)
				},
				_ => None,
			})
			.collect()
	}

	#[test]
	fn full_size_backups_survive_restart_and_are_bound_to_peer() {
		let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let mut blobs = PeerBlobs::new(Arc::clone(&store));
		let data = vec![42; MAX_BLOB_BYTES];
		assert!(blobs.receive(peer(1), data.clone(), true).unwrap());
		drop(blobs);
		let mut restarted = PeerBlobs::new(store);
		restarted.queue_retrieval(peer(2)).unwrap();
		assert!(restarted.merge_events(vec![]).is_empty());
		restarted.queue_retrieval(peer(1)).unwrap();
		assert_eq!(data_for(restarted.merge_events(vec![]), peer(1)), vec![data]);
		assert!(restarted.merge_events(vec![]).is_empty());
	}

	#[test]
	fn unauthorized_and_oversized_writes_leave_existing_backup_intact() {
		let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let mut blobs = PeerBlobs::new(store);
		assert!(!blobs.receive(peer(1), vec![1], false).unwrap());
		assert_eq!(blobs.read(peer(1)).unwrap(), None);
		assert!(blobs.receive(peer(1), vec![2], true).unwrap());
		assert!(!blobs.receive(peer(1), vec![3; MAX_BLOB_BYTES + 1], true).unwrap());
		assert!(!blobs.receive(peer(1), vec![4], false).unwrap());
		assert_eq!(blobs.read(peer(1)).unwrap(), Some(vec![2]));
	}

	#[test]
	fn durable_retrieval_replaces_native_once_and_tracks_latest_backup() {
		let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let mut blobs = PeerBlobs::new(store);
		assert!(blobs.receive(peer(1), vec![2], true).unwrap());
		blobs.queue_retrieval(peer(1)).unwrap();
		assert!(blobs.receive(peer(1), vec![3], true).unwrap());
		let events =
			blobs.merge_events(vec![retrieval(peer(1), vec![1]), retrieval(peer(1), vec![1])]);
		assert_eq!(data_for(events, peer(1)), vec![vec![3]]);
		assert_eq!(
			data_for(blobs.merge_events(vec![retrieval(peer(2), vec![7])]), peer(2)),
			vec![vec![7]]
		);
	}

	#[test]
	fn durable_retrieval_precedes_reestablish_and_preserves_unrelated_native_order() {
		let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let mut blobs = PeerBlobs::new(store);
		assert!(blobs.receive(peer(1), vec![42], true).unwrap());
		blobs.queue_retrieval(peer(1)).unwrap();
		let reestablish = msgs::ChannelReestablish {
			channel_id: ChannelId([9; 32]),
			next_local_commitment_number: 2,
			next_remote_commitment_number: 1,
			your_last_per_commitment_secret: [0; 32],
			my_current_per_commitment_point: peer(1),
			next_funding: None,
			my_current_funding_locked: None,
		};
		let native = vec![
			MessageSendEvent::SendChannelReestablish { node_id: peer(1), msg: reestablish.clone() },
			retrieval(peer(2), vec![7]),
			retrieval(peer(1), vec![1]),
			retrieval(peer(2), vec![8]),
		];
		let events = blobs.merge_events(native);
		assert_eq!(events.len(), 4);
		assert!(matches!(&events[0], MessageSendEvent::SendPeerStorageRetrieval { node_id, msg }
			if *node_id == peer(1) && msg.data == vec![42]));
		assert!(matches!(&events[1], MessageSendEvent::SendChannelReestablish { node_id, msg }
			if *node_id == peer(1) && *msg == reestablish));
		assert!(matches!(&events[2], MessageSendEvent::SendPeerStorageRetrieval { node_id, msg }
			if *node_id == peer(2) && msg.data == vec![7]));
		assert!(matches!(&events[3], MessageSendEvent::SendPeerStorageRetrieval { node_id, msg }
			if *node_id == peer(2) && msg.data == vec![8]));
		assert!(blobs.merge_events(vec![]).is_empty());
	}

	#[test]
	fn durable_slot_limit_applies_after_restart_and_allows_updates() {
		let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let mut blobs = PeerBlobs::new(Arc::clone(&store));
		let now = Instant::now();
		for value in 1..=MAX_STORED_PEERS {
			assert!(blobs
				.receive_at(
					peer(value as u16),
					vec![1],
					true,
					now + Duration::from_secs(value as u64)
				)
				.unwrap());
		}
		let mut restarted = PeerBlobs::new(store);
		assert!(!restarted.receive(peer(1025), vec![1], true).unwrap());
		assert!(restarted.receive(peer(1), vec![2], true).unwrap());
		assert_eq!(restarted.read(peer(1)).unwrap(), Some(vec![2]));
	}

	#[test]
	fn failed_writes_never_replace_the_last_durable_or_queued_backup() {
		let store = Arc::new(FailingStore {
			inner: InMemoryStore::new(),
			fail: AtomicBool::new(false),
			write_attempts: AtomicUsize::new(0),
		});
		let mut blobs = PeerBlobs::new(store.clone());
		assert!(blobs.receive(peer(1), vec![1], true).unwrap());
		blobs.queue_retrieval(peer(1)).unwrap();
		store.fail.store(true, Ordering::SeqCst);
		assert!(blobs.receive(peer(1), vec![2], true).is_err());
		assert!(blobs.receive(peer(2), vec![3], true).is_err());
		assert_eq!(blobs.read(peer(1)).unwrap(), Some(vec![1]));
		assert_eq!(blobs.read(peer(2)).unwrap(), None);
		assert_eq!(blobs.keys.as_ref().unwrap().len(), 1);
		assert_eq!(data_for(blobs.merge_events(vec![]), peer(1)), vec![vec![1]]);
	}

	#[test]
	fn peer_write_limit_warns_and_preserves_latest_durable_recovery() {
		let store = Arc::new(FailingStore {
			inner: InMemoryStore::new(),
			fail: AtomicBool::new(false),
			write_attempts: AtomicUsize::new(0),
		});
		let mut blobs = PeerBlobs::new(store.clone());
		let now = Instant::now();
		for value in 0..PEER_WRITE_BURST {
			assert!(blobs
				.receive_at(peer(1), vec![value as u8; MAX_BLOB_BYTES], true, now)
				.unwrap());
			blobs.queue_retrieval(peer(1)).unwrap();
		}
		for _ in 0..100 {
			assert!(!blobs.receive_at(peer(1), vec![99; MAX_BLOB_BYTES], true, now).unwrap());
		}
		assert_eq!(store.write_attempts.load(Ordering::SeqCst), PEER_WRITE_BURST as usize);
		let last = vec![(PEER_WRITE_BURST - 1) as u8; MAX_BLOB_BYTES];
		assert_eq!(blobs.read(peer(1)).unwrap(), Some(last.clone()));
		let events = blobs.merge_events(vec![]);
		assert!(events.iter().any(|event| matches!(event,
			MessageSendEvent::HandleError { node_id, action: msgs::ErrorAction::SendWarningMessage { msg, .. } }
			if *node_id == peer(1) && msg.data == "Peer backup was not stored; storage is unavailable or a limit was reached."
		)));
		assert_eq!(data_for(events, peer(1)), vec![last]);
		// Rejected floods cannot consume another peer's global write credits.
		assert!(blobs.receive_at(peer(2), vec![2], true, now).unwrap());
		assert!(!blobs
			.receive_at(peer(1), vec![8], true, now + PEER_WRITE_INTERVAL - Duration::from_nanos(1))
			.unwrap());
		assert!(blobs.receive_at(peer(1), vec![8], true, now + PEER_WRITE_INTERVAL).unwrap());
		blobs.queue_retrieval(peer(1)).unwrap();
		assert_eq!(data_for(blobs.merge_events(vec![]), peer(1)), vec![vec![8]]);
		let mut restarted = PeerBlobs::new(store);
		restarted.queue_retrieval(peer(1)).unwrap();
		assert_eq!(data_for(restarted.merge_events(vec![]), peer(1)), vec![vec![8]]);
	}

	#[test]
	fn global_write_limit_bounds_distinct_peers_and_refills_fractionally() {
		let store = Arc::new(FailingStore {
			inner: InMemoryStore::new(),
			fail: AtomicBool::new(false),
			write_attempts: AtomicUsize::new(0),
		});
		let mut blobs = PeerBlobs::new(store.clone());
		let now = Instant::now();
		for value in 1..=GLOBAL_WRITE_BURST {
			assert!(blobs.receive_at(peer(value as u16), vec![1], true, now).unwrap());
		}
		assert!(!blobs.receive_at(peer(65), vec![2], true, now).unwrap());
		assert_eq!(blobs.read(peer(65)).unwrap(), None);
		assert_eq!(store.write_attempts.load(Ordering::SeqCst), GLOBAL_WRITE_BURST as usize);
		assert!(!blobs
			.receive_at(peer(65), vec![2], true, now + GLOBAL_WRITE_INTERVAL / 2)
			.unwrap());
		assert!(blobs.receive_at(peer(65), vec![2], true, now + GLOBAL_WRITE_INTERVAL).unwrap());
		assert!(!blobs.receive_at(peer(66), vec![3], true, now + GLOBAL_WRITE_INTERVAL).unwrap());
		assert_eq!(store.write_attempts.load(Ordering::SeqCst), GLOBAL_WRITE_BURST as usize + 1);
		blobs.queue_retrieval(peer(1)).unwrap();
		assert_eq!(data_for(blobs.merge_events(vec![]), peer(1)), vec![vec![1]]);
	}

	#[test]
	fn failed_store_attempts_consume_write_credits_before_io() {
		let store = Arc::new(FailingStore {
			inner: InMemoryStore::new(),
			fail: AtomicBool::new(false),
			write_attempts: AtomicUsize::new(0),
		});
		let mut blobs = PeerBlobs::new(store.clone());
		let now = Instant::now();
		assert!(blobs.receive_at(peer(1), vec![1], true, now).unwrap());
		blobs.queue_retrieval(peer(1)).unwrap();
		store.fail.store(true, Ordering::SeqCst);
		for _ in 1..PEER_WRITE_BURST {
			assert!(blobs.receive_at(peer(1), vec![2], true, now).is_err());
		}
		assert!(!blobs.receive_at(peer(1), vec![3], true, now).unwrap());
		assert_eq!(store.write_attempts.load(Ordering::SeqCst), PEER_WRITE_BURST as usize);
		assert_eq!(data_for(blobs.merge_events(vec![]), peer(1)), vec![vec![1]]);
		store.fail.store(false, Ordering::SeqCst);
		assert!(blobs.receive_at(peer(1), vec![4], true, now + PEER_WRITE_INTERVAL).unwrap());
		assert_eq!(blobs.read(peer(1)).unwrap(), Some(vec![4]));
	}

	#[test]
	fn bounded_write_budget_map_evicts_only_fully_replenished_peers() {
		let now = Instant::now();
		let mut limits = WriteLimits::new(now);
		for value in 1..=MAX_STORED_PEERS {
			assert!(limits.allow(peer(value as u16), now + Duration::from_secs(value as u64)));
		}
		assert_eq!(limits.peers.len(), MAX_STORED_PEERS);
		let later = now + Duration::from_secs(MAX_STORED_PEERS as u64);
		assert!(limits.allow(peer(1025), later));
		assert!(limits.peers.len() < MAX_STORED_PEERS);
		assert!(!limits.peers.contains_key(&peer(1)));
		assert!(limits.peers.contains_key(&peer(1024)));
		for _ in 1..PEER_WRITE_BURST {
			assert!(limits.allow(peer(1024), later));
		}
		assert!(!limits.allow(peer(1024), later));
	}

	#[test]
	fn corrupt_oversized_persisted_backup_is_never_queued() {
		let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		KVStoreSync::write(
			&*store,
			NAMESPACE,
			"",
			&peer(1).to_string(),
			vec![1; MAX_BLOB_BYTES + 1],
		)
		.unwrap();
		let mut blobs = PeerBlobs::new(store);
		assert_eq!(blobs.queue_retrieval(peer(1)).unwrap_err().kind(), io::ErrorKind::InvalidData);
		assert!(blobs.merge_events(vec![]).is_empty());
	}

	#[test]
	fn storage_warnings_are_bounded_and_coalesced_without_payloads() {
		let store: Arc<DynStore> = Arc::new(InMemoryStore::new());
		let mut blobs = PeerBlobs::new(store);
		for value in 1..=MAX_STORED_PEERS + 2 {
			blobs.warning(peer(value as u16));
			blobs.warning(peer(value as u16));
		}
		let events = blobs.merge_events(vec![]);
		assert_eq!(events.len(), MAX_STORED_PEERS);
		for event in events {
			match event {
				MessageSendEvent::HandleError {
					action: msgs::ErrorAction::SendWarningMessage { msg, .. },
					..
				} => {
					assert_eq!(msg.channel_id, ChannelId([0; 32]));
					assert_eq!(msg.data, "Peer backup was not stored; storage is unavailable or a limit was reached.");
				},
				_ => panic!("expected a nonfatal storage warning"),
			}
		}
		assert!(blobs.merge_events(vec![]).is_empty());
	}

	#[test]
	fn channel_wrapper_delegates_and_refuses_storage_without_a_channel() {
		let path = random_storage_path();
		let mut builder = Builder::new();
		builder.set_storage_dir_path(path.to_string_lossy().to_string());
		let node = builder.build().unwrap();
		let handler = PeerStorageChannelHandler::new(
			Arc::clone(&node.channel_manager),
			Arc::clone(&node.kv_store),
			true,
		);
		assert_eq!(handler.provided_node_features(), node.channel_manager.provided_node_features());
		assert_eq!(handler.get_chain_hashes(), node.channel_manager.get_chain_hashes());
		handler.handle_peer_storage(peer(1), msgs::PeerStorage { data: vec![9; MAX_BLOB_BYTES] });
		assert_eq!(handler.blobs.lock().unwrap().read(peer(1)).unwrap(), None);
		assert!(handler.get_and_clear_pending_msg_events().is_empty());
		let now = Instant::now();
		for _ in 0..PEER_WRITE_BURST {
			assert!(handler.blobs.lock().unwrap().write_limits.allow(peer(1), now));
		}
		handler
			.peer_connected(
				peer(1),
				&msgs::Init {
					features: handler.provided_init_features(peer(1)),
					networks: None,
					remote_network_address: None,
				},
				false,
			)
			.unwrap();
		handler.peer_disconnected(peer(1));
		assert!(!handler.blobs.lock().unwrap().write_limits.allow(peer(1), now));
		let disabled = PeerStorageChannelHandler::new(
			Arc::clone(&node.channel_manager),
			Arc::clone(&node.kv_store),
			false,
		);
		assert_eq!(
			disabled.provided_init_features(peer(1)),
			node.channel_manager.provided_init_features(peer(1))
		);
		assert!(disabled.get_and_clear_pending_msg_events().is_empty());
		disabled.message_received();
		drop(disabled);
		drop(handler);
		drop(node);
		// SqliteStore's test-only Drop removes its directory.
		assert!(!path.exists());
	}
}
