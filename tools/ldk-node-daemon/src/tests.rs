use super::*;
use ldk_node::lightning::ln::channelmanager::PaymentId;
use ldk_node::lightning::types::payment::{PaymentHash, PaymentPreimage};
use std::fs;
use std::io::{BufReader, Cursor, Read};
use std::net::TcpListener;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::sync::atomic::AtomicU64;

static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temp(PathBuf);
impl Temp {
	fn new() -> Self {
		let path = std::env::temp_dir().join(format!(
			"ldk-daemon-test-{}-{}-{}",
			std::process::id(),
			timestamp(),
			NEXT.fetch_add(1, Ordering::Relaxed)
		));
		fs::create_dir(&path).unwrap();
		fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
		Self(path)
	}
}
impl Drop for Temp {
	fn drop(&mut self) {
		let _ = fs::remove_dir_all(&self.0);
	}
}
fn configuration(path: &Path) -> config::Config {
	serde_json::from_value(json!({"network":"regtest","data_dir":path,"alias":"Test primary","listen_address":"127.0.0.1:9735","chain_source":{"type":"bitcoind","host":"127.0.0.1","port":18443,"user":"user","password":"test-only"}})).unwrap()
}
fn received() -> Event {
	Event::PaymentReceived {
		payment_id: Some(PaymentId([3; 32])),
		payment_hash: PaymentHash([4; 32]),
		amount_msat: 12_000,
		custom_records: vec![],
	}
}

#[test]
fn explicit_network_policy_and_unknown_config_fields() {
	let temp = Temp::new();
	let mut cfg = configuration(&temp.0);
	cfg.validate().unwrap();
	assert!(!cfg.chicory.enabled);
	assert_eq!(cfg.chicory.max_client_funding_sats, 500_000);
	cfg.chicory.enabled = true;
	cfg.validate().unwrap();
	cfg.network = "mainnet".into();
	assert!(cfg.validate().is_err());
	let mut value = serde_json::to_value(configuration(&temp.0)).unwrap();
	value["chicory"]["offline_enabled"] = json!(true);
	assert!(serde_json::from_value::<config::Config>(value).is_err());
	let mut value = serde_json::to_value(configuration(&temp.0)).unwrap();
	value["secret_debug"] = json!(true);
	assert!(serde_json::from_value::<config::Config>(value).is_err());
}

#[test]
fn trusted_splice_peers_are_explicit_validated_and_survive_config_restart() {
	let temp = Temp::new();
	let cfg = configuration(&temp.0);
	assert!(cfg.policy().trusted_splice_peer_pubkeys.is_empty());
	let peer = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
	let mut value = serde_json::to_value(cfg).unwrap();
	value["chicory"]["enabled"] = json!(true);
	value["chicory"]["trusted_splice_peer_pubkeys"] = json!([peer.to_uppercase()]);
	let cfg: config::Config = serde_json::from_value(value.clone()).unwrap();
	cfg.validate().unwrap();
	let path = temp.0.join("config.json");
	config::atomic_write(&path, &serde_json::to_vec(&cfg).unwrap()).unwrap();
	let restored = config::Config::read(&path).unwrap();
	assert_eq!(restored.policy().trusted_splice_peer_pubkeys, vec![peer.parse().unwrap()]);
	assert_eq!(
		serde_json::to_value(&restored).unwrap()["chicory"]["trusted_splice_peer_pubkeys"],
		json!([peer])
	);
	assert_eq!(restored.policy().inbound_splice_minimum_depth, 6);
	for invalid in [
		json!([peer, peer.to_uppercase()]),
		json!(["02"]),
		json!(["020000000000000000000000000000000000000000000000000000000000000000"]),
		json!([format!("04{}{}", &peer[2..], &peer[2..])]),
		json!(vec![peer; 129]),
	] {
		value["chicory"]["trusted_splice_peer_pubkeys"] = invalid;
		assert!(serde_json::from_value::<config::Config>(value.clone()).is_err());
	}
}

#[test]
fn process_lock_network_binding_and_existing_state_are_enforced() {
	let temp = Temp::new();
	let cfg = configuration(&temp.0.join("node"));
	let lock = cfg.lock_directory().unwrap();
	assert!(cfg.lock_directory().is_err());
	drop(lock);
	let lock = cfg.lock_directory().unwrap();
	drop(lock);
	let mut other = cfg.clone();
	other.network = "bitcoin".into();
	assert!(other.lock_directory().unwrap_err().contains("different network"));
	let other = configuration(&temp.0.join("existing"));
	fs::create_dir(&other.data_dir).unwrap();
	fs::set_permissions(&other.data_dir, fs::Permissions::from_mode(0o700)).unwrap();
	fs::write(other.data_dir.join("seed"), [5; 64]).unwrap();
	assert!(other.lock_directory().unwrap_err().contains("migration"));
}

#[test]
fn private_file_reader_rejects_permissions_symlinks_and_oversize() {
	let temp = Temp::new();
	let path = temp.0.join("private");
	config::atomic_write(&path, b"private").unwrap();
	assert_eq!(config::read_private(&path, 7).unwrap(), b"private");
	assert!(config::read_private(&path, 6).is_err());
	symlink(&path, temp.0.join("link")).unwrap();
	assert!(config::read_private(&temp.0.join("link"), 100).is_err());
	fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
	assert!(config::read_private(&path, 100).is_err());
}

#[test]
fn administration_frames_are_bounded_and_require_newlines() {
	assert!(read_request(&mut Cursor::new(vec![b'x'; MAX_REQUEST + 1])).is_err());
	assert!(read_request(&mut Cursor::new(b"{}".to_vec())).is_err());
	let mut reader = Cursor::new(b"{}\n{}\n".to_vec());
	assert_eq!(read_request(&mut reader).unwrap(), Some(b"{}\n".to_vec()));
	assert_eq!(read_request(&mut reader).unwrap(), Some(b"{}\n".to_vec()));
	assert_eq!(read_request(&mut reader).unwrap(), None);
}

#[test]
fn amounts_preserve_precision_and_reject_invalid_numeric_inputs() {
	for value in [json!(-1), json!(1.5), json!(JS_MAX_INTEGER + 1), json!("1e6"), json!("+2")] {
		let mut p = Map::new();
		p.insert("amount".into(), value);
		assert!(integer(&p, "amount").is_err());
	}
	let mut p = Map::new();
	p.insert("amount".into(), json!(u64::MAX.to_string()));
	assert_eq!(integer(&p, "amount").unwrap(), u64::MAX);
	assert_eq!(money(u64::MAX), json!(u64::MAX.to_string()));
	assert_eq!(money(42), json!(42));
	p.insert("send_all".into(), json!("false"));
	assert!(flag(&p, "send_all", false).is_err());
}

#[test]
fn history_redacts_preimages_and_does_not_advance_on_failed_write() {
	let temp = Temp::new();
	let mut history = History::open(&temp.0).unwrap();
	let event = Event::PaymentSuccessful {
		payment_id: Some(PaymentId([3; 32])),
		payment_hash: PaymentHash([4; 32]),
		payment_preimage: Some(PaymentPreimage([17; 32])),
		fee_paid_msat: Some(100),
	};
	let serialized = public_event(&event).to_string();
	assert!(!serialized.contains("preimage") && !serialized.contains(&hex(&[17; 32])));
	history.append(&event).unwrap();
	let mut restored = History::open(&temp.0).unwrap();
	assert_eq!(restored.records.len(), 1);
	assert_eq!(restored.next_id, 2);
	let target = temp.0.join("untouched");
	fs::write(&target, b"original").unwrap();
	symlink(&target, temp.0.join("daemon-events.pending")).unwrap();
	assert!(restored.append(&received()).is_err());
	assert_eq!(restored.records.len(), 1);
	assert_eq!(restored.next_id, 2);
	assert_eq!(fs::read(&target).unwrap(), b"original");
}

fn rpc_server(genesis: &str) -> (u16, thread::JoinHandle<()>) {
	let listener = TcpListener::bind("127.0.0.1:0").unwrap();
	let port = listener.local_addr().unwrap().port();
	let genesis = genesis.to_owned();
	let worker = thread::spawn(move || {
		let (mut socket, _) = listener.accept().unwrap();
		socket.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
		let mut reader = BufReader::new(socket.try_clone().unwrap());
		let mut length = 0;
		loop {
			let mut line = String::new();
			reader.read_line(&mut line).unwrap();
			if line == "\r\n" {
				break;
			}
			if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
				length = value.trim().parse::<usize>().unwrap();
			}
		}
		let mut request = vec![0; length];
		reader.read_exact(&mut request).unwrap();
		let request: Value = serde_json::from_slice(&request).unwrap();
		assert_eq!(request["method"], "getblockhash");
		assert_eq!(request["params"], json!([0]));
		let body = json!({"result":genesis,"error":null,"id":1}).to_string();
		write!(socket,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
	});
	(port, worker)
}

#[test]
fn backend_genesis_is_checked_before_loading_wallet_keys() {
	let temp = Temp::new();
	let mut cfg = configuration(&temp.0);
	for (genesis, expected) in [
		(
			ldk_node::bitcoin::blockdata::constants::genesis_block(
				ldk_node::bitcoin::Network::Regtest,
			)
			.block_hash()
			.to_string(),
			true,
		),
		("00".repeat(32), false),
	] {
		let (port, worker) = rpc_server(&genesis);
		if let config::ChainSource::Bitcoind { port: current, .. } = &mut cfg.chain_source {
			*current = port;
		}
		assert_eq!(cfg.verify_chain().is_ok(), expected);
		worker.join().unwrap();
	}
	assert!(!temp.0.join("keys_seed").exists());
}
