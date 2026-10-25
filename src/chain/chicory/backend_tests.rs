//! Exercise the actual configured-client parsers over bounded local sockets.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::encode::{serialize, serialize_hex};
use bitcoin::hashes::Hash;
use bitcoin::hex::DisplayHex;
use bitcoin::{Block, BlockHash, MerkleBlock, Network, OutPoint, ScriptBuf, Transaction};
use electrum_client::{Client, ConfigBuilder};
use lightning::chain::BestBlock;
use serde_json::{json, Value};

use super::super::bitcoind::BitcoindChainSource;
use super::super::electrum::confirmed_electrum_transaction;
use super::super::esplora::EsploraChainSource;
use crate::config::{AddressTypeRuntimeConfig, Config, EsploraSyncConfig};
use crate::fee_estimator::OnchainFeeEstimator;
use crate::io::test_utils::InMemoryStore;
use crate::logger::Logger;
use crate::runtime::Runtime;
use crate::NodeMetrics;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Case {
	Valid,
	FiveConfirmations,
	WrongInitialTip,
	ReorgAtEnd,
	ChangedBlockAtEnd,
	WrongTransaction,
	BadMerkle,
	BadPosition,
	WrongProofHeight,
	WrongParent,
}

#[derive(Clone)]
struct Fixture {
	parent: Transaction,
	tx: Transaction,
	block: Block,
	tip_header: bitcoin::block::Header,
	tip: BestBlock,
	height: u32,
}
impl Fixture {
	fn new(case: Case) -> Self {
		let mut block = genesis_block(Network::Regtest);
		let parent = block.txdata[0].clone();
		let mut tx = parent.clone();
		tx.input[0].previous_output = OutPoint { txid: parent.compute_txid(), vout: 0 };
		tx.input[0].script_sig = ScriptBuf::new();
		// The conflict is discoverable through the spent parent, even though its
		// only output is provably unspendable and need not have indexed history.
		tx.output[0].script_pubkey = ScriptBuf::new_op_return([1]);
		block.txdata = vec![tx.clone()];
		block.header.merkle_root = block.compute_merkle_root().unwrap();
		let mut tip_header = block.header;
		tip_header.prev_blockhash = block.block_hash();
		tip_header.nonce = tip_header.nonce.wrapping_add(1);
		let tip = BestBlock::new(tip_header.block_hash(), 100);
		Self {
			parent,
			tx,
			block,
			tip_header,
			tip,
			height: if case == Case::FiveConfirmations { 96 } else { 95 },
		}
	}
	fn header_json(&self) -> Value {
		let header = self.block.header;
		json!({"version": header.version.to_consensus(), "previousblockhash": header.prev_blockhash,
			"merkleroot": header.merkle_root, "time": header.time, "bits": format!("{:08x}", header.bits.to_consensus()),
			"nonce": header.nonce, "height": self.height, "chainwork": "00".repeat(31) + "01"})
	}
	fn merkle_hex(&self, bad: bool) -> String {
		let mut proof =
			MerkleBlock::from_block_with_predicate(&self.block, |id| *id == self.tx.compute_txid());
		if bad {
			proof.header.merkle_root = bitcoin::TxMerkleNode::all_zeros();
		}
		serialize_hex(&proof)
	}
}

/// Servers accept only small test requests and have finite read/accept lifetimes.
struct Server {
	addr: SocketAddr,
	count: Arc<AtomicUsize>,
	stop: Arc<AtomicBool>,
	worker: Option<JoinHandle<()>>,
}
impl Server {
	fn new(http: bool, answer: impl Fn(&str, &Value, usize) -> Vec<u8> + Send + 'static) -> Self {
		let listener = TcpListener::bind("127.0.0.1:0").unwrap();
		listener.set_nonblocking(true).unwrap();
		let addr = listener.local_addr().unwrap();
		let stop = Arc::new(AtomicBool::new(false));
		let count = Arc::new(AtomicUsize::new(0));
		let stopping = Arc::clone(&stop);
		let requests = Arc::clone(&count);
		let worker = thread::spawn(move || {
			while !stopping.load(Ordering::Acquire) {
				let (mut stream, _) = match listener.accept() {
					Ok(pair) => pair,
					Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
						thread::sleep(Duration::from_millis(2));
						continue;
					},
					Err(error) => panic!("fixture accept: {error}"),
				};
				stream.set_nonblocking(false).unwrap();
				stream.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
				stream.set_write_timeout(Some(Duration::from_secs(2))).unwrap();
				let mut reader = BufReader::new(stream.try_clone().unwrap());
				loop {
					let mut line = String::new();
					match reader.read_line(&mut line) {
						Ok(0) | Err(_) => break,
						Ok(_) => {},
					}
					assert!(line.len() <= 4096);
					let (path, request) = if http {
						let path = line.split_whitespace().nth(1).unwrap().to_owned();
						let mut content_length = 0;
						for _ in 0..64 {
							line.clear();
							reader.read_line(&mut line).unwrap();
							if line == "\r\n" {
								break;
							}
							assert!(line.len() <= 4096);
							if let Some(value) =
								line.to_ascii_lowercase().strip_prefix("content-length:")
							{
								content_length = value.trim().parse::<usize>().unwrap();
							}
						}
						assert!(content_length <= 4096);
						let mut body = vec![0; content_length];
						reader.read_exact(&mut body).unwrap();
						(
							path,
							if body.is_empty() {
								Value::Null
							} else {
								serde_json::from_slice(&body).unwrap()
							},
						)
					} else {
						(String::new(), serde_json::from_str(&line).unwrap())
					};
					let n = requests.fetch_add(1, Ordering::AcqRel);
					assert!(n < 16, "unbounded proof requests");
					let body = answer(&path, &request, n);
					if http {
						write!(
							stream,
							"HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
							body.len()
						)
						.unwrap();
						stream.write_all(&body).unwrap();
						break;
					} else {
						stream.write_all(&body).unwrap();
						stream.write_all(b"\n").unwrap();
					}
				}
			}
		});
		Self { addr, stop, count, worker: Some(worker) }
	}
}
impl Drop for Server {
	fn drop(&mut self) {
		self.stop.store(true, Ordering::Release);
		self.worker.take().unwrap().join().unwrap();
	}
}

#[test]
fn conflict_electrum_proof_checks_identity_merkle_depth_and_reorg() {
	for case in [
		Case::Valid,
		Case::FiveConfirmations,
		Case::WrongInitialTip,
		Case::ReorgAtEnd,
		Case::ChangedBlockAtEnd,
		Case::WrongTransaction,
		Case::BadMerkle,
		Case::BadPosition,
		Case::WrongProofHeight,
		Case::WrongParent,
	] {
		let fixture = Fixture::new(case);
		let data = fixture.clone();
		let server = Server::new(false, move |_, request, n| {
			let result = match request["method"].as_str().unwrap() {
				"blockchain.block.header" => {
					let height = request["params"][0].as_u64().unwrap() as u32;
					let mut header =
						if height == 100 { data.tip_header } else { data.block.header };
					if case == Case::WrongInitialTip
						|| case == Case::ReorgAtEnd && height == 100 && n > 0
						|| case == Case::ChangedBlockAtEnd && height != 100 && n > 6
					{
						header.nonce = header.nonce.wrapping_add(2);
					}
					json!(serialize_hex(&header))
				},
				"blockchain.transaction.get" => {
					let parent = request["params"][0] == data.parent.compute_txid().to_string();
					let tx = if parent {
						if case == Case::WrongParent {
							&data.tx
						} else {
							&data.parent
						}
					} else if case == Case::WrongTransaction {
						&data.parent
					} else {
						&data.tx
					};
					json!(serialize_hex(tx))
				},
				"blockchain.scripthash.get_history" => {
					let hash = bitcoin::hashes::sha256::Hash::hash(
						data.parent.output[0].script_pubkey.as_bytes(),
					);
					let mut raw = hash.to_byte_array();
					raw.reverse();
					assert_eq!(request["params"][0], raw.as_hex().to_string());
					json!([{"tx_hash": data.tx.compute_txid(), "height": data.height}])
				},
				"blockchain.transaction.get_merkle" => {
					json!({"block_height": if case == Case::WrongProofHeight { data.height + 1 } else { data.height },
					"pos": if case == Case::BadPosition { 1 } else { 0 },
					"merkle": if case == Case::BadMerkle { vec!["00".repeat(32)] } else { vec![] }})
				},
				other => panic!("unexpected Electrum call {other}"),
			};
			serde_json::to_vec(&json!({"id": request["id"], "jsonrpc":"2.0", "result": result}))
				.unwrap()
		});
		let client = Client::from_config(
			&format!("tcp://{}", server.addr),
			ConfigBuilder::new().retry(0).timeout(Some(1)).build(),
		)
		.unwrap();
		let result = confirmed_electrum_transaction(
			&client,
			fixture.tx.compute_txid(),
			fixture.tip,
			Instant::now() + Duration::from_secs(3),
		);
		assert_eq!(
			result.is_ok(),
			case == Case::Valid,
			"{case:?}, error: {:?}, requests: {}",
			result.as_ref().err(),
			server.count.load(Ordering::Acquire)
		);
		if let Ok(proof) = result {
			assert_eq!(proof.transaction, fixture.tx);
			assert_eq!(proof.block_hash, fixture.block.block_hash());
		}
		assert!(server.count.load(Ordering::Acquire) <= 8);
		drop(client);
	}
}

#[test]
fn conflict_electrum_expired_deadline_sends_no_requests() {
	let server = Server::new(false, |_, _, _| panic!("expired deadline must not query"));
	let client = Client::from_config(
		&format!("tcp://{}", server.addr),
		ConfigBuilder::new().retry(0).timeout(Some(1)).build(),
	)
	.unwrap();
	let fixture = Fixture::new(Case::Valid);
	assert!(confirmed_electrum_transaction(
		&client,
		fixture.tx.compute_txid(),
		fixture.tip,
		Instant::now()
	)
	.is_err());
	assert_eq!(server.count.load(Ordering::Acquire), 0);
	drop(client);
}

#[test]
fn conflict_electrum_stalled_socket_is_bounded_and_does_not_retry() {
	let fixture = Fixture::new(Case::Valid);
	let header = fixture.tip_header;
	let server = Server::new(false, move |_, request, _| {
		thread::sleep(Duration::from_millis(1500));
		serde_json::to_vec(&json!({"id": request["id"], "result": serialize_hex(&header)})).unwrap()
	});
	let client = Client::from_config(
		&format!("tcp://{}", server.addr),
		ConfigBuilder::new().retry(0).timeout(Some(1)).build(),
	)
	.unwrap();
	let started = Instant::now();
	assert!(confirmed_electrum_transaction(
		&client,
		fixture.tx.compute_txid(),
		fixture.tip,
		started + Duration::from_secs(3),
	)
	.is_err());
	assert!(started.elapsed() < Duration::from_secs(3));
	assert_eq!(server.count.load(Ordering::Acquire), 1);
	// Keep the client socket alive while the finite server callback completes.
	drop(server);
	drop(client);
}

#[test]
fn conflict_esplora_proof_checks_identity_merkle_depth_and_reorg() {
	for case in [
		Case::Valid,
		Case::FiveConfirmations,
		Case::WrongInitialTip,
		Case::ReorgAtEnd,
		Case::ChangedBlockAtEnd,
		Case::WrongTransaction,
		Case::BadMerkle,
	] {
		let fixture = Fixture::new(case);
		let data = fixture.clone();
		let server = Server::new(true, move |path, _, n| {
			if path == "/block-height/100" {
				return if case == Case::WrongInitialTip || case == Case::ReorgAtEnd && n > 0 {
					BlockHash::all_zeros().to_string()
				} else {
					data.tip.block_hash.to_string()
				}
				.into_bytes();
			}
			if path.starts_with("/block-height/") {
				return if case == Case::ChangedBlockAtEnd && n > 5 {
					BlockHash::all_zeros().to_string()
				} else {
					data.block.block_hash().to_string()
				}
				.into_bytes();
			}
			if path.ends_with("/status") {
				return serde_json::to_vec(&json!({"confirmed":true,"block_height":data.height,"block_hash":data.block.block_hash(),"block_time":1})).unwrap();
			}
			if path.ends_with("/raw") {
				return serialize(if case == Case::WrongTransaction {
					&data.parent
				} else {
					&data.tx
				});
			}
			if path.ends_with("/merkleblock-proof") {
				return data.merkle_hex(case == Case::BadMerkle).into_bytes();
			}
			panic!("unexpected Esplora path {path}");
		});
		let logger = Arc::new(Logger::new_log_facade());
		let runtime = Runtime::new(Arc::clone(&logger)).unwrap();
		let config = Arc::new(Config::default());
		let source = EsploraChainSource::new(
			format!("http://{}", server.addr),
			HashMap::new(),
			EsploraSyncConfig::default(),
			Arc::new(OnchainFeeEstimator::new()),
			Arc::new(InMemoryStore::new()),
			Arc::clone(&config),
			Arc::new(RwLock::new(AddressTypeRuntimeConfig::from_config(&config, vec![]))),
			logger,
			Arc::new(RwLock::new(NodeMetrics::default())),
		);
		let result =
			runtime.block_on(source.confirmed_transaction(fixture.tx.compute_txid(), fixture.tip));
		assert_eq!(result.is_ok(), case == Case::Valid, "{case:?}");
		assert!(server.count.load(Ordering::Acquire) <= 7);
	}
}

#[test]
fn conflict_core_proof_checks_block_merkle_depth_and_reorg() {
	for case in [
		Case::Valid,
		Case::FiveConfirmations,
		Case::WrongInitialTip,
		Case::ReorgAtEnd,
		Case::ChangedBlockAtEnd,
		Case::WrongTransaction,
		Case::BadMerkle,
	] {
		let mut fixture = Fixture::new(case);
		if case == Case::WrongTransaction {
			// A valid, consistent active block whose transaction set does not
			// contain the requested transaction is still not a conflict proof.
			fixture.block.txdata = vec![fixture.parent.clone()];
			fixture.block.header.merkle_root = fixture.block.compute_merkle_root().unwrap();
			fixture.tip_header.prev_blockhash = fixture.block.block_hash();
			fixture.tip = BestBlock::new(fixture.tip_header.block_hash(), 100);
		}
		let data = fixture.clone();
		let server = Server::new(true, move |_, request, n| {
			let result = match request["method"].as_str().unwrap() {
				"getblockhash" => {
					let height = request["params"][0].as_u64().unwrap() as u32;
					let hash = if case == Case::WrongInitialTip
						|| case == Case::ReorgAtEnd && height == 100 && n > 0
						|| case == Case::ChangedBlockAtEnd && height != 100 && n > 5
					{
						BlockHash::all_zeros()
					} else if height == 100 {
						data.tip.block_hash
					} else {
						data.block.block_hash()
					};
					json!(hash)
				},
				"getrawtransaction" => json!({"blockhash":data.block.block_hash()}),
				"getblockheader" => data.header_json(),
				"getblock" => {
					let mut block = data.block.clone();
					if case == Case::BadMerkle {
						block.txdata[0] = data.parent.clone();
					}
					json!(serialize_hex(&block))
				},
				other => panic!("unexpected RPC call {other}"),
			};
			serde_json::to_vec(&json!({"id":request["id"],"result":result,"error":null})).unwrap()
		});
		let logger = Arc::new(Logger::new_log_facade());
		let runtime = Runtime::new(Arc::clone(&logger)).unwrap();
		let source = BitcoindChainSource::new_rpc(
			"127.0.0.1".to_owned(),
			server.addr.port(),
			"test".to_owned(),
			"test".to_owned(),
			Arc::new(OnchainFeeEstimator::new()),
			Arc::new(InMemoryStore::new()),
			Arc::new(Config::default()),
			logger,
			Arc::new(RwLock::new(NodeMetrics::default())),
		);
		let result =
			runtime.block_on(source.confirmed_transaction(fixture.tx.compute_txid(), fixture.tip));
		assert_eq!(result.is_ok(), case == Case::Valid, "{case:?}");
		assert!(server.count.load(Ordering::Acquire) <= 7);
	}
}
