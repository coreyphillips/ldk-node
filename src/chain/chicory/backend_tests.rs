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
use super::super::electrum::{
	confirmed_electrum_transaction, electrum_transaction_status, ElectrumChainSource,
};
use super::super::esplora::EsploraChainSource;
use crate::config::{AddressTypeRuntimeConfig, Config, ElectrumSyncConfig, EsploraSyncConfig};
use crate::fee_estimator::OnchainFeeEstimator;
use crate::io::test_utils::InMemoryStore;
use crate::logger::Logger;
use crate::payment::ConfirmationStatus;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatusCase {
	Confirmed,
	Unconfirmed,
	Unknown,
	WrongTransaction,
	BadMerkle,
	Reorg,
	Inconsistent,
	WrongTimestamp,
}

fn assert_transaction_status(
	result: Result<ConfirmationStatus, crate::Error>, case: StatusCase, fixture: &Fixture,
) {
	match case {
		StatusCase::Confirmed => assert_eq!(
			result,
			Ok(ConfirmationStatus::Confirmed {
				block_hash: fixture.block.block_hash(),
				height: fixture.height,
				timestamp: u64::from(fixture.block.header.time),
			})
		),
		StatusCase::Unconfirmed => assert_eq!(result, Ok(ConfirmationStatus::Unconfirmed)),
		_ => assert!(result.is_err(), "uncertain status must fail: {case:?}, {result:?}"),
	}
}

#[test]
fn transaction_status_electrum_checks_presence_identity_proof_and_reorg() {
	for case in [
		StatusCase::Confirmed,
		StatusCase::Unconfirmed,
		StatusCase::Unknown,
		StatusCase::WrongTransaction,
		StatusCase::BadMerkle,
		StatusCase::Reorg,
		StatusCase::Inconsistent,
	] {
		let fixture = Fixture::new(Case::Valid);
		let data = fixture.clone();
		let server = Server::new(false, move |_, request, n| {
			let result = match request["method"].as_str().unwrap() {
				"blockchain.transaction.get" => {
					let parent = request["params"][0] == data.parent.compute_txid().to_string();
					json!(serialize_hex(if parent || case == StatusCase::WrongTransaction {
						&data.parent
					} else {
						&data.tx
					}))
				},
				"blockchain.scripthash.get_history" => {
					if case == StatusCase::Unknown {
						json!([])
					} else if case == StatusCase::Inconsistent {
						json!([
							{"tx_hash":data.tx.compute_txid(),"height":data.height},
							{"tx_hash":data.tx.compute_txid(),"height":0}
						])
					} else {
						json!([{"tx_hash":data.tx.compute_txid(),"height":if case == StatusCase::Unconfirmed { 0 } else { data.height }}])
					}
				},
				"blockchain.transaction.get_merkle" => json!({"block_height":data.height,"pos":0,
					"merkle":if case == StatusCase::BadMerkle { vec!["00".repeat(32)] } else { vec![] }}),
				"blockchain.block.header" => {
					let mut header = data.block.header;
					if case == StatusCase::Reorg && n > 4 {
						header.nonce = header.nonce.wrapping_add(1);
					}
					json!(serialize_hex(&header))
				},
				other => panic!("unexpected Electrum status request {other}"),
			};
			serde_json::to_vec(&json!({"id":request["id"],"result":result})).unwrap()
		});
		let client = Client::from_config(
			&format!("tcp://{}", server.addr),
			ConfigBuilder::new().retry(0).timeout(Some(1)).build(),
		)
		.unwrap();
		assert_transaction_status(
			electrum_transaction_status(
				&client,
				fixture.tx.compute_txid(),
				Instant::now() + Duration::from_secs(3),
			),
			case,
			&fixture,
		);
		assert!(server.count.load(Ordering::Acquire) <= 7);
		drop(client);
	}
}

#[test]
fn transaction_status_electrum_expired_deadline_sends_no_requests() {
	let server = Server::new(false, |_, _, _| panic!("expired status lookup must not query"));
	let client = Client::from_config(
		&format!("tcp://{}", server.addr),
		ConfigBuilder::new().retry(0).timeout(Some(1)).build(),
	)
	.unwrap();
	let fixture = Fixture::new(Case::Valid);
	assert!(
		electrum_transaction_status(&client, fixture.tx.compute_txid(), Instant::now()).is_err()
	);
	assert_eq!(server.count.load(Ordering::Acquire), 0);
	drop(client);
}

#[test]
fn transaction_status_esplora_checks_presence_identity_proof_and_reorg() {
	for case in [
		StatusCase::Confirmed,
		StatusCase::Unconfirmed,
		StatusCase::Unknown,
		StatusCase::WrongTransaction,
		StatusCase::BadMerkle,
		StatusCase::Reorg,
		StatusCase::Inconsistent,
		StatusCase::WrongTimestamp,
	] {
		let fixture = Fixture::new(Case::Valid);
		let data = fixture.clone();
		let server = Server::new(true, move |path, _, n| {
			if path.ends_with("/raw") {
				return if case == StatusCase::Unknown {
					vec![]
				} else {
					serialize(if case == StatusCase::WrongTransaction {
						&data.parent
					} else {
						&data.tx
					})
				};
			}
			if path.ends_with("/status") {
				return serde_json::to_vec(&if case == StatusCase::Unconfirmed { json!({"confirmed":false}) }
					else { json!({"confirmed":case != StatusCase::Inconsistent,"block_height":data.height,
						"block_hash":data.block.block_hash(),"block_time":if case == StatusCase::WrongTimestamp { 1 } else { data.block.header.time }}) }).unwrap();
			}
			if path.ends_with("/merkleblock-proof") {
				return data.merkle_hex(case == StatusCase::BadMerkle).into_bytes();
			}
			if path.starts_with("/block-height/") {
				return if case == StatusCase::Reorg && n > 2 {
					BlockHash::all_zeros()
				} else {
					data.block.block_hash()
				}
				.to_string()
				.into_bytes();
			}
			panic!("unexpected Esplora status request {path}");
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
		assert_transaction_status(
			runtime.block_on(source.fetch_transaction_status(fixture.tx.compute_txid())),
			case,
			&fixture,
		);
		assert!(server.count.load(Ordering::Acquire) <= 5);
	}
}

#[test]
fn transaction_status_core_checks_mempool_identity_proof_and_reorg() {
	for case in [
		StatusCase::Confirmed,
		StatusCase::Unconfirmed,
		StatusCase::Unknown,
		StatusCase::WrongTransaction,
		StatusCase::BadMerkle,
		StatusCase::Reorg,
		StatusCase::Inconsistent,
		StatusCase::WrongTimestamp,
	] {
		let fixture = Fixture::new(Case::Valid);
		let data = fixture.clone();
		let server = Server::new(true, move |_, request, n| {
			let result = match request["method"].as_str().unwrap() {
				"getrawtransaction" => {
					let hex = serialize_hex(if case == StatusCase::WrongTransaction {
						&data.parent
					} else {
						&data.tx
					});
					if case == StatusCase::Unconfirmed || case == StatusCase::Unknown {
						json!({"hex":hex})
					} else {
						json!({"hex":hex,"blockhash":data.block.block_hash(),
						"confirmations":if case == StatusCase::Inconsistent { 0 } else { 1 },
						"blocktime":if case == StatusCase::WrongTimestamp { 1 } else { data.block.header.time }})
					}
				},
				"getmempoolentry" => {
					if case == StatusCase::Unknown {
						return serde_json::to_vec(&json!({"id":request["id"],"result":null,
						"error":{"code":-5,"message":"Transaction not in mempool"}}))
						.unwrap();
					}
					json!({"vsize":100})
				},
				"getblockheader" => data.header_json(),
				"getblockhash" => json!(if case == StatusCase::Reorg && n > 2 {
					BlockHash::all_zeros()
				} else {
					data.block.block_hash()
				}),
				"getblock" => {
					let mut block = data.block.clone();
					if case == StatusCase::BadMerkle {
						block.txdata[0] = data.parent.clone();
					}
					json!(serialize_hex(&block))
				},
				other => panic!("unexpected RPC status request {other}"),
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
		assert_transaction_status(
			runtime.block_on(source.fetch_transaction_status(fixture.tx.compute_txid())),
			case,
			&fixture,
		);
		assert!(server.count.load(Ordering::Acquire) <= 5);
	}
}

#[test]
fn direct_funding_core_unspent_requires_exact_value_script_and_mempool_awareness() {
	for case in 0..5 {
		let fixture = Fixture::new(Case::Valid);
		let output = fixture.parent.output[0].clone();
		let outpoint = OutPoint { txid: fixture.parent.compute_txid(), vout: 0 };
		let expected = output.clone();
		let server = Server::new(true, move |_, request, _| {
			assert_eq!(request["method"], "gettxout");
			assert_eq!(request["params"], json!([outpoint.txid.to_string(), 0, true]));
			let result = match case {
				1 => Value::Null,
				2 => json!({"scriptPubKey":{"hex":"00"},"value":expected.value.to_btc()}),
				3 => {
					json!({"scriptPubKey":{"hex":expected.script_pubkey.to_hex_string()},"value":expected.value.to_btc() + 0.00000001})
				},
				4 => json!({"scriptPubKey":{"hex":expected.script_pubkey.to_hex_string()}}),
				_ => {
					json!({"scriptPubKey":{"hex":expected.script_pubkey.to_hex_string()},"value":expected.value.to_btc()})
				},
			};
			serde_json::to_vec(&json!({"id":request["id"],"result":result,"error":null})).unwrap()
		});
		let logger = Arc::new(Logger::new_log_facade());
		let runtime = Runtime::new(logger.clone()).unwrap();
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
		let result = runtime.block_on(source.is_unspent_output(outpoint, output));
		match case {
			0 => assert_eq!(result, Ok(true)),
			1 => assert_eq!(result, Ok(false)),
			_ => assert!(result.is_err()),
		}
		assert_eq!(server.count.load(Ordering::Acquire), 1);
	}
}

#[test]
fn direct_funding_esplora_unspent_requires_output_and_positive_spend_status() {
	for case in 0..4 {
		let fixture = Fixture::new(Case::Valid);
		let output = fixture.tx.output[0].clone();
		let outpoint = OutPoint { txid: fixture.tx.compute_txid(), vout: 0 };
		let mut transaction = fixture.tx.clone();
		if case == 3 {
			transaction.output[0].value = bitcoin::Amount::from_sat(1);
		}
		let server = Server::new(true, move |path, _, _| {
			if path == format!("/tx/{}/raw", outpoint.txid) {
				return serialize(&transaction);
			}
			assert_eq!(path, format!("/tx/{}/outspend/0", outpoint.txid));
			serde_json::to_vec(&match case {
				1 => json!({"spent":true}),
				2 => json!({}),
				_ => json!({"spent":false}),
			})
			.unwrap()
		});
		let logger = Arc::new(Logger::new_log_facade());
		let runtime = Runtime::new(logger.clone()).unwrap();
		let config = Arc::new(Config::default());
		let source = EsploraChainSource::new(
			format!("http://{}", server.addr),
			HashMap::new(),
			EsploraSyncConfig::default(),
			Arc::new(OnchainFeeEstimator::new()),
			Arc::new(InMemoryStore::new()),
			config.clone(),
			Arc::new(RwLock::new(AddressTypeRuntimeConfig::from_config(&config, vec![]))),
			logger,
			Arc::new(RwLock::new(NodeMetrics::default())),
		);
		let result = runtime.block_on(source.is_unspent_output(outpoint, output));
		match case {
			0 => assert_eq!(result, Ok(true)),
			1 => assert_eq!(result, Ok(false)),
			_ => assert!(result.is_err()),
		}
		assert!(server.count.load(Ordering::Acquire) <= 2);
	}
}

#[test]
fn direct_funding_electrum_unspent_requires_exact_script_outpoint_and_value() {
	for case in 0..5 {
		let fixture = Fixture::new(Case::Valid);
		let output = fixture.parent.output[0].clone();
		let outpoint = OutPoint { txid: fixture.parent.compute_txid(), vout: 0 };
		let expected = output.clone();
		let server = Server::new(false, move |_, request, _| {
			assert_eq!(request["method"], "blockchain.scripthash.listunspent");
			let mut hash = bitcoin::hashes::sha256::Hash::hash(expected.script_pubkey.as_bytes())
				.to_byte_array();
			hash.reverse();
			assert_eq!(request["params"][0], hash.as_hex().to_string());
			let coins = if case == 1 {
				json!([])
			} else {
				json!([{
					"tx_hash":if case == 2 { fixture.tx.compute_txid() } else { outpoint.txid },
					"tx_pos":if case == 3 { 1 } else { 0 }, "height":95,
					"value":if case == 4 { 1 } else { expected.value.to_sat() }
				}])
			};
			serde_json::to_vec(&json!({"jsonrpc":"2.0","id":request["id"],"result":coins})).unwrap()
		});
		let logger = Arc::new(Logger::new_log_facade());
		let runtime = Runtime::new(logger.clone()).unwrap();
		let config = Arc::new(Config::default());
		let source = ElectrumChainSource::new(
			format!("tcp://{}", server.addr),
			ElectrumSyncConfig::default(),
			Arc::new(OnchainFeeEstimator::new()),
			Arc::new(InMemoryStore::new()),
			config.clone(),
			Arc::new(RwLock::new(AddressTypeRuntimeConfig::from_config(&config, vec![]))),
			logger,
			Arc::new(RwLock::new(NodeMetrics::default())),
		);
		source.start(runtime.handle().clone()).unwrap();
		assert_eq!(runtime.block_on(source.is_unspent_output(outpoint, output)), Ok(case == 0));
		source.stop();
		assert_eq!(server.count.load(Ordering::Acquire), 1);
	}
}
