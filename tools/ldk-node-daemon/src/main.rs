//! Private JSONL administration for one persistent native LDK Node.
//! The parent manager authenticates operators. This process has no HTTP listener.
#![forbid(unsafe_code)]

mod config;

use std::collections::VecDeque;
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ldk_node::bitcoin::{Address, FeeRate};
use ldk_node::lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Description};
use ldk_node::payment::PaymentKind;
use ldk_node::{Event, Node, OnchainSendResult};
use serde::Deserialize;
use serde_json::{json, Map, Value};

const MAX_REQUEST: usize = 256 * 1024;
const MAX_HISTORY: usize = 2048;
const JS_MAX_INTEGER: u64 = 9_007_199_254_740_991;
const METHODS: &[&str] = &[
	"info",
	"balance",
	"channels",
	"payments",
	"peers",
	"address",
	"invoice",
	"pay",
	"estimate_onchain",
	"send_onchain",
	"connect",
	"disconnect",
	"open",
	"close",
	"splice_in",
	"splice_out",
	"sync",
	"offline_status",
	"events",
	"stop",
];

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
	id: Value,
	method: String,
	#[serde(default)]
	params: Map<String, Value>,
}

fn timestamp() -> u64 {
	SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()
}
fn hex(bytes: &[u8]) -> String {
	bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn money(value: u64) -> Value {
	if value <= JS_MAX_INTEGER {
		json!(value)
	} else {
		json!(value.to_string())
	}
}
fn output(value: &Value) -> io::Result<()> {
	let mut stdout = io::stdout().lock();
	serde_json::to_writer(&mut stdout, value)?;
	writeln!(stdout)?;
	stdout.flush()
}
fn text<'a>(params: &'a Map<String, Value>, name: &str) -> Result<&'a str, String> {
	params
		.get(name)
		.and_then(Value::as_str)
		.filter(|s| !s.is_empty() && s.len() <= 16_384)
		.ok_or_else(|| format!("Missing or invalid {name}"))
}
fn integer(params: &Map<String, Value>, name: &str) -> Result<u64, String> {
	let value = params.get(name).ok_or_else(|| format!("Missing {name}"))?;
	let number =
		match value {
			Value::String(s)
				if s.len() <= 20 && !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) =>
			{
				s.parse().ok()
			},
			Value::Number(n) => n.as_u64().filter(|n| *n <= JS_MAX_INTEGER),
			_ => None,
		}
		.ok_or_else(|| {
			format!("{name} must be an exact nonnegative integer; use a decimal string for large values")
		})?;
	Ok(number)
}
fn flag(params: &Map<String, Value>, name: &str, fallback: bool) -> Result<bool, String> {
	match params.get(name) {
		None => Ok(fallback),
		Some(Value::Bool(value)) => Ok(*value),
		_ => Err(format!("{name} must be a boolean")),
	}
}
fn only(params: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
	if params.keys().any(|key| !allowed.contains(&key.as_str())) {
		Err("Unknown operation parameter".into())
	} else {
		Ok(())
	}
}
fn positive(params: &Map<String, Value>, name: &str) -> Result<u64, String> {
	let value = integer(params, name)?;
	if value == 0 {
		Err(format!("{name} must be positive"))
	} else {
		Ok(value)
	}
}
fn fee(params: &Map<String, Value>) -> Result<Option<FeeRate>, String> {
	if !params.contains_key("fee_rate_sat_per_kwu") {
		return Ok(None);
	}
	let value = positive(params, "fee_rate_sat_per_kwu")?;
	if !(253..=25_000_000).contains(&value) {
		return Err("Fee rate is outside the supported range".into());
	}
	Ok(Some(FeeRate::from_sat_per_kwu(value)))
}
fn native(error: ldk_node::NodeError) -> String {
	error.to_string()
}

// Only explicit public fields are persisted or sent to the dashboard. Never Debug an event:
// payment preimages, custom TLVs and untrusted reason payloads can contain private material.
fn public_event(event: &Event) -> Value {
	match event {
		Event::PaymentSuccessful { payment_id, payment_hash, fee_paid_msat, .. } => {
			json!({"kind":"payment_successful","payment_id":payment_id.map(|id| hex(&id.0)),"payment_hash":payment_hash.to_string(),"fee_paid_msat":fee_paid_msat.map(money)})
		},
		Event::PaymentFailed { payment_id, payment_hash, .. } => {
			json!({"kind":"payment_failed","payment_id":payment_id.map(|id| hex(&id.0)),"payment_hash":payment_hash.map(|hash| hash.to_string())})
		},
		Event::PaymentReceived { payment_id, payment_hash, amount_msat, .. } => {
			json!({"kind":"payment_received","payment_id":payment_id.map(|id| hex(&id.0)),"payment_hash":payment_hash.to_string(),"amount_msat":money(*amount_msat)})
		},
		Event::PaymentForwarded {
			prev_channel_id,
			next_channel_id,
			total_fee_earned_msat,
			outbound_amount_forwarded_msat,
			..
		} => {
			json!({"kind":"payment_forwarded","prev_channel_id":prev_channel_id.to_string(),"next_channel_id":next_channel_id.to_string(),"fee_msat":total_fee_earned_msat.map(money),"amount_msat":outbound_amount_forwarded_msat.map(money)})
		},
		Event::ChannelPending { channel_id, counterparty_node_id, funding_txo, .. } => {
			json!({"kind":"channel_pending","channel_id":channel_id.to_string(),"counterparty_node_id":counterparty_node_id.to_string(),"funding_txo":funding_txo.to_string()})
		},
		Event::ChannelReady { channel_id, counterparty_node_id, funding_txo, .. } => {
			json!({"kind":"channel_ready","channel_id":channel_id.to_string(),"counterparty_node_id":counterparty_node_id.map(|id|id.to_string()),"funding_txo":funding_txo.map(|outpoint|outpoint.to_string())})
		},
		Event::ChannelClosed { channel_id, counterparty_node_id, .. } => {
			json!({"kind":"channel_closed","channel_id":channel_id.to_string(),"counterparty_node_id":counterparty_node_id.map(|id|id.to_string())})
		},
		Event::SplicePending { channel_id, new_funding_txo, .. } => {
			json!({"kind":"splice_pending","channel_id":channel_id.to_string(),"funding_txo":new_funding_txo.to_string()})
		},
		Event::SpliceFailed { channel_id, .. } => {
			json!({"kind":"splice_failed","channel_id":channel_id.to_string()})
		},
		Event::PaymentClaimable { payment_id, payment_hash, claimable_amount_msat, .. } => {
			json!({"kind":"payment_claimable","payment_id":hex(&payment_id.0),"payment_hash":payment_hash.to_string(),"amount_msat":money(*claimable_amount_msat)})
		},
		_ => json!({"kind":"node_update"}),
	}
}

struct History {
	path: PathBuf,
	records: VecDeque<Value>,
	next_id: u64,
}
impl History {
	fn open(directory: &Path) -> Result<Self, String> {
		let path = directory.join("daemon-events.json");
		let records: VecDeque<Value> = if path.exists() {
			serde_json::from_slice(&config::read_private(&path, 8 * 1024 * 1024)?)
				.map_err(|_| "Invalid event history")?
		} else {
			VecDeque::new()
		};
		if records.len() > MAX_HISTORY {
			return Err("Oversized event history".into());
		}
		let next_id = records
			.back()
			.and_then(|event| event["sequence"].as_u64())
			.unwrap_or(0)
			.checked_add(1)
			.ok_or("Event sequence exhausted")?;
		Ok(Self { path, records, next_id })
	}
	fn append(&mut self, event: &Event) -> Result<(), String> {
		let mut record = public_event(event);
		record["sequence"] = json!(self.next_id);
		record["timestamp"] = json!(timestamp());
		let mut next = self.records.clone();
		next.push_back(record);
		while next.len() > MAX_HISTORY {
			next.pop_front();
		}
		let next_id = self.next_id.checked_add(1).ok_or("Event sequence exhausted")?;
		config::atomic_write(
			&self.path,
			&serde_json::to_vec(&next).map_err(|_| "Cannot encode event history")?,
		)?;
		self.records = next;
		self.next_id = next_id;
		Ok(())
	}
}

fn handle(
	node: &Node, config: &config::Config, history: &Mutex<History>, request: &Request,
) -> Result<Value, String> {
	let p = &request.params;
	match request.method.as_str() {
		"info" => {
			only(p, &[])?;
			let status = node.status();
			Ok(
				json!({"node_id":node.node_id().to_string(),"network":config.network,"alias":config.alias,
                "best_block_height":status.current_best_block.height,"best_block_hash":status.current_best_block.block_hash.to_string(),
                "is_running":status.is_running,"listening_addresses":node.listening_addresses().unwrap_or_default().iter().map(ToString::to_string).collect::<Vec<_>>(),
                "latest_lightning_sync":status.latest_lightning_wallet_sync_timestamp,"latest_onchain_sync":status.latest_onchain_wallet_sync_timestamp,
                "capabilities":METHODS,"provider_enabled":config.chicory.enabled,"offline_enabled":config.chicory.offline_enabled}),
			)
		},
		"balance" => {
			only(p, &[])?;
			let balance = node.list_balances();
			Ok(
				json!({"onchain_total_sats":money(balance.total_onchain_balance_sats),"onchain_spendable_sats":money(balance.spendable_onchain_balance_sats),"lightning_total_sats":money(balance.total_lightning_balance_sats),"anchor_reserve_sats":money(balance.total_anchor_channels_reserve_sats)}),
			)
		},
		"channels" => {
			only(p, &[])?;
			Ok(json!(node.list_channels().into_iter().map(|c| json!({"channel_id":c.channel_id.to_string(),"counterparty_node_id":c.counterparty_node_id.to_string(),"value_sats":money(c.channel_value_sats),"outbound_capacity_msat":money(c.outbound_capacity_msat),"inbound_capacity_msat":money(c.inbound_capacity_msat),"is_usable":c.is_usable,"is_channel_ready":c.is_channel_ready,"is_public":c.is_announced,"confirmations_required":c.confirmations_required,"confirmations":c.confirmations,"funding_txo":c.funding_txo.map(|outpoint|outpoint.to_string())})).collect::<Vec<_>>()))
		},
		"payments" => {
			only(p, &[])?;
			let mut payments = node.list_payments();
			payments.sort_by_key(|payment| std::cmp::Reverse(payment.latest_update_timestamp));
			Ok(json!(payments.into_iter().take(2000).map(|payment| {
                let (kind, txid) = match payment.kind {
                    PaymentKind::Onchain { txid, .. } => ("onchain", Some(txid.to_string())),
                    PaymentKind::Bolt11 { .. } => ("bolt11", None), PaymentKind::Bolt11Jit { .. } => ("bolt11_jit", None),
                    PaymentKind::Bolt12Offer { .. } => ("bolt12_offer", None), PaymentKind::Bolt12Refund { .. } => ("bolt12_refund", None),
                    PaymentKind::Spontaneous { .. } => ("spontaneous", None),
                };
                json!({"id":hex(&payment.id.0),"kind":kind,"txid":txid,"direction":format!("{:?}",payment.direction).to_lowercase(),"status":format!("{:?}",payment.status).to_lowercase(),"amount_msat":payment.amount_msat.map(money),"fee_paid_msat":payment.fee_paid_msat.map(money),"updated_at":payment.latest_update_timestamp})
            }).collect::<Vec<_>>()))
		},
		"peers" => {
			only(p, &[])?;
			Ok(json!(node.list_peers().into_iter().map(|peer|json!({"node_id":peer.node_id.to_string(),"address":peer.address.to_string(),"is_connected":peer.is_connected,"is_persisted":peer.is_persisted})).collect::<Vec<_>>()))
		},
		"address" => {
			only(p, &[])?;
			Ok(json!({"address":node.onchain_payment().new_address().map_err(native)?.to_string()}))
		},
		"invoice" => {
			only(p, &["amount_msat", "description", "expiry_secs"])?;
			let description = match p.get("description") {
				None => "",
				Some(Value::String(value)) => value.as_str(),
				_ => return Err("Invoice description must be a string".into()),
			};
			if description.len() > 639 {
				return Err("Invoice description is too long".into());
			}
			let description = Bolt11InvoiceDescription::Direct(
				Description::new(description.to_owned())
					.map_err(|_| "Invalid invoice description")?,
			);
			let expiry: u32 = if p.contains_key("expiry_secs") {
				positive(p, "expiry_secs")?.try_into().map_err(|_| "Invalid expiry")?
			} else {
				3600
			};
			if expiry > 604800 {
				return Err("Invoice expiry cannot exceed seven days".into());
			}
			let invoice = if p.contains_key("amount_msat") {
				node.bolt11_payment().receive(positive(p, "amount_msat")?, &description, expiry)
			} else {
				node.bolt11_payment().receive_variable_amount(&description, expiry)
			}
			.map_err(native)?;
			Ok(json!({"invoice":invoice.to_string()}))
		},
		"pay" => {
			only(p, &["invoice", "amount_msat"])?;
			let invoice = Bolt11Invoice::from_str(text(p, "invoice")?)
				.map_err(|_| "Invalid BOLT11 invoice")?;
			let id = if p.contains_key("amount_msat") {
				node.bolt11_payment().send_using_amount(&invoice, positive(p, "amount_msat")?, None)
			} else {
				node.bolt11_payment().send(&invoice, None)
			}
			.map_err(native)?;
			Ok(json!({"id":hex(&id.0)}))
		},
		"send_onchain" | "estimate_onchain" => {
			only(p, &["address", "amount_sats", "send_all", "fee_rate_sat_per_kwu"])?;
			let address = Address::from_str(text(p, "address")?)
				.map_err(|_| "Invalid Bitcoin address")?
				.require_network(config::network(&config.network)?)
				.map_err(|_| "Address belongs to another network")?;
			let all = flag(p, "send_all", false)?;
			if all == p.contains_key("amount_sats") {
				return Err("Choose exactly one of amount_sats or send_all".into());
			}
			let amount = if all { None } else { Some(positive(p, "amount_sats")?) };
			let rate = fee(p)?;
			if request.method == "estimate_onchain" {
				let fee = if let Some(amount) = amount {
					node.onchain_payment().calculate_total_fee(&address, amount, rate, None)
				} else {
					node.onchain_payment().calculate_send_all_fee(&address, true, rate)
				}
				.map_err(native)?;
				return Ok(json!({"fee_sats":money(fee),"retains_channel_reserves":true}));
			}
			let outcome = if let Some(amount) = amount {
				node.onchain_payment()
					.send_to_address_with_broadcast_result(&address, amount, rate, None)
			} else {
				node.onchain_payment()
					.send_all_to_address_with_broadcast_result(&address, true, rate)
			}
			.map_err(native)?;
			// Rejection or unknown delivery is an attempted transaction, never permission to retry.
			Ok(match outcome {
				OnchainSendResult::Accepted { txid } => {
					json!({"txid":txid.to_string(),"broadcast":"accepted"})
				},
				OnchainSendResult::Rejected { txid, .. } => {
					json!({"txid":txid.to_string(),"broadcast":"rejected","retry_safe":false})
				},
				OnchainSendResult::Unknown { txid } => {
					json!({"txid":txid.to_string(),"broadcast":"unknown","retry_safe":false})
				},
			})
		},
		"connect" => {
			only(p, &["node_id", "address"])?;
			node.connect(
				text(p, "node_id")?.parse().map_err(|_| "Invalid node id")?,
				text(p, "address")?.parse().map_err(|_| "Invalid peer address")?,
				true,
			)
			.map_err(native)?;
			Ok(json!({"accepted":true}))
		},
		"disconnect" => {
			only(p, &["node_id"])?;
			node.disconnect(text(p, "node_id")?.parse().map_err(|_| "Invalid node id")?)
				.map_err(native)?;
			Ok(json!({"accepted":true}))
		},
		"open" => {
			only(p, &["node_id", "address", "amount_sats"])?;
			let id = node
				.open_channel(
					text(p, "node_id")?.parse().map_err(|_| "Invalid node id")?,
					text(p, "address")?.parse().map_err(|_| "Invalid peer address")?,
					positive(p, "amount_sats")?,
					None,
					None,
				)
				.map_err(native)?;
			Ok(json!({"user_channel_id":id.to_string()}))
		},
		"close" | "splice_in" | "splice_out" => {
			match request.method.as_str() {
				"close" => only(p, &["channel_id", "counterparty_node_id", "force"]),
				"splice_in" => only(p, &["channel_id", "counterparty_node_id", "amount_sats"]),
				_ => only(p, &["channel_id", "counterparty_node_id", "amount_sats", "address"]),
			}?;
			let channel = node
				.list_channels()
				.into_iter()
				.find(|channel| {
					channel.channel_id.to_string() == text(p, "channel_id").unwrap_or("")
						&& channel.counterparty_node_id.to_string()
							== text(p, "counterparty_node_id").unwrap_or("")
				})
				.ok_or("No matching native channel")?;
			match request.method.as_str() {
				"close" => {
					if flag(p, "force", false)? {
						node.force_close_channel(
							&channel.user_channel_id,
							channel.counterparty_node_id,
							Some("Operator requested force close".into()),
						)
					} else {
						node.close_channel(&channel.user_channel_id, channel.counterparty_node_id)
					}
					.map_err(native)?;
				},
				"splice_in" => node
					.splice_in(
						&channel.user_channel_id,
						channel.counterparty_node_id,
						positive(p, "amount_sats")?,
					)
					.map_err(native)?,
				"splice_out" => {
					let address = Address::from_str(text(p, "address")?)
						.map_err(|_| "Invalid Bitcoin address")?
						.require_network(config::network(&config.network)?)
						.map_err(|_| "Address belongs to another network")?;
					node.splice_out(
						&channel.user_channel_id,
						channel.counterparty_node_id,
						&address,
						positive(p, "amount_sats")?,
					)
					.map_err(native)?;
				},
				_ => unreachable!(),
			}
			Ok(json!({"accepted":true}))
		},
		"sync" => {
			only(p, &[])?;
			node.sync_wallets().map_err(native)?;
			Ok(json!({"synced":true}))
		},
		"offline_status" => {
			only(p, &[])?;
			Ok(
				json!({"enabled":config.chicory.offline_enabled,"epochs":node.list_chicory_offline_epochs().into_iter().map(|epoch|json!({"channel_id":epoch.channel_id.to_string(),"epoch_id":hex(&epoch.epoch_id),"phase":epoch.phase,"slot_count":epoch.slot_count,"reserved_msat":money(epoch.reserved_msat),"settling_count":epoch.settling_count,"settled_count":epoch.settled_count,"persistence_pending":epoch.persistence_pending})).collect::<Vec<_>>()}),
			)
		},
		"events" => {
			only(p, &[])?;
			Ok(json!(history.lock().map_err(|_| "Event history unavailable")?.records))
		},
		"stop" => {
			only(p, &[])?;
			node.stop().map_err(native)?;
			Ok(json!({"stopped":true}))
		},
		_ => Err("Unknown operation".into()),
	}
}

fn read_request(reader: &mut impl BufRead) -> Result<Option<Vec<u8>>, String> {
	let mut line = Vec::new();
	loop {
		let bytes = reader.fill_buf().map_err(|_| "Cannot read administration input")?;
		if bytes.is_empty() {
			return if line.is_empty() {
				Ok(None)
			} else {
				Err("Truncated administration request".into())
			};
		}
		let count = bytes.iter().position(|b| *b == b'\n').map(|n| n + 1).unwrap_or(bytes.len());
		if line.len() + count > MAX_REQUEST {
			return Err("Administration request exceeds size limit".into());
		}
		line.extend_from_slice(&bytes[..count]);
		reader.consume(count);
		if line.last() == Some(&b'\n') {
			return Ok(Some(line));
		}
	}
}

fn run() -> Result<(), String> {
	let args: Vec<String> = std::env::args().collect();
	if args.len() != 3 || args[1] != "--config" {
		return Err("Usage: ldk-node-daemon --config /absolute/path/node.json".into());
	}
	let config = config::Config::read(Path::new(&args[2]))?;
	let _lock = config.lock_directory()?;
	config.verify_chain()?;
	let history = Arc::new(Mutex::new(History::open(&config.data_dir)?));
	let node = Arc::new(config.build()?);
	node.start().map_err(native)?;
	let stopping = Arc::new(AtomicBool::new(false));
	let event_failed = Arc::new(AtomicBool::new(false));
	let event_worker = {
		let node = Arc::clone(&node);
		let history = Arc::clone(&history);
		let stopping = Arc::clone(&stopping);
		let failed = Arc::clone(&event_failed);
		thread::spawn(move || {
			while !stopping.load(Ordering::Acquire) {
				if let Some(event) = node.next_event() {
					let result = history
						.lock()
						.map_err(|_| "Event history unavailable".to_owned())
						.and_then(|mut history| history.append(&event))
						.and_then(|_| node.event_handled().map_err(native));
					if result.is_err() {
						failed.store(true, Ordering::Release);
						let _ = output(&json!({"event":"error","code":"event_persistence_failed"}));
						let _ = node.stop();
						return;
					}
				} else {
					thread::sleep(Duration::from_millis(100));
				}
			}
		})
	};
	let result = (|| -> Result<(), String> {
		output(&json!({"event":"ready","node_id":node.node_id().to_string(),"network":config.network,"listen_address":config.listen_address,"capabilities":METHODS})).map_err(|_|"Administration output closed")?;
		let stdin = io::stdin();
		let mut reader = stdin.lock();
		while let Some(line) = read_request(&mut reader)? {
			if event_failed.load(Ordering::Acquire) {
				return Err("Event persistence failed; native node stopped".into());
			}
			let request: Request = match serde_json::from_slice(&line) {
				Ok(request) => request,
				Err(_) => {
					output(&json!({"id":null,"error":{"code":"invalid_request","message":"Invalid administration request"}})).map_err(|_|"Administration output closed")?;
					continue;
				},
			};
			if !request.id.as_u64().is_some_and(|id| id <= JS_MAX_INTEGER)
				&& !request.id.as_str().is_some_and(|id| !id.is_empty() && id.len() <= 64)
			{
				return Err("Request id must be a bounded string or safe integer".into());
			}
			let response = if matches!(
				request.method.as_str(),
				"open" | "splice_in" | "splice_out" | "send_onchain"
			) {
				node.with_chicory_wallet_operation(|| handle(&node, &config, &history, &request))
					.map_err(native)
					.and_then(|response| response)
			} else {
				handle(&node, &config, &history, &request)
			};
			let stop = request.method == "stop" && response.is_ok();
			let response = match response {
				Ok(result) => json!({"id":request.id,"result":result}),
				Err(message) => {
					json!({"id":request.id,"error":{"code":"operation_failed","message":message}})
				},
			};
			output(&response).map_err(|_| "Administration output closed")?;
			if stop {
				break;
			}
		}
		Ok(())
	})();
	stopping.store(true, Ordering::Release);
	event_worker.join().map_err(|_| "Event worker stopped unexpectedly")?;
	if node.status().is_running {
		node.stop().map_err(native)?;
	}
	result
}

fn main() {
	if let Err(message) = run() {
		eprintln!("ldk-node-daemon: {message}");
		std::process::exit(1);
	}
}

#[cfg(test)]
mod tests;
