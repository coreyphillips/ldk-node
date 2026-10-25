//! Disposable regtest driver for the experimental native Chicory JIT service.
//!
//! Run with a data directory, listening port and chain-source URL. Administration
//! uses newline JSON on stdin/stdout, so no unauthenticated HTTP API is opened.
//! This driver deliberately uses regtest and is not a complete Chicory primary.

use std::error::Error;
use std::io::{self, BufRead, Write};
use std::str::FromStr;
#[cfg(feature = "uniffi")]
use std::sync::Arc;

use ldk_node::bitcoin::Network;
use ldk_node::chicory::{JitServiceConfig, OfflineReceiveConfig};
use ldk_node::lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Description};
use ldk_node::{Builder, Event, Node};
use serde_json::{json, Value};

fn field<'a>(request: &'a Value, name: &str) -> Result<&'a str, Box<dyn Error>> {
	request.get(name).and_then(Value::as_str).ok_or_else(|| format!("missing {name}").into())
}

fn amount(request: &Value) -> Result<u64, Box<dyn Error>> {
	request.get("amountSats").and_then(Value::as_u64).ok_or_else(|| "missing amountSats".into())
}

fn handle(node: &Node, request: &Value) -> Result<Value, Box<dyn Error>> {
	match field(request, "method")? {
		"sync" => {
			node.sync_wallets()?;
			Ok(json!(true))
		},
		"balance" => {
			let balance = node.list_balances();
			Ok(json!({"onchainSats": balance.total_onchain_balance_sats,
				"spendableOnchainSats": balance.spendable_onchain_balance_sats,
				"lightningSats": balance.total_lightning_balance_sats}))
		},
		"channels" => Ok(json!(node
			.list_channels()
			.into_iter()
			.map(|channel| json!({
				"channelId": channel.channel_id.to_string(),
				"counterpartyNodeId": channel.counterparty_node_id.to_string(),
				"isChannelReady": channel.is_channel_ready,
				"isUsable": channel.is_usable,
				"inboundCapacityMsat": channel.inbound_capacity_msat,
				"outboundCapacityMsat": channel.outbound_capacity_msat,
				"valueSats": channel.channel_value_sats,
				"fundingTxid": channel.funding_txo.map(|outpoint| outpoint.txid.to_string()),
				"fundingOutputIndex": channel.funding_txo.map(|outpoint| outpoint.vout),
			}))
			.collect::<Vec<_>>())),
		"invoice" => {
			let description =
				request.get("description").and_then(Value::as_str).unwrap_or("regtest");
			let description =
				Bolt11InvoiceDescription::Direct(Description::new(description.into())?);
			#[cfg(feature = "uniffi")]
			let description = description.into();
			let msat = amount(request)?.checked_mul(1000).ok_or("amount overflow")?;
			let invoice = node.bolt11_payment().receive(msat, &description, 3600)?;
			Ok(json!({"bolt11": invoice.to_string()}))
		},
		"pay" => {
			let invoice = Bolt11Invoice::from_str(field(request, "bolt11")?)?;
			#[cfg(feature = "uniffi")]
			let invoice = Arc::new(invoice.into());
			let id = node.bolt11_payment().send(&invoice, None)?;
			Ok(json!({"paymentId": format!("{:?}", id)}))
		},
		"open" => {
			let id = node.open_channel(
				field(request, "nodeId")?.parse()?,
				field(request, "address")?.parse()?,
				amount(request)?,
				None,
				None,
			)?;
			Ok(json!({"userChannelId": id.to_string()}))
		},
		"splice_in" => {
			let channel_id = field(request, "channelId")?;
			let channel = node
				.list_channels()
				.into_iter()
				.find(|channel| channel.channel_id.to_string() == channel_id)
				.ok_or("unknown channel")?;
			node.splice_in(
				&channel.user_channel_id,
				channel.counterparty_node_id,
				amount(request)?,
			)?;
			Ok(json!(true))
		},
		"force_close" => {
			let channel_id = field(request, "channelId")?;
			let channel = node
				.list_channels()
				.into_iter()
				.find(|channel| channel.channel_id.to_string() == channel_id)
				.ok_or("unknown channel")?;
			node.force_close_channel(
				&channel.user_channel_id,
				channel.counterparty_node_id,
				Some("Disposable regtest recovery sweep".into()),
			)?;
			Ok(json!(true))
		},
		"events" => {
			let mut events = Vec::new();
			while let Some(mut event) = node.next_event() {
				// Qualification needs public payment identities, never settlement secrets.
				if let Event::PaymentSuccessful { payment_preimage, .. } = &mut event {
					*payment_preimage = None;
				}
				events.push(format!("{:?}", event));
				node.event_handled()?;
			}
			Ok(json!(events))
		},
		"stop" => {
			node.stop()?;
			Ok(json!(true))
		},
		method => Err(format!("unknown method: {method}").into()),
	}
}

fn output(value: Value) -> io::Result<()> {
	let mut stdout = io::stdout().lock();
	serde_json::to_writer(&mut stdout, &value)?;
	writeln!(stdout)?;
	stdout.flush()
}

fn main() -> Result<(), Box<dyn Error>> {
	let args: Vec<_> = std::env::args().collect();
	if args.len() < 3 || args.len() > 4 {
		return Err("usage: chicory-primary <data-directory> <port> [tcp://host:port or rpc://user:password@host:port]".into());
	}
	let port: u16 = args[2].parse()?;
	#[cfg(not(feature = "uniffi"))]
	let mut builder = Builder::new();
	#[cfg(feature = "uniffi")]
	let builder = Builder::new();
	builder.set_network(Network::Regtest);
	builder.set_node_alias("Chicory regtest primary".into())?;
	builder.set_storage_dir_path(args[1].clone());
	builder.set_listening_addresses(vec![format!("127.0.0.1:{port}").parse()?])?;
	let chain_source = args.get(3).cloned().unwrap_or_else(|| "tcp://127.0.0.1:60001".into());
	let chain_url = reqwest::Url::parse(&chain_source)?;
	if chain_url.scheme() == "rpc" {
		builder.set_chain_source_bitcoind_rpc(
			chain_url.host_str().ok_or("missing RPC host")?.into(),
			chain_url.port().ok_or("missing RPC port")?,
			chain_url.username().into(),
			chain_url.password().ok_or("missing RPC password")?.into(),
		);
	} else {
		builder.set_chain_source_electrum(chain_source, None);
	}
	builder.set_chicory_service(JitServiceConfig {
		enabled: true,
		offline_receive: OfflineReceiveConfig {
			enabled: std::env::var("CHICORY_ENABLE_OFFLINE").as_deref() == Ok("1"),
			..OfflineReceiveConfig::default()
		},
		relay_enabled: true,
		allow_confirmed_v2: true,
		allow_splice_jit: true,
		reuse_funding_key_on_splice: true,
		inbound_splice_minimum_depth: 6,
		flat_fee_sat: 100,
		fee_ppm: 1000,
		max_client_funding_sats: 500_000,
		max_total_fronted_sats: 2_000_000,
		..JitServiceConfig::default()
	})?;
	let node = builder.build()?;
	node.start()?;
	output(json!({"ready":true,"nodeId":node.node_id().to_string(),
		"uri":format!("{}@127.0.0.1:{port}",node.node_id()),
		"address":node.onchain_payment().new_address()?.to_string()}))?;
	for line in io::stdin().lock().lines() {
		let line = line?;
		let request: Value = match serde_json::from_str(&line) {
			Ok(request) => request,
			Err(error) => {
				output(json!({"error":error.to_string()}))?;
				continue;
			},
		};
		let result = handle(&node, &request);
		let stopping =
			request.get("method").and_then(Value::as_str) == Some("stop") && result.is_ok();
		match result {
			Ok(value) => output(json!({"id":request.get("id"),"result":value}))?,
			Err(error) => output(json!({"id":request.get("id"),"error":error.to_string()}))?,
		}
		if stopping {
			return Ok(());
		}
	}
	node.stop()?;
	Ok(())
}
