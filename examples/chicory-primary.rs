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
use ldk_node::chicory::JitServiceConfig;
use ldk_node::lightning_invoice::{Bolt11Invoice, Bolt11InvoiceDescription, Description};
use ldk_node::payment::ConfirmationStatus;
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
		"direct_funding_request" => {
			let result = node.create_direct_funding_request(request.get("amountSats").and_then(Value::as_u64), 600)?;
			Ok(json!({"request": result.request, "requestId": result.request_id, "paymentHash": result.payment_hash, "expiresAt": result.expires_at}))
		},
		"direct_funding_send" => {
			let result = node.send_direct_funding(field(request, "request")?.to_owned(), request.get("amountSats").and_then(Value::as_u64), request.get("maxFeeSats").and_then(Value::as_u64).unwrap_or(10_000))?;
			Ok(direct_payment(result))
		},
		"direct_funding_payments" => Ok(json!(node.list_direct_funding_payments().into_iter().map(direct_payment).collect::<Vec<_>>())),
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
				"userChannelId": channel.user_channel_id.0.to_string(),
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
		"check_primary" => {
			node.check_primary_connection(field(request, "nodeId")?.parse()?)?;
			Ok(json!({ "connected": true }))
		},
		"quote_primary" => {
			let quote = node.quote_primary_receive(field(request, "nodeId")?.parse()?, amount(request)?.checked_mul(1000).ok_or("amount overflow")?, 10_000)?;
			Ok(json!({"amountMsat": quote.amount_msat, "feeMsat": quote.fee_msat, "fundingSats": quote.funding_sats}))
		},
		"receive_primary" => {
			let description = Bolt11InvoiceDescription::Direct(Description::new("primary regtest".into())?);
			#[cfg(feature = "uniffi")]
			let description = description.into();
			let invoice = node.receive_via_primary(field(request, "nodeId")?.parse()?, amount(request)?.checked_mul(1000).ok_or("amount overflow")?, &description, 3600, request.get("maxFeeMsat").and_then(Value::as_u64).unwrap_or(500_000), 10_000)?;
			Ok(json!({"bolt11": invoice.to_string()}))
		},
		"payments" => Ok(json!(node.list_payments().into_iter().map(|payment| json!({"id": format!("{:?}", payment.id), "amountMsat": payment.amount_msat, "status": format!("{:?}", payment.status), "direction": format!("{:?}", payment.direction)})).collect::<Vec<_>>())),
		"connect" => {
			node.connect(field(request, "nodeId")?.parse()?, field(request, "address")?.parse()?, true)?;
			Ok(json!(true))
		},
		"transaction" => {
			let transaction = node.fetch_transaction_details(&field(request, "txid")?.parse()?)?;
			Ok(json!({"inputs": transaction.inputs.iter().map(|input| json!({"txid":input.txid.to_string(),"vout":input.vout})).collect::<Vec<_>>(), "outputs": transaction.outputs.iter().map(|output| json!({"valueSats":output.value,"address":output.scriptpubkey_address})).collect::<Vec<_>>()}))
		},
		"transaction_status" => {
			Ok(match node.fetch_transaction_status(&field(request, "txid")?.parse()?)? {
				ConfirmationStatus::Unconfirmed => json!({"confirmed": false}),
				ConfirmationStatus::Confirmed { block_hash, height, timestamp } => json!({
					"confirmed": true, "blockHash": block_hash.to_string(), "height": height, "timestamp": timestamp
				}),
			})
		},
		"splice_out" => {
			let channel_id = field(request, "channelId")?;
			let channel = node.list_channels().into_iter().find(|channel| channel.channel_id.to_string() == channel_id).ok_or("unknown channel")?;
			node.splice_out_with_fee_rate(&channel.user_channel_id, channel.counterparty_node_id, &field(request, "address")?.parse::<ldk_node::bitcoin::Address<_>>()?.require_network(Network::Regtest)?, amount(request)?, request.get("feeRate").and_then(Value::as_u64).unwrap_or(2))?;
			Ok(json!(true))
		},
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
			let id = if let Some(value) = request.get("userChannelId").and_then(Value::as_str) {
				node.open_channel_with_user_channel_id(field(request, "nodeId")?.parse()?, field(request, "address")?.parse()?, amount(request)?, None, None, &ldk_node::UserChannelId(value.parse()?))?
			} else {
				node.open_channel(field(request, "nodeId")?.parse()?, field(request, "address")?.parse()?, amount(request)?, None, None)?
			};
			Ok(json!({"userChannelId": id.0.to_string()}))
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

fn direct_payment(payment: ldk_node::DirectFundingPaymentDetails) -> Value {
	json!({"requestId":payment.request_id, "paymentHash":payment.payment_hash, "amountSats":payment.amount_sats, "feeSats":payment.fee_sats, "fundingTxid":payment.funding_txid, "status":format!("{:?}",payment.status), "isOutbound":payment.is_outbound})
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
	let primary_uri = std::env::var("LFBW_PRIMARY_URI").ok();
	if let Some(uri) = &primary_uri {
		let (key, _) = uri.split_once('@').ok_or("invalid primary URI")?;
		builder.set_primary_node(key.parse()?);
	} else if std::env::var("LFBW_DISABLE_PROVIDER").as_deref() != Ok("1") {
		let trusted_splice_peer_pubkeys = std::env::var("CHICORY_TEST_TRUSTED_SPLICE_PEERS")
			.ok()
			.map(|value| -> Result<Vec<_>, Box<dyn Error>> {
				serde_json::from_str::<Vec<String>>(&value)?
					.into_iter()
					.map(|key| {
						if key.len() != 66 || !(key.starts_with("02") || key.starts_with("03")) {
							return Err(
								"trusted splice peer must be a compressed public key".into()
							);
						}
						Ok(key.parse()?)
					})
					.collect()
			})
			.transpose()?
			.unwrap_or_default();
		builder.set_chicory_service(JitServiceConfig {
			enabled: true,
			relay_enabled: true,
			allow_confirmed_v2: true,
			allow_splice_jit: true,
			trusted_splice_peer_pubkeys,
			reuse_funding_key_on_splice: true,
			inbound_splice_minimum_depth: 6,
			flat_fee_sat: 100,
			fee_ppm: 1000,
			max_client_funding_sats: 500_000,
			max_total_fronted_sats: 2_000_000,
			..JitServiceConfig::default()
		})?;
	}
	let node = builder.build()?;
	node.start()?;
	if let Some(uri) = primary_uri {
		let (key, address) = uri.split_once('@').ok_or("invalid primary URI")?;
		node.connect(key.parse()?, address.parse()?, true)?;
	}
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
