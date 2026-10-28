//! Native client for the primary-node JIT receive protocol used by Beignet.
//!
//! BOLT 8 authenticates the peer. Requests are bounded, correlated to that peer,
//! and time out without creating an invoice. Only the configured primary may
//! authorize liquidity; every invoice records an explicit maximum withheld fee.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{PublicKey, Secp256k1};
use lightning::chain::chaininterface::ConfirmationTarget as LdkConfirmationTarget;
use lightning::ln::channel_state::ChannelDetails;
use lightning::ln::channelmanager::{AChannelManager, PaymentId};
use lightning::routing::router::{RouteHint, RouteHintHop};
use lightning::types::payment::{PaymentHash, PaymentSecret};
use lightning::util::config::{ChannelConfigUpdate, ChannelHandshakeConfigUpdate};
use lightning_invoice::{InvoiceBuilder, RoutingFees};
use tokio::sync::oneshot;

use crate::error::Error;
use crate::event::{TransactionDetails, TxInput, TxOutput};
use crate::fee_estimator::{ConfirmationTarget, FeeEstimator};
#[cfg(feature = "uniffi")]
use crate::ffi::maybe_try_convert_enum;
use crate::ffi::maybe_wrap;
use crate::logger::{log_info, LdkLogger};
use crate::payment::{LSPFeeLimits, PaymentDetails, PaymentDirection, PaymentKind, PaymentStatus};
use crate::primary_wire::{
	self as wire, Envelope, FeeMode, JitAck, JitAuthorization, JitQuote, JitQuoteRequest,
};
use crate::Node;

#[cfg(not(feature = "uniffi"))]
type Invoice = lightning_invoice::Bolt11Invoice;
#[cfg(feature = "uniffi")]
type Invoice = std::sync::Arc<crate::ffi::Bolt11Invoice>;
#[cfg(not(feature = "uniffi"))]
type Description = lightning_invoice::Bolt11InvoiceDescription;
#[cfg(feature = "uniffi")]
type Description = crate::ffi::Bolt11InvoiceDescription;

const MAX_PENDING: usize = 32;
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECTION_PROBE_AMOUNT_MSAT: u64 = 1000;
const MAX_MONEY_MSAT: u64 = 2_100_000_000_000_000_000;
const MIN_FINAL_CLTV: u16 = 72;
const ROUTE_CLTV: u16 = 80;

// Only an explicitly selected private primary receives the splice-compatible handshake policy.
pub(crate) fn primary_channel_handshake(
	config: &crate::config::Config, peer: PublicKey, announced: bool,
) -> ChannelHandshakeConfigUpdate {
	if config.primary_node_id == Some(peer) && !announced {
		splice_channel_handshake()
	} else {
		ChannelHandshakeConfigUpdate::default()
	}
}

// Shared only by explicitly enabled private primary client/provider negotiations.
pub(crate) fn splice_channel_handshake() -> ChannelHandshakeConfigUpdate {
	ChannelHandshakeConfigUpdate {
		max_inbound_htlc_value_in_flight_msat: Some(MAX_MONEY_MSAT),
		retain_counterparty_htlc_limit_for_splicing: Some(true),
		..Default::default()
	}
}

/// A primary's read-only quote. It does not reserve capacity or create an invoice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrimaryReceiveQuote {
	/// Requested invoice amount, before the receiver's fee is deducted.
	pub amount_msat: u64,
	/// Maximum fee deducted from this amount using the returned terms.
	pub fee_msat: u64,
	/// Funding the primary proposes to provide, in satoshis.
	pub funding_sats: u64,
}

/// Fee estimates from the configured chain backend, in satoshis per virtual byte.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OnchainFeeRates {
	/// The one-block estimate.
	pub fast_sat_per_vbyte: u64,
	/// The six-block estimate.
	pub normal_sat_per_vbyte: u64,
	/// The twelve-block estimate.
	pub slow_sat_per_vbyte: u64,
	/// The estimate used for channel funding and splices.
	pub channel_funding_sat_per_vbyte: u64,
}

struct Pending {
	peer: PublicKey,
	subtype: u16,
	reply: oneshot::Sender<Envelope>,
}

#[derive(Default)]
struct State {
	pending: HashMap<[u8; 8], Pending>,
	messages: Vec<(PublicKey, Envelope)>,
}

pub(crate) struct PrimaryClient {
	primary: Option<PublicKey>,
	state: Mutex<State>,
}

struct Request<'a> {
	client: &'a PrimaryClient,
	id: [u8; 8],
	reply: Option<oneshot::Receiver<Envelope>>,
}

impl Drop for Request<'_> {
	fn drop(&mut self) {
		let mut state = self.client.state.lock().unwrap();
		state.pending.remove(&self.id);
		state.messages.retain(|(_, message)| request_id(message) != Some(self.id));
	}
}

fn request_id(message: &Envelope) -> Option<[u8; 8]> {
	let start = if message.subtype == wire::JIT_AUTHORIZATION { 32 } else { 0 };
	message.payload.get(start..start + 8)?.try_into().ok()
}

impl PrimaryClient {
	pub(crate) fn new(primary: Option<PublicKey>) -> Self {
		Self { primary, state: Mutex::new(State::default()) }
	}

	pub(crate) fn enabled(&self) -> bool {
		self.primary.is_some()
	}

	fn quote(
		&self, peer: PublicKey, amount_msat: u64, target_inbound_sats: u64,
	) -> Result<Request<'_>, Error> {
		self.begin(peer, wire::JIT_QUOTE_REQUEST, wire::JIT_QUOTE, |request_id| {
			JitQuoteRequest {
				request_id,
				max_amount_msat: amount_msat,
				target_remaining_inbound_sat: target_inbound_sats,
			}
			.encode()
		})
	}

	fn begin(
		&self, peer: PublicKey, subtype: u16, response: u16,
		payload: impl FnOnce([u8; 8]) -> Vec<u8>,
	) -> Result<Request<'_>, Error> {
		if self.primary != Some(peer) {
			return Err(Error::LiquiditySourceUnavailable);
		}
		let mut state = self.state.lock().unwrap();
		if state.pending.len() >= MAX_PENDING {
			return Err(Error::LiquidityRequestFailed);
		}
		let id = loop {
			let candidate = rand::random();
			if !state.pending.contains_key(&candidate) {
				break candidate;
			}
		};
		let (sender, receiver) = oneshot::channel();
		state.pending.insert(id, Pending { peer, subtype: response, reply: sender });
		state.messages.push((
			peer,
			Envelope { version: wire::PROTOCOL_VERSION, subtype, payload: payload(id) },
		));
		Ok(Request { client: self, id, reply: Some(receiver) })
	}

	pub(crate) fn take_messages(&self) -> Vec<(PublicKey, Envelope)> {
		std::mem::take(&mut self.state.lock().unwrap().messages)
	}

	pub(crate) fn handle_message(&self, peer: PublicKey, message: &Envelope) {
		if self.primary != Some(peer) || message.version != wire::PROTOCOL_VERSION {
			return;
		}
		let Some(id) = request_id(message) else {
			return;
		};
		let mut state = self.state.lock().unwrap();
		if !state
			.pending
			.get(&id)
			.is_some_and(|pending| pending.peer == peer && pending.subtype == message.subtype)
		{
			return;
		}
		if let Some(pending) = state.pending.remove(&id) {
			let _ = pending.reply.send(message.clone());
		}
	}

	pub(crate) fn disconnected(&self, peer: PublicKey) {
		let mut state = self.state.lock().unwrap();
		state.pending.retain(|_, pending| pending.peer != peer);
		state.messages.retain(|(target, _)| *target != peer);
	}
}

impl Request<'_> {
	async fn receive_quote(self) -> Result<JitQuote, Error> {
		let response = self.receive().await?;
		JitQuote::decode(&response.payload).map_err(|_| Error::LiquidityRequestFailed)
	}

	async fn receive(mut self) -> Result<Envelope, Error> {
		let receiver = self.reply.take().ok_or(Error::LiquidityRequestFailed)?;
		tokio::time::timeout(RESPONSE_TIMEOUT, receiver)
			.await
			.map_err(|_| Error::LiquidityRequestTimedOut)?
			.map_err(|_| Error::LiquidityRequestFailed)
	}
}

// Refusals are untrusted diagnostics, not permission to relax any receive check.
// Match only known provider messages; budget, policy and unknown failures remain rejections.
fn primary_rejection_error(reason: Option<&str>) -> Error {
	match reason {
		Some("provider wallet has insufficient available funds")
		| Some("provider lacks confirmed native-witness funds for this splice")
		| Some(
			"the provider does not hold enough on-chain funds to front this receive right now",
		) => Error::LiquiditySourceInsufficientFunds,
		Some("opening fee consumes payment") => Error::LiquidityReceiveAmountTooSmall,
		_ => Error::LiquidityRequestRejected,
	}
}

// Bound untrusted text independently of the wire parser and escape control characters so a
// provider cannot inject log lines. Never include authorization payloads or payment secrets.
fn primary_reason_for_log(reason: Option<&str>) -> String {
	reason.unwrap_or("No reason supplied").chars().take(200).flat_map(char::escape_debug).collect()
}

fn fee_msat(amount_msat: u64, flat_fee_sat: u64, fee_ppm: u32) -> Result<u64, Error> {
	if fee_ppm > 1_000_000 {
		return Err(Error::LiquidityRequestFailed);
	}
	let fee =
		u128::from(flat_fee_sat) * 1000 + u128::from(amount_msat) * u128::from(fee_ppm) / 1_000_000;
	let fee = u64::try_from(fee).map_err(|_| Error::LiquidityRequestFailed)?;
	if fee >= amount_msat {
		return Err(Error::LiquidityReceiveAmountTooSmall);
	}
	Ok(fee)
}

// An existing channel uses its advertised forwarding policy before the provider
// can hold a liquidity shortfall for a splice. Only an intercept has zero hop fees.
fn primary_receive_route(
	peer: PublicKey, channels: &[ChannelDetails], intercept_scid: u64,
) -> Result<RouteHintHop, Error> {
	let existing = channels
		.iter()
		.find(|channel| channel.counterparty.node_id == peer && channel.is_channel_ready);
	let (short_channel_id, fees, cltv_expiry_delta) = if let Some(channel) = existing {
		let scid = channel
			.inbound_scid_alias
			.or(channel.short_channel_id)
			.ok_or(Error::LiquiditySourceUnavailable)?;
		let policy = channel
			.counterparty
			.forwarding_info
			.as_ref()
			.ok_or(Error::LiquiditySourceUnavailable)?;
		(
			scid,
			RoutingFees {
				base_msat: policy.fee_base_msat,
				proportional_millionths: policy.fee_proportional_millionths,
			},
			policy.cltv_expiry_delta.max(ROUTE_CLTV),
		)
	} else {
		(intercept_scid, RoutingFees { base_msat: 0, proportional_millionths: 0 }, ROUTE_CLTV)
	};
	Ok(RouteHintHop {
		src_node_id: peer,
		short_channel_id,
		fees,
		cltv_expiry_delta,
		htlc_minimum_msat: None,
		htlc_maximum_msat: None,
	})
}

// Do not request a new intercept while a primary channel is still opening or closing.
fn check_primary_channels_ready(peer: PublicKey, channels: &[ChannelDetails]) -> Result<(), Error> {
	if channels
		.iter()
		.any(|channel| channel.counterparty.node_id == peer && !channel.is_channel_ready)
	{
		return Err(Error::LiquiditySourceUnavailable);
	}
	Ok(())
}

// A splice cannot renegotiate an older channel's aggregate inbound limit. Check the actual
// delivered amount before authorizing an invoice, and again if the acknowledged fee changes.
fn check_primary_receive_limit(
	peer: PublicKey, channels: &[ChannelDetails], amount_msat: u64, fee_msat: u64,
) -> Result<(), Error> {
	check_primary_channels_ready(peer, channels)?;
	if let Some(channel) = channels
		.iter()
		.find(|channel| channel.counterparty.node_id == peer && channel.is_channel_ready)
	{
		let limit = channel
			.inbound_htlc_value_in_flight_maximum_msat
			.ok_or(Error::LiquiditySourceUnavailable)?;
		let delivered = amount_msat.checked_sub(fee_msat).ok_or(Error::InvalidAmount)?;
		if delivered > limit {
			return Err(Error::InvalidAmount);
		}
	}
	Ok(())
}

// A consumed caller identity is a durable replay tombstone, independent of whether
// its channel remains listed. The caller serializes this with channel creation.
pub(crate) fn reserve_channel_open_id<S: lightning::util::persist::KVStoreSync + ?Sized>(
	store: &S, id: u128,
) -> Result<(), Error> {
	const NAMESPACE: &str = "channel_open_ids";
	let key = id.to_string();
	match store.read(NAMESPACE, "", &key) {
		Ok(_) => return Err(Error::ChannelCreationFailed),
		Err(error) if error.kind() == lightning::io::ErrorKind::NotFound => {},
		Err(_) => return Err(Error::PersistenceFailed),
	}
	store.write(NAMESPACE, "", &key, vec![1]).map_err(|_| Error::PersistenceFailed)
}

// Bind the sender's onion total to the invoice amount. The authorized skim only
// reduces the transferred HTLC amount, not this original onion total.
fn register_primary_payment<C: AChannelManager>(
	manager: &C, amount_msat: u64, expiry_secs: u32,
) -> Result<(PaymentHash, PaymentSecret), Error>
where
	C::L: Clone,
{
	manager
		.get_cm()
		.create_inbound_payment(Some(amount_msat), expiry_secs, Some(MIN_FINAL_CLTV))
		.map_err(|_| Error::InvoiceCreationFailed)
}

impl Node {
	fn primary_receive_rejection(&self, stage: &str, reason: Option<&str>) -> Error {
		let error = primary_rejection_error(reason);
		log_info!(
			self.logger,
			"Primary receive {} rejected: {:?}; provider reason=\"{}\"",
			stage,
			error,
			primary_reason_for_log(reason)
		);
		error
	}

	fn check_primary_peer(&self, node_id: PublicKey) -> Result<(), Error> {
		if !*self.is_running.read().unwrap() {
			return Err(Error::NotRunning);
		}
		if self.config.primary_node_id != Some(node_id)
			|| !self.config.trusted_peers_0conf.contains(&node_id)
		{
			return Err(Error::LiquiditySourceUnavailable);
		}
		if !self.peer_manager.list_peers().iter().any(|peer| peer.counterparty_node_id == node_id) {
			return Err(Error::ConnectionFailed);
		}
		Ok(())
	}

	fn check_primary(
		&self, node_id: PublicKey, amount_msat: u64, target_inbound_sats: u64,
	) -> Result<(), Error> {
		self.check_primary_peer(node_id)?;
		if amount_msat == 0
			|| amount_msat > MAX_MONEY_MSAT
			|| target_inbound_sats > MAX_MONEY_MSAT / 1000
		{
			return Err(Error::InvalidAmount);
		}
		check_primary_channels_ready(
			node_id,
			&self.channel_manager.list_channels_with_counterparty(&node_id),
		)
	}

	fn request_primary_quote(
		&self, node_id: PublicKey, amount_msat: u64, target_inbound_sats: u64,
	) -> Result<JitQuote, Error> {
		let request = self.primary_client.quote(node_id, amount_msat, target_inbound_sats)?;
		self.peer_manager.process_events();
		self.runtime.try_block_on(request.receive_quote())?
	}

	/// Checks that the selected, connected primary supports the JIT receive protocol.
	///
	/// The peer must be configured with [`crate::Builder::set_primary_node`]. A well-formed
	/// response from that authenticated peer proves protocol support even when it declines the
	/// probe because liquidity is unavailable. This check neither reserves funds nor authorizes
	/// a payment, and does not require existing channels to be ready. Use
	/// [`Self::quote_primary_receive`] to check liquidity and fees for an actual receive amount.
	/// Unsupported peers, malformed responses and missing replies fail closed after at most
	/// the protocol response timeout.
	pub fn check_primary_connection(&self, node_id: PublicKey) -> Result<(), Error> {
		self.check_primary_peer(node_id)?;
		self.request_primary_quote(node_id, CONNECTION_PROBE_AMOUNT_MSAT, 0).map(|_| ())
	}

	/// Fetches a quote from the configured, connected primary without reserving capacity.
	///
	/// The peer must have been explicitly selected with [`crate::Builder::set_primary_node`].
	/// A timeout, declined quote, invalid fee, or different responding peer fails closed.
	/// Funding refusals, other refusals, response timeouts and amounts consumed by the fee
	/// have distinct errors. Provider text is retained only in bounded, escaped diagnostics.
	pub fn quote_primary_receive(
		&self, node_id: PublicKey, amount_msat: u64, target_inbound_sats: u64,
	) -> Result<PrimaryReceiveQuote, Error> {
		self.check_primary(node_id, amount_msat, target_inbound_sats)?;
		let quote = self.request_primary_quote(node_id, amount_msat, target_inbound_sats)?;
		if !quote.accepted {
			return Err(self.primary_receive_rejection("quote", quote.reason.as_deref()));
		}
		let fee_msat = fee_msat(amount_msat, quote.flat_fee_sat, quote.fee_ppm)?;
		check_primary_receive_limit(
			node_id,
			&self.channel_manager.list_channels_with_counterparty(&node_id),
			amount_msat,
			fee_msat,
		)?;
		Ok(PrimaryReceiveQuote { amount_msat, fee_msat, funding_sats: quote.funding_sats })
	}

	/// Authorizes a fixed-amount primary receive and returns its locally signed invoice.
	///
	/// The invoice is returned only after the selected primary acknowledges an intercept
	/// and its fee is within `max_fee_msat`. The fee may be withheld from the amount.
	/// Payment metadata persists the exact accepted ceiling before the invoice leaves this API.
	/// Unknown or changing fee modes are rejected. The caller must connect the primary first.
	/// Invoice and authorization lifetimes are capped at the providers' common ten-minute limit.
	pub fn receive_via_primary(
		&self, node_id: PublicKey, amount_msat: u64, description: &Description, expiry_secs: u32,
		max_fee_msat: u64, target_inbound_sats: u64,
	) -> Result<Invoice, Error> {
		self.check_primary(node_id, amount_msat, target_inbound_sats)?;
		if expiry_secs == 0 || expiry_secs > 86_400 {
			return Err(Error::InvalidInvoice);
		}
		let expiry_secs = expiry_secs.min(600);
		let quote = self.quote_primary_receive(node_id, amount_msat, target_inbound_sats)?;
		if quote.fee_msat > max_fee_msat {
			return Err(Error::LiquidityFeeTooHigh);
		}
		self.check_primary(node_id, amount_msat, target_inbound_sats)?;

		#[cfg(feature = "uniffi")]
		let description: lightning_invoice::Bolt11InvoiceDescription =
			maybe_try_convert_enum(description)?;
		#[cfg(not(feature = "uniffi"))]
		let description = description.clone();
		let (hash, secret) =
			register_primary_payment(self.channel_manager.as_ref(), amount_msat, expiry_secs)?;
		let request = self.primary_client.begin(
			node_id,
			wire::JIT_AUTHORIZATION,
			wire::JIT_ACK,
			|request_id| {
				JitAuthorization {
					request_id,
					payment_hash: Some(hash.0),
					max_amount_msat: amount_msat,
					expected_total_msat: Some(amount_msat),
					target_remaining_inbound_sat: target_inbound_sats,
					expiry_seconds: expiry_secs,
					accepts_skimmed_fee: true,
				}
				.encode()
			},
		)?;
		self.peer_manager.process_events();
		let response = self.runtime.try_block_on(request.receive())??;
		let ack = JitAck::decode(&response.payload).map_err(|_| Error::LiquidityRequestFailed)?;
		if !ack.accepted {
			return Err(self.primary_receive_rejection("authorization", ack.reason.as_deref()));
		}
		if ack.intercept_scid == 0 || ack.fee_mode == Some(FeeMode::Hop) {
			return Err(Error::LiquidityRequestFailed);
		}
		let accepted_fee = fee_msat(amount_msat, ack.flat_fee_sat, ack.fee_ppm)?;
		if accepted_fee > max_fee_msat {
			return Err(Error::LiquidityFeeTooHigh);
		}
		let channels = self.channel_manager.list_channels_with_counterparty(&node_id);
		check_primary_receive_limit(node_id, &channels, amount_msat, accepted_fee)?;
		let channel_ids: Vec<_> = channels.iter().map(|channel| channel.channel_id).collect();
		if !channel_ids.is_empty() {
			self.channel_manager
				.update_partial_channel_config(
					&node_id,
					&channel_ids,
					&ChannelConfigUpdate {
						accept_underpaying_htlcs: Some(true),
						..Default::default()
					},
				)
				.map_err(|_| Error::ChannelConfigUpdateFailed)?;
		}
		let route = primary_receive_route(node_id, &channels, ack.intercept_scid)?;
		let invoice = InvoiceBuilder::new(self.config.network.into())
			.invoice_description(description.clone())
			.payment_hash(sha256::Hash::from_byte_array(hash.0))
			.payment_secret(secret)
			.current_timestamp()
			.min_final_cltv_expiry_delta(u64::from(MIN_FINAL_CLTV))
			.expiry_time(Duration::from_secs(u64::from(expiry_secs)))
			.amount_milli_satoshis(amount_msat)
			.basic_mpp()
			.private_route(RouteHint(vec![route]))
			.build_signed(|message| {
				Secp256k1::new()
					.sign_ecdsa_recoverable(message, &self.keys_manager.get_node_secret_key())
			})
			.map_err(|_| Error::InvoiceCreationFailed)?;
		let preimage = self.channel_manager.get_payment_preimage(hash, secret).ok();
		let description = match invoice.description() {
			lightning_invoice::Bolt11InvoiceDescriptionRef::Direct(description) => {
				description.to_string()
			},
			lightning_invoice::Bolt11InvoiceDescriptionRef::Hash(hash) => {
				crate::hex_utils::to_string(hash.0.as_ref())
			},
		};
		self.payment_store.insert(PaymentDetails::new(
			PaymentId(hash.0),
			PaymentKind::Bolt11Jit {
				hash,
				preimage,
				secret: Some(secret),
				counterparty_skimmed_fee_msat: None,
				lsp_fee_limits: LSPFeeLimits {
					max_total_opening_fee_msat: Some(accepted_fee),
					max_proportional_opening_fee_ppm_msat: None,
				},
				description: Some(description),
				bolt11: Some(invoice.to_string()),
			},
			Some(amount_msat),
			None,
			PaymentDirection::Inbound,
			PaymentStatus::Pending,
		))?;
		Ok(maybe_wrap(invoice))
	}

	/// Fetches transaction contents from the configured backend, verifying its transaction ID.
	/// This is a content lookup, not proof of confirmation. For transactions outside the BDK
	/// wallet, `amount_sats` is zero because wallet ownership cannot be inferred from chain data.
	pub fn fetch_transaction_details(
		&self, txid: &bitcoin::Txid,
	) -> Result<TransactionDetails, Error> {
		if !*self.is_running.read().unwrap() {
			return Err(Error::NotRunning);
		}
		let transaction =
			self.runtime.try_block_on(self.chain_source.fetch_transaction(*txid))??;
		Ok(TransactionDetails {
			amount_sats: self
				.get_transaction_details(txid)
				.map_or(0, |details| details.amount_sats),
			inputs: transaction.input.iter().map(TxInput::from_tx_input).collect(),
			outputs: transaction
				.output
				.iter()
				.enumerate()
				.map(|(index, output)| {
					TxOutput::from_tx_output(output, index as u32, self.config.network)
				})
				.collect(),
		})
	}

	/// Returns whether native channel funding or splicing is currently in flight.
	/// Callers should defer automatic wallet funding while this is true, including after restart.
	pub fn has_pending_funding_operation(&self) -> bool {
		self.channel_manager.has_pending_funding_operation()
			|| self.direct_funding.receiver.has_pending()
	}

	/// Returns chain-backend estimates, using the node's conservative fallback when unsynced.
	/// Estimates are rounded upward and are not transaction quotes or fee guarantees.
	pub fn estimated_fee_rates(&self) -> OnchainFeeRates {
		let rate = |target| {
			self.fee_estimator.estimate_fee_rate(target).to_sat_per_kwu().div_ceil(250).max(1)
		};
		let slow = rate(ConfirmationTarget::ChannelFunding);
		let normal = rate(ConfirmationTarget::OnchainPayment).max(slow);
		OnchainFeeRates {
			fast_sat_per_vbyte: rate(LdkConfirmationTarget::MaximumFeeEstimate.into()).max(normal),
			normal_sat_per_vbyte: normal,
			slow_sat_per_vbyte: slow,
			channel_funding_sat_per_vbyte: slow,
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::secp256k1::SecretKey;
	use lightning::events::HTLCHandlingFailureType;
	use lightning::ln::channel_state::CounterpartyForwardingInfo;
	use lightning::ln::channelmanager::{RecipientOnionFields, Retry};
	use lightning::ln::functional_test_utils::{
		check_added_monitors, claim_payment, create_announced_chan_between_nodes,
		create_chanmon_cfgs, create_network, create_node_cfgs, create_node_chanmgrs,
		do_pass_along_path, expect_payment_failed_conditions, fail_payment_along_path,
		PassAlongPathArgs, PaymentFailedConditions,
	};
	use lightning::ln::msgs::BaseMessageHandler;
	use lightning::routing::router::{PaymentParameters, RouteParameters};
	use lightning::util::config::ChannelHandshakeConfig;
	use lightning::util::ser::{Readable, Writeable};
	#[cfg(feature = "chicory")]
	use std::sync::Arc;

	#[cfg(feature = "chicory")]
	fn pairing_test_node(seed: u8, primary: Option<PublicKey>) -> Node {
		let config =
			crate::config::Config { network: bitcoin::Network::Regtest, ..Default::default() };
		let mut builder = crate::builder::NodeBuilder::from_config(config);
		builder.set_chain_source_esplora("http://127.0.0.1:1".into(), None);
		builder.set_entropy_seed_bytes([seed; 64]);
		builder.set_log_facade_logger();
		if let Some(primary) = primary {
			builder.set_primary_node(primary);
		} else {
			builder
				.set_chicory_service(crate::chicory::JitServiceConfig {
					enabled: true,
					..Default::default()
				})
				.unwrap();
		}
		builder.build_with_store(Arc::new(crate::io::test_utils::InMemoryStore::new())).unwrap()
	}

	#[cfg(feature = "chicory")]
	#[test]
	fn primary_pairing_accepts_unfunded_provider_without_approving_receives() {
		let provider = pairing_test_node(41, None);
		let primary = provider.node_id();
		let client = pairing_test_node(42, Some(primary));
		assert_eq!(client.check_primary_connection(primary), Err(Error::NotRunning));
		*client.is_running.write().unwrap() = true;
		assert_eq!(
			client.check_primary_connection(peer(3)),
			Err(Error::LiquiditySourceUnavailable)
		);
		assert_eq!(client.check_primary_connection(primary), Err(Error::ConnectionFailed));
		let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let address = listener.local_addr().unwrap();
		listener.set_nonblocking(true).unwrap();
		let manager = Arc::clone(&provider.peer_manager);
		provider.runtime.spawn_cancellable_background_task(async move {
			let listener = tokio::net::TcpListener::from_std(listener).unwrap();
			let stream = listener.accept().await.unwrap().0.into_std().unwrap();
			lightning_net_tokio::setup_inbound(manager, stream).await;
		});
		client.connect(primary, address.into(), false).unwrap();
		assert_eq!(provider.list_balances().total_onchain_balance_sats, 0);
		assert_eq!(client.check_primary_connection(primary), Ok(()));
		assert_eq!(
			client.quote_primary_receive(primary, 100_000_000, 10_000),
			Err(Error::LiquiditySourceInsufficientFunds)
		);
		let description = lightning_invoice::Bolt11InvoiceDescription::Direct(
			lightning_invoice::Description::new("Unfunded primary".into()).unwrap(),
		);
		#[cfg(feature = "uniffi")]
		let description = description.into();
		assert!(matches!(
			client.receive_via_primary(primary, 100_000_000, &description, 600, 1_000_000, 10_000),
			Err(Error::LiquiditySourceInsufficientFunds)
		));
		assert!(client.list_payments().is_empty());
		assert!(client.list_channels().is_empty());
		assert!(provider.list_channels().is_empty());
		client.disconnect(primary).unwrap();
		assert_eq!(client.check_primary_connection(primary), Err(Error::ConnectionFailed));
		*client.is_running.write().unwrap() = false;
	}

	fn probe_reply(request_id: [u8; 8], accepted: bool) -> Envelope {
		Envelope {
			version: wire::PROTOCOL_VERSION,
			subtype: wire::JIT_QUOTE,
			payload: JitQuote {
				request_id,
				accepted,
				flat_fee_sat: 100,
				fee_ppm: 1000,
				max_client_funding_sats: 1_000_000,
				funding_sats: if accepted { 20_000 } else { 0 },
				reason: (!accepted)
					.then(|| "provider wallet has insufficient available funds".into()),
			}
			.encode(),
		}
	}

	#[test]
	fn protocol_probe_requires_complete_canonical_quote_reply() {
		let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
		let client = PrimaryClient::new(Some(peer(1)));
		for accepted in [false, true] {
			let request = client.quote(peer(1), CONNECTION_PROBE_AMOUNT_MSAT, 0).unwrap();
			let outgoing = client.take_messages();
			assert_eq!(outgoing.len(), 1);
			let outgoing = JitQuoteRequest::decode(&outgoing[0].1.payload).unwrap();
			assert_eq!(outgoing.max_amount_msat, 1000);
			assert_eq!(outgoing.target_remaining_inbound_sat, 0);
			client.handle_message(peer(1), &probe_reply(request.id, accepted));
			assert_eq!(runtime.block_on(request.receive_quote()).unwrap().accepted, accepted);
		}
		for length in 8..39 {
			let request = client.quote(peer(1), CONNECTION_PROBE_AMOUNT_MSAT, 0).unwrap();
			let mut response = probe_reply(request.id, false);
			response.payload.truncate(length);
			client.handle_message(peer(1), &response);
			assert_eq!(
				runtime.block_on(request.receive_quote()),
				Err(Error::LiquidityRequestFailed)
			);
		}
		for flag in 2..=255 {
			let request = client.quote(peer(1), CONNECTION_PROBE_AMOUNT_MSAT, 0).unwrap();
			let mut response = probe_reply(request.id, false);
			response.payload[8] = flag;
			client.handle_message(peer(1), &response);
			assert_eq!(
				runtime.block_on(request.receive_quote()),
				Err(Error::LiquidityRequestFailed)
			);
		}
		assert!(client.state.lock().unwrap().pending.is_empty());
		assert!(client.take_messages().is_empty());
	}

	#[test]
	fn unsupported_peer_and_uncorrelated_probe_replies_time_out_and_clean_up() {
		let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
		let client = PrimaryClient::new(Some(peer(1)));
		let ignored = client.quote(peer(1), CONNECTION_PROBE_AMOUNT_MSAT, 0).unwrap();
		let invalid = client.quote(peer(1), CONNECTION_PROBE_AMOUNT_MSAT, 0).unwrap();
		let response = probe_reply(invalid.id, false);
		client.handle_message(peer(2), &response);
		client.handle_message(peer(1), &Envelope { version: 2, ..response.clone() });
		client.handle_message(peer(1), &Envelope { subtype: wire::JIT_ACK, ..response.clone() });
		let mut wrong_id = response;
		wrong_id.payload[0] ^= 1;
		client.handle_message(peer(1), &wrong_id);
		let (ignored, invalid) = runtime
			.block_on(async { tokio::join!(ignored.receive_quote(), invalid.receive_quote()) });
		assert_eq!(ignored, Err(Error::LiquidityRequestTimedOut));
		assert_eq!(invalid, Err(Error::LiquidityRequestTimedOut));
		assert!(client.state.lock().unwrap().pending.is_empty());
		assert!(client.take_messages().is_empty());
	}

	#[test]
	fn pending_primary_channel_blocks_receive_without_affecting_other_peers() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		create_announced_chan_between_nodes(&nodes, 0, 1);
		let primary = nodes[1].node.get_our_node_id();
		let mut channels = nodes[0].node.list_channels();
		let mut pending = channels[0].clone();
		pending.is_channel_ready = false;
		channels.push(pending);
		assert_eq!(
			check_primary_channels_ready(primary, &channels),
			Err(Error::LiquiditySourceUnavailable)
		);
		assert_eq!(
			check_primary_receive_limit(primary, &channels, 1000, 100),
			Err(Error::LiquiditySourceUnavailable)
		);
		channels[1].counterparty.node_id = peer(42);
		assert!(check_primary_channels_ready(primary, &channels).is_ok());
		assert!(check_primary_channels_ready(primary, &channels[1..]).is_ok());
		assert!(check_primary_channels_ready(primary, &[]).is_ok());
	}

	#[test]
	fn splice_handshake_policy_is_only_for_selected_private_primary() {
		let mut config = crate::config::Config::default();
		for selected in [None, Some(peer(1))] {
			config.primary_node_id = selected;
			for target in [peer(1), peer(2)] {
				for announced in [false, true] {
					let mut handshake = ChannelHandshakeConfig::default();
					handshake.apply(&primary_channel_handshake(&config, target, announced));
					let primary = selected == Some(target) && !announced;
					assert_eq!(
						handshake.max_inbound_htlc_value_in_flight_msat,
						primary.then_some(MAX_MONEY_MSAT)
					);
					assert_eq!(handshake.retain_counterparty_htlc_limit_for_splicing, primary);
					assert_eq!(handshake.max_inbound_htlc_value_in_flight_percent_of_channel, 10);
				}
			}
		}
	}

	#[test]
	fn legacy_primary_limit_refuses_oversized_receive_and_counts_net_amount() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		create_announced_chan_between_nodes(&nodes, 0, 1);
		let peer = nodes[1].node.get_our_node_id();
		let mut channels = nodes[0].node.list_channels();
		channels[0].inbound_htlc_value_in_flight_maximum_msat = Some(48_200_000);
		assert_eq!(
			check_primary_receive_limit(peer, &channels, 100_000_000, 200_000),
			Err(Error::InvalidAmount)
		);
		assert!(check_primary_receive_limit(peer, &channels, 48_400_000, 200_000).is_ok());
		let encoded = channels[0].encode();
		let restored = ChannelDetails::read(&mut &encoded[..]).unwrap();
		assert_eq!(restored.inbound_htlc_value_in_flight_maximum_msat, Some(48_200_000));
		let mut runner = proptest::test_runner::TestRunner::default();
		runner
			.run(
				&(0u64..MAX_MONEY_MSAT, 0u64..MAX_MONEY_MSAT, 1u64..MAX_MONEY_MSAT),
				|(amount, fee, limit)| {
					let mut channels = channels.clone();
					channels[0].inbound_htlc_value_in_flight_maximum_msat = Some(limit);
					let expected = amount.checked_sub(fee).is_some_and(|net| net <= limit);
					proptest::prop_assert_eq!(
						check_primary_receive_limit(peer, &channels, amount, fee).is_ok(),
						expected
					);
					Ok(())
				},
			)
			.unwrap();
		channels[0].inbound_htlc_value_in_flight_maximum_msat = None;
		assert_eq!(
			check_primary_receive_limit(peer, &channels, 100_000, 1000),
			Err(Error::LiquiditySourceUnavailable)
		);
		let encoded = channels[0].encode();
		assert_eq!(
			ChannelDetails::read(&mut &encoded[..])
				.unwrap()
				.inbound_htlc_value_in_flight_maximum_msat,
			None
		);
	}

	#[test]
	fn primary_route_preserves_existing_channel_policy() {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		create_announced_chan_between_nodes(&nodes, 0, 1);
		let peer = nodes[1].node.get_our_node_id();
		let mut channels = nodes[0].node.list_channels();
		channels[0].inbound_scid_alias = Some(42);
		for cltv_expiry_delta in [40, 144] {
			channels[0].counterparty.forwarding_info = Some(CounterpartyForwardingInfo {
				fee_base_msat: 1000,
				fee_proportional_millionths: 7,
				cltv_expiry_delta,
			});
			let hint = primary_receive_route(peer, &channels, 99).unwrap();
			assert_eq!(hint.short_channel_id, 42);
			assert_eq!(hint.fees.base_msat, 1000);
			assert_eq!(hint.fees.proportional_millionths, 7);
			assert_eq!(hint.cltv_expiry_delta, cltv_expiry_delta.max(ROUTE_CLTV));
		}
		channels[0].inbound_scid_alias = None;
		assert_eq!(
			primary_receive_route(peer, &channels, 99).unwrap().short_channel_id,
			channels[0].short_channel_id.unwrap()
		);
		channels[0].counterparty.forwarding_info = None;
		assert_eq!(
			primary_receive_route(peer, &channels, 99),
			Err(Error::LiquiditySourceUnavailable)
		);
	}

	#[test]
	fn primary_intercept_route_has_zero_routing_fees() {
		let hint = primary_receive_route(peer(1), &[], 99).unwrap();
		assert_eq!(hint.short_channel_id, 99);
		assert_eq!(hint.fees.base_msat, 0);
		assert_eq!(hint.fees.proportional_millionths, 0);
		assert_eq!(hint.cltv_expiry_delta, ROUTE_CLTV);
	}

	#[test]
	fn caller_open_ids_are_one_shot_across_independent_reservations() {
		let store = crate::io::test_utils::InMemoryStore::new();
		assert!(reserve_channel_open_id(&store, 42).is_ok());
		// No in-memory cache or live channel is needed to refuse the replay.
		assert_eq!(reserve_channel_open_id(&store, 42), Err(Error::ChannelCreationFailed));
		assert!(reserve_channel_open_id(&store, u128::MAX).is_ok());
		assert_eq!(reserve_channel_open_id(&store, u128::MAX), Err(Error::ChannelCreationFailed));
	}

	#[test]
	fn caller_open_ids_remain_consumed_in_an_independent_store_connection() {
		let directory =
			std::env::temp_dir().join(format!("primary-open-id-{}", rand::random::<u128>()));
		// SqliteStore's test-only Drop deletes its directory, so keep the original
		// connection alive while opening the independent persistence reader.
		let first =
			crate::io::sqlite_store::SqliteStore::new(directory.clone(), None, None).unwrap();
		reserve_channel_open_id(&first, 17).unwrap();
		let reopened = crate::io::sqlite_store::SqliteStore::new(directory, None, None).unwrap();
		assert_eq!(reserve_channel_open_id(&reopened, 17), Err(Error::ChannelCreationFailed));
	}

	#[test]
	fn caller_open_id_storage_errors_fail_closed() {
		struct BrokenStore {
			read_fails: bool,
		}
		impl lightning::util::persist::KVStoreSync for BrokenStore {
			fn read(&self, _: &str, _: &str, _: &str) -> Result<Vec<u8>, lightning::io::Error> {
				Err(lightning::io::Error::new(
					if self.read_fails {
						lightning::io::ErrorKind::Other
					} else {
						lightning::io::ErrorKind::NotFound
					},
					"test",
				))
			}
			fn write(
				&self, _: &str, _: &str, _: &str, _: Vec<u8>,
			) -> Result<(), lightning::io::Error> {
				assert!(!self.read_fails, "read failure must stop before writing");
				Err(lightning::io::Error::new(lightning::io::ErrorKind::Other, "test"))
			}
			fn remove(
				&self, _: &str, _: &str, _: &str, _: bool,
			) -> Result<(), lightning::io::Error> {
				panic!("reservations are never removed")
			}
			fn list(&self, _: &str, _: &str) -> Result<Vec<String>, lightning::io::Error> {
				panic!("unused")
			}
		}
		for read_fails in [false, true] {
			assert_eq!(
				reserve_channel_open_id(&BrokenStore { read_fails }, 7),
				Err(Error::PersistenceFailed)
			);
		}
	}

	#[test]
	fn primary_payment_secret_rejects_lower_onion_total() {
		for paid_msat in [1_988_000, 2_000_000] {
			let chanmon_cfgs = create_chanmon_cfgs(2);
			let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
			let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, None]);
			let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
			create_announced_chan_between_nodes(&nodes, 0, 1);
			let (hash, secret) = register_primary_payment(nodes[1].node, 2_000_000, 600).unwrap();
			let params = PaymentParameters::from_node_id(
				nodes[1].node.get_our_node_id(),
				u32::from(MIN_FINAL_CLTV),
			)
			.with_bolt11_features(nodes[1].node.bolt11_invoice_features())
			.unwrap();
			nodes[0]
				.node
				.send_payment(
					hash,
					RecipientOnionFields::secret_only(secret),
					PaymentId(hash.0),
					RouteParameters::from_payment_params_and_value(params, paid_msat),
					Retry::Attempts(0),
				)
				.unwrap();
			check_added_monitors(&nodes[0], 1);
			let mut messages = nodes[0].node.get_and_clear_pending_msg_events();
			assert_eq!(messages.len(), 1);
			let path = [&nodes[1]];
			let preimage = nodes[1].node.get_payment_preimage(hash, secret).unwrap();
			let args =
				PassAlongPathArgs::new(&nodes[0], &path, paid_msat, hash, messages.remove(0))
					.with_payment_secret(secret)
					.with_payment_preimage(preimage);
			if paid_msat < 2_000_000 {
				assert!(do_pass_along_path(
					args.expect_failure(HTLCHandlingFailureType::Receive { payment_hash: hash })
				)
				.is_none());
				fail_payment_along_path(&[&nodes[0], &nodes[1]]);
				expect_payment_failed_conditions(
					&nodes[0],
					hash,
					true,
					PaymentFailedConditions::new(),
				);
			} else {
				assert!(do_pass_along_path(args).is_some());
				claim_payment(&nodes[0], &path, preimage);
			}
		}
	}

	fn peer(value: u8) -> PublicKey {
		PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[value; 32]).unwrap())
	}

	proptest::proptest! {
		#[test]
		fn bounded_fee_matches_provider_integer_formula(amount in 1u64..MAX_MONEY_MSAT, flat in 0u64..1_000_000, ppm in 0u32..1_000_001) {
			let expected = u128::from(flat) * 1000 + u128::from(amount) * u128::from(ppm) / 1_000_000;
			match fee_msat(amount, flat, ppm) {
				Ok(actual) => { proptest::prop_assert_eq!(u128::from(actual), expected); proptest::prop_assert!(actual < amount); },
				Err(error) => {
					proptest::prop_assert!(expected >= u128::from(amount));
					proptest::prop_assert_eq!(error, Error::LiquidityReceiveAmountTooSmall);
				},
			}
		}

		#[test]
		fn provider_diagnostics_remain_bounded_and_single_line(reason in ".*") {
			let diagnostic = primary_reason_for_log(Some(&reason));
			proptest::prop_assert!(diagnostic.len() <= 200 * 10);
			proptest::prop_assert!(!diagnostic.chars().any(char::is_control));
		}
	}

	#[test]
	fn provider_refusals_preserve_funding_and_fee_errors_without_guessing_unknown_reasons() {
		for reason in [
			"provider wallet has insufficient available funds",
			"provider lacks confirmed native-witness funds for this splice",
			"the provider does not hold enough on-chain funds to front this receive right now",
		] {
			assert_eq!(
				primary_rejection_error(Some(reason)),
				Error::LiquiditySourceInsufficientFunds
			);
		}
		assert_eq!(
			primary_rejection_error(Some("opening fee consumes payment")),
			Error::LiquidityReceiveAmountTooSmall
		);
		for reason in [
			None,
			Some(""),
			Some("provider lifetime funding budget exhausted"),
			Some("the provider has reached its lifetime funding budget"),
			Some("provider has a native funding operation in progress"),
			Some("unknown provider failure"),
			Some("provider wallet has insufficient available funds\nforged log entry"),
		] {
			assert_eq!(primary_rejection_error(reason), Error::LiquidityRequestRejected);
		}
	}

	#[test]
	fn provider_diagnostics_escape_controls_and_truncate_at_character_boundaries() {
		assert_eq!(
			primary_reason_for_log(Some("declined\n\r\t\0\u{1b}\"\\")),
			"declined\\n\\r\\t\\0\\u{1b}\\\"\\\\"
		);
		assert_eq!(primary_reason_for_log(Some(&"é".repeat(300))), "é".repeat(200));
		assert_eq!(primary_reason_for_log(None), "No reason supplied");
	}

	#[test]
	fn cancelled_authorizations_remove_hash_prefixed_wire_message() {
		let client = PrimaryClient::new(Some(peer(1)));
		let request = client
			.begin(peer(1), wire::JIT_AUTHORIZATION, wire::JIT_ACK, |request_id| {
				JitAuthorization {
					request_id,
					payment_hash: Some([3; 32]),
					max_amount_msat: 1000,
					expected_total_msat: Some(1000),
					target_remaining_inbound_sat: 0,
					expiry_seconds: 60,
					accepts_skimmed_fee: true,
				}
				.encode()
			})
			.unwrap();
		assert_eq!(client.state.lock().unwrap().messages.len(), 1);
		drop(request);
		assert!(client.take_messages().is_empty());
	}

	#[test]
	fn fees_use_provider_rounding_and_reject_overflow_or_full_amount() {
		assert_eq!(fee_msat(20_000_000, 100, 1000).unwrap(), 120_000);
		assert_eq!(fee_msat(1_000_001, 0, 1).unwrap(), 1);
		assert_eq!(fee_msat(1000, 1, 0), Err(Error::LiquidityReceiveAmountTooSmall));
		assert_eq!(fee_msat(999, 1, 0), Err(Error::LiquidityReceiveAmountTooSmall));
		assert_eq!(fee_msat(1000, 0, 1_000_000), Err(Error::LiquidityReceiveAmountTooSmall));
		assert_eq!(fee_msat(u64::MAX, u64::MAX, 0), Err(Error::LiquidityRequestFailed));
		assert_eq!(fee_msat(1000, 0, 1_000_001), Err(Error::LiquidityRequestFailed));
	}

	#[test]
	fn replies_require_exact_peer_version_type_and_correlation() {
		let client = PrimaryClient::new(Some(peer(1)));
		let mut request = client
			.begin(peer(1), wire::JIT_QUOTE_REQUEST, wire::JIT_QUOTE, |id| id.to_vec())
			.unwrap();
		let message =
			Envelope { version: 1, subtype: wire::JIT_QUOTE, payload: request.id.to_vec() };
		client.handle_message(peer(2), &message);
		client.handle_message(peer(1), &Envelope { version: 2, ..message.clone() });
		client.handle_message(peer(1), &Envelope { subtype: wire::JIT_ACK, ..message.clone() });
		client.handle_message(peer(1), &Envelope { payload: vec![0; 8], ..message.clone() });
		assert_eq!(client.state.lock().unwrap().pending.len(), 1);
		client.handle_message(peer(1), &message);
		assert_eq!(request.reply.as_mut().unwrap().try_recv().unwrap(), message);
		assert!(client.state.lock().unwrap().pending.is_empty());
	}

	#[test]
	fn cancellation_disconnect_and_bounds_release_requests() {
		let client = PrimaryClient::new(Some(peer(1)));
		assert!(client.begin(peer(2), 4, 5, |id| id.to_vec()).is_err());
		let mut requests = Vec::new();
		for _ in 0..MAX_PENDING {
			requests.push(client.begin(peer(1), 4, 5, |id| id.to_vec()).unwrap());
		}
		assert!(client.begin(peer(1), 4, 5, |id| id.to_vec()).is_err());
		requests.clear();
		assert!(client.take_messages().is_empty());
		assert!(client.state.lock().unwrap().pending.is_empty());
		let mut request = client.begin(peer(1), 4, 5, |id| id.to_vec()).unwrap();
		client.disconnected(peer(1));
		assert_eq!(
			request.reply.as_mut().unwrap().try_recv(),
			Err(oneshot::error::TryRecvError::Closed)
		);
		assert!(client.take_messages().is_empty());
	}
}
