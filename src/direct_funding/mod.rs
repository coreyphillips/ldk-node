//! Native endpoints for Beignet v3 third-party channel funding.
//!
//! A request binds the receiver identity, network, amount and expiry. Funds are
//! committed only after the payer verifies the exact negotiated transaction.
//! Durable records precede every witness release; an interrupted exchange after
//! that point remains pending and must never authorize a second payment.

#![forbid(unsafe_code)]

mod api;
pub(crate) mod codec;
pub(crate) mod crypto;
mod receiver;
pub(crate) mod sender;
mod transport;

use std::fmt;
use std::sync::Arc;

pub(crate) struct Service {
	pub sender: sender::Sender,
	pub receiver: receiver::Receiver,
	pub transport: Arc<transport::Transport>,
}

impl Service {
	pub(crate) fn new(
		wallet: Arc<crate::types::Wallet>, manager: Arc<crate::types::ChannelManager>,
		keys: Arc<crate::types::KeysManager>, chain: Arc<crate::chain::ChainSource>,
		fees: Arc<crate::fee_estimator::OnchainFeeEstimator>, store: Arc<crate::types::DynStore>,
		config: Arc<crate::config::Config>,
	) -> Result<Self, crate::builder::BuildError> {
		let transport =
			Arc::new(transport::Transport::new(bitcoin::secp256k1::PublicKey::from_secret_key(
				&bitcoin::secp256k1::Secp256k1::signing_only(),
				&keys.get_node_secret_key(),
			)));
		let sender = sender::Sender::new(
			wallet,
			Arc::clone(&chain),
			Arc::clone(&store),
			Arc::clone(&config),
			Arc::clone(&manager),
		)
		.map_err(|_| crate::builder::BuildError::ReadFailed)?;
		let receiver = receiver::Receiver::new(
			manager,
			keys,
			chain,
			fees,
			store,
			config,
			Arc::clone(&transport),
		)?;
		Ok(Self { sender, receiver, transport })
	}
}

/// A verified payment request suitable for displaying in a BIP21 `bgnq` field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectFundingRequestDetails {
	/// Canonical signed base64url envelope.
	pub request: String,
	/// Stable identity used for retries.
	pub request_id: String,
	/// Hash of the delivery receipt preimage, used to identify this payment.
	pub payment_hash: String,
	/// Receiver's authenticated Lightning node identity.
	pub receiver_node_id: String,
	/// Requested amount, absent when the payer chooses it.
	pub amount_sats: Option<u64>,
	/// Signed expiration in milliseconds since the Unix epoch.
	pub expires_at: u64,
}

/// Durable status of a channel-funding payment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectFundingPaymentStatus {
	/// Negotiation is in progress and no witness has been released.
	Offered,
	/// A witness may have been released; do not make another payment.
	SignedPending,
	/// The funding transaction has been observed in the mempool.
	MempoolSeen,
	/// The funding transaction has been confirmed.
	Confirmed,
	/// The attempt was abandoned before signing.
	Aborted,
	/// The attempt failed, including a confirmed conflicting spend after signing.
	/// This status does not by itself authorize another payment using a different rail.
	Failed,
}

/// Secret-free payment information for wallet activity and restart recovery.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectFundingPaymentDetails {
	/// Signed request identifier.
	pub request_id: String,
	/// Stable delivery receipt hash.
	pub payment_hash: String,
	/// Value contributed to the receiving channel.
	pub amount_sats: u64,
	/// Payer's fee when the exact transaction is known; zero for the receiver.
	pub fee_sats: Option<u64>,
	/// Negotiated funding transaction identifier, when known.
	pub funding_txid: Option<String>,
	/// Current durable payment state.
	pub status: DirectFundingPaymentStatus,
	/// True for payments sent by this wallet.
	pub is_outbound: bool,
	/// Time this payment was first recorded, in Unix milliseconds.
	pub created_at: u64,
}

fn request_details(
	request: &codec::RequestEnvelope, encoded: String,
) -> DirectFundingRequestDetails {
	DirectFundingRequestDetails {
		request: encoded,
		request_id: codec::hex(&request.request_id),
		payment_hash: codec::hex(&request.receipt_hash),
		receiver_node_id: request.receiver_node_id.to_string(),
		amount_sats: request.amount_sat,
		expires_at: request.expires_at,
	}
}

/// A refusal before a direct-funding payment commits a spendable witness.
/// Pending committed payments are returned as payment records, never as errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirectFundingError {
	/// The request is malformed or its signature is invalid.
	InvalidRequest,
	/// The request is no longer payable.
	Expired,
	/// The request belongs to another Bitcoin network.
	WrongNetwork,
	/// An amountless request needs a payer-selected amount.
	AmountRequired,
	/// The selected amount contradicts the signed request.
	AmountMismatch,
	/// No available confirmed wallet coin covers the amount and fee ceiling.
	InsufficientFunds,
	/// No supported transport or eligible primary channel is available.
	Unavailable,
	/// The receiver declined before any witness was released.
	Declined,
	/// The negotiated transaction or ownership proof failed validation.
	InvalidFunding,
	/// Durable storage could not record a required transition.
	PersistenceFailed,
	/// The native node is not running.
	NotRunning,
	/// The configured chain source could not establish required evidence.
	ChainUnavailable,
	/// The exchange expired before any witness was released.
	Timeout,
	/// Another funding operation or the bounded session limit prevents admission.
	Busy,
}

impl fmt::Display for DirectFundingError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.write_str(match self {
			Self::InvalidRequest => "Invalid direct-funding request",
			Self::Expired => "Direct-funding request expired",
			Self::WrongNetwork => "Direct-funding request is for another network",
			Self::AmountRequired => "Direct-funding request requires an amount",
			Self::AmountMismatch => "Direct-funding amount does not match the request",
			Self::InsufficientFunds => "No confirmed coin covers direct funding and its fee limit",
			Self::Unavailable => "Direct funding is unavailable",
			Self::Declined => "Direct-funding offer was declined",
			Self::InvalidFunding => "Direct-funding transaction failed validation",
			Self::PersistenceFailed => "Direct-funding state could not be persisted",
			Self::NotRunning => "Node is not running",
			Self::ChainUnavailable => "Direct-funding chain evidence is unavailable",
			Self::Timeout => "Direct funding timed out before signing",
			Self::Busy => "Another channel funding operation is pending",
		})
	}
}

impl std::error::Error for DirectFundingError {}

pub(crate) fn now_ms() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
		.unwrap_or(0)
}
