use super::sender::{SendResult, SenderPaymentStatus};
use super::{
	request_details, DirectFundingError as Error, DirectFundingPaymentDetails,
	DirectFundingPaymentStatus as Status, DirectFundingRequestDetails,
};
use crate::Node;

impl Node {
	/// Mint a signed Beignet v3 request, routed through the configured primary.
	/// The primary must be connected and support confirmed v2 channels/splices and
	/// direct-funding relay. No channel is created until a payer offers a verified coin.
	/// The amount, when specified, must be at least 5,000 sats; lifetime is 1..=3,600 seconds.
	pub fn create_direct_funding_request(
		&self, amount_sats: Option<u64>, expiry_secs: u32,
	) -> Result<DirectFundingRequestDetails, Error> {
		if !*self.is_running.read().unwrap() {
			return Err(Error::NotRunning);
		}
		if self.channel_manager.has_pending_funding_operation() {
			return Err(Error::Busy);
		}
		let primary = self.config.primary_node_id.ok_or(Error::Unavailable)?;
		let peer = self
			.list_peers()
			.into_iter()
			.find(|p| p.node_id == primary && p.is_connected)
			.ok_or(Error::Unavailable)?;
		let address = peer.address.to_string();
		let (host, port) = address.rsplit_once(':').ok_or(Error::Unavailable)?;
		let port = port.parse().map_err(|_| Error::Unavailable)?;
		self.direct_funding.receiver.mint(
			amount_sats,
			expiry_secs,
			host.trim_matches(['[', ']']).to_owned(),
			port,
		)
	}

	/// Authenticate a direct-funding request without connecting or spending funds.
	/// Wrong-network, expired and malformed new requests are refused locally.
	pub fn decode_direct_funding_request(
		&self, request: String,
	) -> Result<DirectFundingRequestDetails, Error> {
		let prepared = self.direct_funding.sender.prepare(&request, None)?;
		let mut details = request_details(&prepared.envelope, request);
		details.amount_sats = prepared.amount_sats;
		Ok(details)
	}

	/// Revoke an unpaid request after another rail of a combined invoice settles.
	/// A payment which may already have released a witness cannot be revoked and
	/// returns `Busy`; callers must continue tracking that payment to settlement.
	pub fn invalidate_direct_funding_request(&self, request_id: String) -> Result<(), Error> {
		self.direct_funding.receiver.invalidate(&request_id)
	}

	/// Verify the signed request and selected amount, then establish its transport.
	/// This does not select, reserve or spend a coin.
	pub fn prepare_direct_funding(
		&self, request: String, amount_sats: Option<u64>,
	) -> Result<DirectFundingRequestDetails, Error> {
		if !*self.is_running.read().unwrap() {
			return Err(Error::NotRunning);
		}
		let prepared = self.direct_funding.sender.prepare(&request, amount_sats)?;
		if prepared.prior_result.is_none() {
			self.runtime.block_on(self.direct_funding.transport.open(&prepared.envelope))?;
		}
		let mut details = request_details(&prepared.envelope, request);
		details.amount_sats = prepared.amount_sats;
		Ok(details)
	}

	/// Pay a signed request using a confirmed wallet coin, subject to the user's
	/// absolute fee ceiling. After a witness may have left the device this returns
	/// a durable pending payment even when the connection or receipt is lost.
	/// Retrying the same request recovers that attempt and never spends a second coin.
	pub fn send_direct_funding(
		&self, request: String, amount_sats: Option<u64>, max_fee_sats: u64,
	) -> Result<DirectFundingPaymentDetails, Error> {
		if !*self.is_running.read().unwrap() {
			return Err(Error::NotRunning);
		}
		let prepared = self.direct_funding.sender.prepare(&request, amount_sats)?;
		if prepared.prior_result.is_none() && self.has_pending_funding_operation() {
			return Err(Error::Busy);
		}
		let result = self.runtime.block_on(async {
			let mut lane = match self.direct_funding.transport.open(&prepared.envelope).await {
				Ok(lane) => lane,
				Err(error) => return prepared.prior_result.ok_or(error),
			};
			self.direct_funding.sender.send(&request, amount_sats, max_fee_sats, &mut lane).await
		})?;
		Ok(payment_details(result))
	}

	/// List durable direct-funding activity after restart, including uncertain
	/// signed payments which must not be replaced with an ordinary onchain payment.
	pub fn list_direct_funding_payments(&self) -> Vec<DirectFundingPaymentDetails> {
		let mut payments = self.direct_funding.receiver.payments();
		payments.extend(self.direct_funding.sender.list().into_iter().map(payment_details));
		payments.sort_by_key(|p| p.created_at);
		payments
	}
}

fn payment_details(result: SendResult) -> DirectFundingPaymentDetails {
	DirectFundingPaymentDetails {
		request_id: result.request_id,
		payment_hash: result.payment_hash,
		amount_sats: result.amount_sats,
		fee_sats: result.fee_sats,
		funding_txid: result.funding_txid,
		is_outbound: true,
		created_at: result.created_at,
		status: match result.status {
			SenderPaymentStatus::Offered => Status::Offered,
			SenderPaymentStatus::SignedPending => Status::SignedPending,
			SenderPaymentStatus::MempoolSeen => Status::MempoolSeen,
			SenderPaymentStatus::Confirmed => Status::Confirmed,
			SenderPaymentStatus::Aborted => Status::Aborted,
			SenderPaymentStatus::Failed => Status::Failed,
		},
	}
}
