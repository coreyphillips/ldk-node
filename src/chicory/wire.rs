//! Bounded codecs for Beignet's custom peer envelope and JIT receive messages.
//!
//! Inputs are untrusted peer data. Decoding does not authorize funding or forwarding.
//! Unknown envelope versions and subtypes are preserved so callers can ignore them.
//! JIT's optional trailing fields follow Beignet's backwards-compatible rules.

#![forbid(unsafe_code)]

use std::fmt;

/// The odd Lightning wire type carrying Beignet application messages.
pub const CUSTOM_MESSAGE_TYPE: u16 = 44069;
/// The currently implemented envelope version.
pub const PROTOCOL_VERSION: u16 = 1;
/// Maximum application payload after the wire type and envelope header.
pub const MAX_PAYLOAD: usize = 65_535 - 2 - 4;
/// Register an invoice's JIT receive intent.
pub const JIT_AUTHORIZATION: u16 = 1;
/// Reply to a JIT receive registration.
pub const JIT_ACK: u16 = 2;
/// Request a read-only JIT quote.
pub const JIT_QUOTE_REQUEST: u16 = 4;
/// Reply to a read-only JIT quote.
pub const JIT_QUOTE: u16 = 5;
/// Relay a sealed direct-funding frame between connected peers.
pub const DIRECT_FUNDING_RELAY: u16 = 22;

const MAX_REASON_BYTES: usize = 200;
const MAX_RELAY_BYTES: usize = 32_768;

/// A malformed or over-limit wire message, without retaining hostile payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WireError(pub &'static str);

impl fmt::Display for WireError {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter.write_str(self.0)
	}
}

impl std::error::Error for WireError {}

/// Versioned application data, excluding the outer Lightning message type.
#[derive(Clone, Eq, PartialEq)]
pub struct Envelope {
	/// Unknown versions must not be dispatched as the current protocol.
	pub version: u16,
	/// Unknown subtypes must be ignored by application handlers.
	pub subtype: u16,
	/// Raw application bytes, bounded on encode and decode.
	pub payload: Vec<u8>,
}

// Receive-service replies can contain claim preimages. Logging a generic custom
// message must not reveal payloads, including unknown future subtypes.
impl fmt::Debug for Envelope {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("Envelope")
			.field("version", &self.version)
			.field("subtype", &self.subtype)
			.field("payload_len", &self.payload.len())
			.finish()
	}
}

impl Envelope {
	/// Encode an envelope, rejecting payloads exceeding the BOLT 8 limit.
	pub fn encode(&self) -> Result<Vec<u8>, WireError> {
		bounded(&self.payload, MAX_PAYLOAD)?;
		let mut bytes = Vec::with_capacity(4 + self.payload.len());
		bytes.extend_from_slice(&self.version.to_be_bytes());
		bytes.extend_from_slice(&self.subtype.to_be_bytes());
		bytes.extend_from_slice(&self.payload);
		Ok(bytes)
	}

	/// Parse a bounded envelope while retaining unknown versions and subtypes.
	pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
		bounded(bytes, MAX_PAYLOAD + 4)?;
		let mut reader = Reader::new(bytes);
		Ok(Self { version: reader.u16()?, subtype: reader.u16()?, payload: reader.rest().to_vec() })
	}
}

/// The agreed way to charge the opening fee.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeeMode {
	/// Deduct the fee from the receiver's forwarded amount.
	Skim,
	/// Charge the sender through the invoice's routing hint.
	Hop,
}

/// A bounded request to register a JIT receive intent. Amounts remain untrusted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JitAuthorization {
	/// Eight client-chosen correlation bytes, echoed in the acknowledgment.
	pub request_id: [u8; 8],
	/// A missing or all-zero hash means an unbound intent.
	pub payment_hash: Option<[u8; 32]>,
	/// Maximum amount that may be held for this intent, in millisatoshis.
	pub max_amount_msat: u64,
	/// Known invoice total, with absent or zero meaning unknown.
	pub expected_total_msat: Option<u64>,
	/// Inbound liquidity desired after receiving the payment, in satoshis.
	pub target_remaining_inbound_sat: u64,
	/// Requested intent lifetime, subject to provider policy.
	pub expiry_seconds: u32,
	/// Explicit consent to receive less than the onion amount by the agreed fee.
	pub accepts_skimmed_fee: bool,
}

impl JitAuthorization {
	/// Encode the current 69-byte request, including explicit skim consent.
	pub fn encode(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(69);
		bytes.extend_from_slice(&self.payment_hash.unwrap_or([0; 32]));
		bytes.extend_from_slice(&self.request_id);
		bytes.extend_from_slice(&self.max_amount_msat.to_be_bytes());
		bytes.extend_from_slice(&self.expected_total_msat.unwrap_or(0).to_be_bytes());
		bytes.extend_from_slice(&self.target_remaining_inbound_sat.to_be_bytes());
		bytes.extend_from_slice(&self.expiry_seconds.to_be_bytes());
		bytes.push(u8::from(self.accepts_skimmed_fee));
		bytes
	}

	/// Decode legacy 68-byte requests and current requests without assuming consent.
	pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
		bounded(bytes, MAX_PAYLOAD)?;
		let mut reader = Reader::new(bytes);
		let hash = reader.array()?;
		let request_id = reader.array()?;
		let max_amount_msat = reader.u64()?;
		let total = reader.u64()?;
		let target_remaining_inbound_sat = reader.u64()?;
		let expiry_seconds = reader.u32()?;
		let accepts_skimmed_fee = reader.rest().first() == Some(&1);
		Ok(Self {
			request_id,
			payment_hash: (hash != [0; 32]).then_some(hash),
			max_amount_msat,
			expected_total_msat: (total != 0).then_some(total),
			target_remaining_inbound_sat,
			expiry_seconds,
			accepts_skimmed_fee,
		})
	}
}

/// An acknowledgment binding a provider-minted intercept SCID and fee terms.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JitAck {
	/// Correlation identifier from the authorization.
	pub request_id: [u8; 8],
	/// Synthetic routing SCID, zero for a declined request.
	pub intercept_scid: u64,
	/// True only when the provider registered the intent.
	pub accepted: bool,
	/// Flat opening fee in satoshis.
	pub flat_fee_sat: u64,
	/// Proportional opening fee in parts per million.
	pub fee_ppm: u32,
	/// Optional human-readable refusal, encoded with Beignet's 200-byte limit.
	pub reason: Option<String>,
	/// Missing on older providers and interpreted as skim by the application.
	pub fee_mode: Option<FeeMode>,
}

impl JitAck {
	/// Encode terms and truncate the reason to the reference protocol's byte limit.
	pub fn encode(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(32 + MAX_REASON_BYTES);
		bytes.extend_from_slice(&self.request_id);
		bytes.extend_from_slice(&self.intercept_scid.to_be_bytes());
		bytes.push(u8::from(self.accepted));
		bytes.extend_from_slice(&self.flat_fee_sat.to_be_bytes());
		bytes.extend_from_slice(&self.fee_ppm.to_be_bytes());
		write_reason(&mut bytes, self.reason.as_deref());
		if let Some(mode) = self.fee_mode {
			bytes.push(u8::from(mode == FeeMode::Hop));
		}
		bytes
	}

	/// Decode optional fee mode, treating unknown mode bytes as legacy skim.
	pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
		bounded(bytes, MAX_PAYLOAD)?;
		let mut reader = Reader::new(bytes);
		let request_id = reader.array()?;
		let intercept_scid = reader.u64()?;
		let accepted = reader.u8()? == 1;
		let flat_fee_sat = reader.u64()?;
		let fee_ppm = reader.u32()?;
		let reason = reader.reason()?;
		let fee_mode =
			reader.rest().first().map(|mode| if *mode == 1 { FeeMode::Hop } else { FeeMode::Skim });
		Ok(Self { request_id, intercept_scid, accepted, flat_fee_sat, fee_ppm, reason, fee_mode })
	}
}

/// A read-only quote request that must not allocate an intent or spend funds.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JitQuoteRequest {
	/// Client correlation identifier.
	pub request_id: [u8; 8],
	/// Proposed receive amount in millisatoshis.
	pub max_amount_msat: u64,
	/// Requested remaining inbound liquidity in satoshis.
	pub target_remaining_inbound_sat: u64,
}

impl JitQuoteRequest {
	/// Encode the 24-byte quote request.
	pub fn encode(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(24);
		bytes.extend_from_slice(&self.request_id);
		bytes.extend_from_slice(&self.max_amount_msat.to_be_bytes());
		bytes.extend_from_slice(&self.target_remaining_inbound_sat.to_be_bytes());
		bytes
	}

	/// Decode a quote request, ignoring backwards-compatible trailing bytes.
	pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
		bounded(bytes, MAX_PAYLOAD)?;
		let mut reader = Reader::new(bytes);
		Ok(Self {
			request_id: reader.array()?,
			max_amount_msat: reader.u64()?,
			target_remaining_inbound_sat: reader.u64()?,
		})
	}
}

/// Provider fee terms and capacity for a proposed JIT receive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JitQuote {
	/// Correlation identifier from the request.
	pub request_id: [u8; 8],
	/// Whether the provider would accept this request at quote time.
	pub accepted: bool,
	/// Flat fee in satoshis.
	pub flat_fee_sat: u64,
	/// Proportional fee in parts per million.
	pub fee_ppm: u32,
	/// Provider's funding cap for one client in satoshis.
	pub max_client_funding_sats: u64,
	/// Funding proposed for this receive, zero when refused.
	pub funding_sats: u64,
	/// Optional human-readable refusal.
	pub reason: Option<String>,
}

impl JitQuote {
	/// Encode a quote with a bounded reason.
	pub fn encode(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(39 + MAX_REASON_BYTES);
		bytes.extend_from_slice(&self.request_id);
		bytes.push(u8::from(self.accepted));
		bytes.extend_from_slice(&self.flat_fee_sat.to_be_bytes());
		bytes.extend_from_slice(&self.fee_ppm.to_be_bytes());
		bytes.extend_from_slice(&self.max_client_funding_sats.to_be_bytes());
		bytes.extend_from_slice(&self.funding_sats.to_be_bytes());
		write_reason(&mut bytes, self.reason.as_deref());
		bytes
	}

	/// Decode fee terms, rejecting truncated reasons before reading their contents.
	pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
		bounded(bytes, MAX_PAYLOAD)?;
		let mut reader = Reader::new(bytes);
		let request_id = reader.array()?;
		let accepted = match reader.u8()? {
			0 => false,
			1 => true,
			_ => return Err(WireError("invalid quote acceptance flag")),
		};
		Ok(Self {
			request_id,
			accepted,
			flat_fee_sat: reader.u64()?,
			fee_ppm: reader.u32()?,
			max_client_funding_sats: reader.u64()?,
			funding_sats: reader.u64()?,
			reason: reader.reason()?,
		})
	}
}

/// A relay frame names either a destination or an authenticated relay-stamped origin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayAddress {
	/// Originator request. The relay must authenticate and stamp its origin itself.
	To([u8; 33]),
	/// Forwarded frame. A relay must never forward this form again.
	From([u8; 33]),
}

/// A canonical direct-funding relay TLV frame. Key validity is checked by the caller.
#[derive(Clone, Eq, PartialEq)]
pub struct RelayFrame {
	/// Inner direct-funding subtype, subject to the relay's allowlist.
	pub subtype: u16,
	/// Sealed inner bytes. A relay does not decrypt this payload.
	pub payload: Vec<u8>,
	/// Exactly one routing address, preventing ambiguous or spoofed origin frames.
	pub address: RelayAddress,
}

impl fmt::Debug for RelayFrame {
	fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
		formatter
			.debug_struct("RelayFrame")
			.field("subtype", &self.subtype)
			.field("address", &self.address)
			.field("payload_len", &self.payload.len())
			.finish()
	}
}

impl RelayFrame {
	/// Encode a bounded frame that Beignet's relay decoder accepts.
	pub fn encode(&self) -> Result<Vec<u8>, WireError> {
		bounded(&self.payload, MAX_RELAY_BYTES)?;
		let mut bytes = Vec::new();
		write_tlv(&mut bytes, 0, &self.subtype.to_be_bytes());
		write_tlv(&mut bytes, 2, &self.payload);
		match &self.address {
			RelayAddress::To(key) => write_tlv(&mut bytes, 4, key),
			RelayAddress::From(key) => write_tlv(&mut bytes, 6, key),
		}
		bounded(&bytes, MAX_RELAY_BYTES)?;
		Ok(bytes)
	}

	/// Decode canonical TLVs, ignoring unknown odd types and rejecting unknown even ones.
	pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
		bounded(bytes, MAX_RELAY_BYTES)?;
		let mut reader = Reader::new(bytes);
		let (mut subtype, mut payload, mut address, mut previous) = (None, None, None, None);
		while !reader.rest().is_empty() {
			let kind = reader.bigsize()?;
			if previous.is_some_and(|previous| kind <= previous) {
				return Err(WireError("unordered relay TLV"));
			}
			previous = Some(kind);
			let length = usize::try_from(reader.bigsize()?)
				.map_err(|_| WireError("relay TLV length overflow"))?;
			let value = reader.take(length)?;
			match kind {
				0 => {
					subtype = Some(u16::from_be_bytes(
						value.try_into().map_err(|_| WireError("invalid relay subtype length"))?,
					))
				},
				2 => payload = Some(value.to_vec()),
				4 | 6 => {
					if address.is_some() {
						return Err(WireError("ambiguous relay address"));
					}
					let key =
						value.try_into().map_err(|_| WireError("invalid relay address length"))?;
					address = Some(if kind == 4 {
						RelayAddress::To(key)
					} else {
						RelayAddress::From(key)
					});
				},
				unknown if unknown % 2 == 0 => return Err(WireError("unknown required relay TLV")),
				_ => {},
			}
		}
		Ok(Self {
			subtype: subtype.ok_or(WireError("missing relay subtype"))?,
			payload: payload.ok_or(WireError("missing relay payload"))?,
			address: address.ok_or(WireError("missing relay address"))?,
		})
	}
}

fn bounded(bytes: &[u8], maximum: usize) -> Result<(), WireError> {
	if bytes.len() > maximum {
		Err(WireError("message exceeds size limit"))
	} else {
		Ok(())
	}
}

// Beignet truncates UTF-8 bytes, including potentially splitting the last codepoint.
fn write_reason(bytes: &mut Vec<u8>, reason: Option<&str>) {
	let reason = reason.unwrap_or("").as_bytes();
	let reason = &reason[..reason.len().min(MAX_REASON_BYTES)];
	bytes.extend_from_slice(&(reason.len() as u16).to_be_bytes());
	bytes.extend_from_slice(reason);
}

fn write_tlv(bytes: &mut Vec<u8>, kind: u8, value: &[u8]) {
	bytes.push(kind);
	if value.len() < 0xfd {
		bytes.push(value.len() as u8);
	} else {
		bytes.push(0xfd);
		bytes.extend_from_slice(&(value.len() as u16).to_be_bytes());
	}
	bytes.extend_from_slice(value);
}

struct Reader<'a> {
	bytes: &'a [u8],
}

impl<'a> Reader<'a> {
	fn new(bytes: &'a [u8]) -> Self {
		Self { bytes }
	}
	fn rest(&self) -> &'a [u8] {
		self.bytes
	}
	fn take(&mut self, length: usize) -> Result<&'a [u8], WireError> {
		if length > self.bytes.len() {
			return Err(WireError("truncated message"));
		}
		let (value, rest) = self.bytes.split_at(length);
		self.bytes = rest;
		Ok(value)
	}
	fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
		self.take(N)?.try_into().map_err(|_| WireError("invalid field length"))
	}
	fn u8(&mut self) -> Result<u8, WireError> {
		Ok(self.array::<1>()?[0])
	}
	fn u16(&mut self) -> Result<u16, WireError> {
		Ok(u16::from_be_bytes(self.array()?))
	}
	fn u32(&mut self) -> Result<u32, WireError> {
		Ok(u32::from_be_bytes(self.array()?))
	}
	fn u64(&mut self) -> Result<u64, WireError> {
		Ok(u64::from_be_bytes(self.array()?))
	}
	fn reason(&mut self) -> Result<Option<String>, WireError> {
		let length = usize::from(self.u16()?);
		let bytes = self.take(length)?;
		Ok((length != 0).then(|| String::from_utf8_lossy(bytes).into_owned()))
	}
	fn bigsize(&mut self) -> Result<u64, WireError> {
		let first = self.u8()?;
		let (value, minimum) = match first {
			0xfd => (u64::from(self.u16()?), 0xfd),
			0xfe => (u64::from(self.u32()?), 0x1_0000),
			0xff => (self.u64()?, 0x1_0000_0000),
			value => return Ok(u64::from(value)),
		};
		if value < minimum {
			return Err(WireError("noncanonical BigSize"));
		}
		Ok(value)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use proptest::prelude::*;

	fn hex(value: &str) -> Vec<u8> {
		value
			.as_bytes()
			.chunks_exact(2)
			.map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
			.collect()
	}

	#[test]
	fn beignet_generated_vectors() {
		// Generated with Beignet 0.32.2's real encodeJit* implementations.
		let authorization = hex("090909090909090909090909090909090909090909090909090909090909090901020304050607080000000005f5e1000000000002faf0800000000000004e2000000e1001");
		let ack = hex("0102030405060708ffffff010203040501000000000000007d000009c400026f6b01");
		let request = hex("01020304050607080000000005f5e1000000000000004e20");
		let quote = hex(
			"010203040506070801000000000000007d000009c4000000000007a120000000000001d4c000026f6b",
		);
		let decoded = JitAuthorization::decode(&authorization).unwrap();
		assert_eq!(decoded.payment_hash, Some([9; 32]));
		assert_eq!(decoded.max_amount_msat, 100_000_000);
		assert_eq!(decoded.expected_total_msat, Some(50_000_000));
		assert_eq!(decoded.target_remaining_inbound_sat, 20_000);
		assert_eq!(decoded.expiry_seconds, 3600);
		assert!(decoded.accepts_skimmed_fee);
		assert_eq!(decoded.encode(), authorization);
		let decoded = JitAck::decode(&ack).unwrap();
		assert_eq!(decoded.intercept_scid, 0xffffff0102030405);
		assert_eq!(decoded.fee_mode, Some(FeeMode::Hop));
		assert_eq!(decoded.flat_fee_sat, 125);
		assert_eq!(decoded.fee_ppm, 2500);
		assert_eq!(decoded.reason.as_deref(), Some("ok"));
		assert_eq!(decoded.encode(), ack);
		assert_eq!(JitQuoteRequest::decode(&request).unwrap().encode(), request);
		let decoded = JitQuote::decode(&quote).unwrap();
		assert_eq!(decoded.max_client_funding_sats, 500_000);
		assert_eq!(decoded.funding_sats, 120_000);
		assert_eq!(decoded.encode(), quote);
	}

	#[test]
	fn diagnostic_formatting_is_independent_of_secret_payload_bytes() {
		for subtype in [1, 22, 81, u16::MAX] {
			let first = Envelope { version: 1, subtype, payload: vec![17; 32] };
			let second = Envelope { payload: vec![241; 32], ..first.clone() };
			assert_eq!(format!("{first:?}"), format!("{second:?}"));
			let first =
				RelayFrame { subtype, payload: first.payload, address: RelayAddress::To([2; 33]) };
			let second = RelayFrame { payload: second.payload, ..first.clone() };
			assert_eq!(format!("{first:?}"), format!("{second:?}"));
		}
	}

	#[test]
	fn legacy_extensions_and_truncated_fields() {
		let mut auth = vec![0; 68];
		let decoded = JitAuthorization::decode(&auth).unwrap();
		assert_eq!(decoded.payment_hash, None);
		assert_eq!(decoded.expected_total_msat, None);
		assert!(!decoded.accepts_skimmed_fee);
		auth.push(2);
		assert!(!JitAuthorization::decode(&auth).unwrap().accepts_skimmed_fee);
		let mut ack = vec![0; 31];
		assert_eq!(JitAck::decode(&ack).unwrap().fee_mode, None);
		ack.push(99);
		assert_eq!(JitAck::decode(&ack).unwrap().fee_mode, Some(FeeMode::Skim));
		ack[30] = 2;
		assert!(JitAck::decode(&ack).is_err());
		let mut quote = vec![0; 39];
		quote[38] = 1;
		assert!(JitQuote::decode(&quote).is_err());
		for size in 0..68 {
			assert!(JitAuthorization::decode(&auth[..size]).is_err());
		}
		for size in 0..31 {
			assert!(JitAck::decode(&ack[..size]).is_err());
		}
		for size in 0..24 {
			assert!(JitQuoteRequest::decode(&auth[..size]).is_err());
		}
		for size in 0..39 {
			assert!(JitQuote::decode(&quote[..size]).is_err());
		}
	}

	#[test]
	fn envelope_boundaries_and_unknown_values() {
		for size in 0..4 {
			assert!(Envelope::decode(&vec![0; size]).is_err());
		}
		let mut envelope =
			Envelope { version: 65535, subtype: 65535, payload: vec![3; MAX_PAYLOAD] };
		assert_eq!(Envelope::decode(&envelope.encode().unwrap()).unwrap(), envelope);
		envelope.payload.push(3);
		assert!(envelope.encode().is_err());
		assert!(Envelope::decode(&vec![0; MAX_PAYLOAD + 5]).is_err());
		let oversized = vec![0; MAX_PAYLOAD + 1];
		assert!(JitAuthorization::decode(&oversized).is_err());
		assert!(JitAck::decode(&oversized).is_err());
		assert!(JitQuoteRequest::decode(&oversized).is_err());
		assert!(JitQuote::decode(&oversized).is_err());
	}

	#[test]
	fn reason_byte_truncation_matches_beignet() {
		let ack = JitAck {
			request_id: [0; 8],
			intercept_scid: 0,
			accepted: false,
			flat_fee_sat: 0,
			fee_ppm: 0,
			reason: Some(format!("{}é", "a".repeat(199))),
			fee_mode: Some(FeeMode::Skim),
		};
		let bytes = ack.encode();
		assert_eq!(bytes.len(), 232);
		assert_eq!(&bytes[29..31], &[0, 200]);
		assert_eq!(bytes[230], 0xc3);
		assert!(JitAck::decode(&bytes).unwrap().reason.unwrap().ends_with('\u{fffd}'));
	}

	#[test]
	fn relay_rejects_ambiguous_addresses_and_noncanonical_tlvs() {
		let frame =
			RelayFrame { subtype: 16, payload: vec![9], address: RelayAddress::To([2; 33]) };
		let bytes = frame.encode().unwrap();
		assert_eq!(RelayFrame::decode(&bytes).unwrap(), frame);
		let mut extended = bytes.clone();
		write_tlv(&mut extended, 7, &[1, 2]);
		assert_eq!(RelayFrame::decode(&extended).unwrap(), frame);
		let mut ambiguous = bytes.clone();
		write_tlv(&mut ambiguous, 6, &[3; 33]);
		assert!(RelayFrame::decode(&ambiguous).is_err());
		let mut required = bytes.clone();
		write_tlv(&mut required, 8, &[]);
		assert!(RelayFrame::decode(&required).is_err());
		let mut duplicate = bytes.clone();
		write_tlv(&mut duplicate, 4, &[2; 33]);
		assert!(RelayFrame::decode(&duplicate).is_err());
		for noncanonical in
			[&[0xfd, 0, 0][..], &[0xfe, 0, 0, 0, 0][..], &[0xff, 0, 0, 0, 0, 0, 0, 0, 0][..]]
		{
			assert!(RelayFrame::decode(noncanonical).is_err());
		}
		for size in 0..bytes.len() {
			assert!(RelayFrame::decode(&bytes[..size]).is_err());
		}
		let oversized = RelayFrame { payload: vec![0; MAX_RELAY_BYTES], ..frame };
		assert!(oversized.encode().is_err());
		assert!(RelayFrame::decode(&vec![0; MAX_RELAY_BYTES + 1]).is_err());
	}

	proptest! {
		#[test]
		fn arbitrary_payloads_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..66_000)) {
			let _ = Envelope::decode(&bytes);
			let _ = JitAuthorization::decode(&bytes);
			let _ = JitAck::decode(&bytes);
			let _ = JitQuoteRequest::decode(&bytes);
			let _ = JitQuote::decode(&bytes);
			let _ = RelayFrame::decode(&bytes);
		}

		#[test]
		fn jit_round_trips(id in any::<[u8; 8]>(), hash in any::<[u8; 32]>(), amount in 1u64..=u64::MAX,
			target in any::<u64>(), expiry in any::<u32>(), consent in any::<bool>(), ppm in any::<u32>()) {
			let authorization = JitAuthorization { request_id: id, payment_hash: (hash != [0;32]).then_some(hash),
				max_amount_msat: amount, expected_total_msat: Some(amount), target_remaining_inbound_sat: target,
				expiry_seconds: expiry, accepts_skimmed_fee: consent };
			prop_assert_eq!(JitAuthorization::decode(&authorization.encode()).unwrap(), authorization);
			let request = JitQuoteRequest { request_id: id, max_amount_msat: amount, target_remaining_inbound_sat: target };
			prop_assert_eq!(JitQuoteRequest::decode(&request.encode()).unwrap(), request);
			let ack = JitAck { request_id: id, intercept_scid: amount, accepted: consent, flat_fee_sat: target, fee_ppm: ppm,
				reason: Some("reason".to_owned()), fee_mode: Some(if consent { FeeMode::Hop } else { FeeMode::Skim }) };
			prop_assert_eq!(JitAck::decode(&ack.encode()).unwrap(), ack);
			let quote = JitQuote { request_id: id, accepted: consent, flat_fee_sat: target, fee_ppm: ppm,
				max_client_funding_sats: target, funding_sats: amount, reason: None };
			prop_assert_eq!(JitQuote::decode(&quote.encode()).unwrap(), quote);
		}

		#[test]
		fn relay_round_trip(payload in prop::collection::vec(any::<u8>(), 0..32_000), key in any::<[u8;33]>(), subtype in any::<u16>(), from in any::<bool>()) {
			let frame = RelayFrame { subtype, payload, address: if from { RelayAddress::From(key) } else { RelayAddress::To(key) } };
			prop_assert_eq!(RelayFrame::decode(&frame.encode().unwrap()).unwrap(), frame);
		}
	}
}
