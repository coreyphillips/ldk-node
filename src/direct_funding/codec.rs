//! Bounded, canonical wire codecs for Beignet direct funding v3.
//!
//! These codecs reproduce `beignet/src/lightning/direct-funding/{envelope,messages}.ts`.
//! Parsing never authorizes payment: callers must additionally check transaction economics,
//! ownership, request lifecycle and the authenticated transport. Envelope decoding verifies
//! the node signature and chain before returning a request usable for a new payment.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fmt;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bitcoin::hashes::{sha256, sha256d, Hash};
use bitcoin::secp256k1::PublicKey;
use bitcoin::{
	absolute, transaction, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid,
};

use super::crypto::verify_message;

pub(crate) const MAX_MESSAGE_BYTES: usize = 32_768;
pub(crate) const MAX_RAW_TX_BYTES: usize = 20_000;
pub(crate) const MAX_SCRIPT_BYTES: usize = 520;
pub(crate) const MAX_AMOUNT_SAT: u64 = 2_100_000_000_000_000;
pub(crate) const MAX_REQUEST_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1000;
pub(crate) const DEFAULT_REQUEST_TTL_MS: u64 = 60 * 60 * 1000;
pub(crate) const OFFER: u16 = 16;
pub(crate) const OFFER_ACK: u16 = 17;
pub(crate) const SIGN_REQUEST: u16 = 18;
pub(crate) const WITNESS: u16 = 19;
pub(crate) const RECEIPT: u16 = 21;
pub(crate) const RELAY: u16 = 22;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CodecError {
	Malformed(&'static str),
	UnsupportedVersion,
	Expired,
	ExpiryTooDistant,
	InvalidSignature,
	WrongSigner,
	WrongChain,
}
impl fmt::Display for CodecError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Malformed(reason) => write!(f, "malformed direct funding: {reason}"),
			other => write!(f, "direct funding: {other:?}"),
		}
	}
}
impl std::error::Error for CodecError {}
type Result<T> = std::result::Result<T, CodecError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BlindedHop {
	pub blinded_node_id: PublicKey,
	pub encrypted_data: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum TransportDescriptor {
	DirectPeer {
		host: String,
		port: u16,
	},
	OnionMessage {
		host: String,
		port: u16,
		intro_node_id: PublicKey,
		path_key: PublicKey,
		hops: Vec<BlindedHop>,
	},
	Relay {
		relay_node_id: PublicKey,
		host: String,
		port: u16,
	},
	Unknown {
		kind: u8,
		value: Vec<u8>,
	},
}
impl TransportDescriptor {
	/// Direct and relay endpoints the native peer transport can dial. An onion introduction
	/// also serves as the protocol's relay fallback, without publishing a duplicate descriptor.
	pub(crate) fn endpoint(&self, receiver: PublicKey) -> Option<(PublicKey, &str, u16, bool)> {
		match self {
			Self::DirectPeer { host, port } => Some((receiver, host, *port, false)),
			Self::OnionMessage { host, port, intro_node_id, .. } => {
				Some((*intro_node_id, host, *port, true))
			},
			Self::Relay { relay_node_id, host, port } => Some((*relay_node_id, host, *port, true)),
			Self::Unknown { .. } => None,
		}
	}
	fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
		let mut value = Vec::new();
		let kind = match self {
			Self::DirectPeer { host, port } => {
				put_host(&mut value, host, *port)?;
				1
			},
			Self::OnionMessage { host, port, intro_node_id, path_key, hops } => {
				if hops.len() > 8 {
					return Err(CodecError::Malformed("too many blinded hops"));
				}
				put_host(&mut value, host, *port)?;
				value.extend(intro_node_id.serialize());
				value.extend(path_key.serialize());
				value.push(hops.len() as u8);
				for hop in hops {
					value.extend(hop.blinded_node_id.serialize());
					put_blob16(&mut value, &hop.encrypted_data)?;
				}
				2
			},
			Self::Relay { relay_node_id, host, port } => {
				value.extend(relay_node_id.serialize());
				put_host(&mut value, host, *port)?;
				3
			},
			Self::Unknown { kind, value: bytes } => {
				value.extend(bytes);
				*kind
			},
		};
		out.push(kind);
		put_blob16(out, &value)
	}
	fn decode(kind: u8, value: &[u8]) -> Result<Self> {
		let mut r = Reader::new(value);
		Ok(match kind {
			1 => {
				let (host, port) = r.host()?;
				Self::DirectPeer { host, port }
			},
			2 => {
				let (host, port) = r.host()?;
				let intro_node_id = r.pubkey()?;
				let path_key = r.pubkey()?;
				let count = r.u8()?;
				if count > 8 {
					return Err(CodecError::Malformed("too many blinded hops"));
				}
				let mut hops = Vec::with_capacity(count as usize);
				for _ in 0..count {
					hops.push(BlindedHop {
						blinded_node_id: r.pubkey()?,
						encrypted_data: r.blob16(8192)?.to_vec(),
					});
				}
				Self::OnionMessage { host, port, intro_node_id, path_key, hops }
			},
			3 => {
				let relay_node_id = r.pubkey()?;
				let (host, port) = r.host()?;
				Self::Relay { relay_node_id, host, port }
			},
			_ => Self::Unknown { kind, value: value.to_vec() },
		})
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RequestEnvelope {
	pub request_id: [u8; 16],
	pub chain_hash: [u8; 32],
	pub receiver_node_id: PublicKey,
	pub expires_at: u64,
	pub amount_sat: Option<u64>,
	pub receipt_hash: [u8; 32],
	pub encryption_key: PublicKey,
	pub transports: Vec<TransportDescriptor>,
	pub signature: [u8; 65],
	/// Exact signed bytes, including unknown flags and transport extensions on decoded requests.
	pub signed_bytes: Vec<u8>,
}
impl RequestEnvelope {
	/// Populate the exact signing bytes of a locally minted request. Sign the returned string
	/// with the node's Lightning message signer, then store the compact signature in `signature`.
	pub(crate) fn prepare_signature(&mut self, now_ms: u64) -> Result<String> {
		self.check_expiry(now_ms, false)?;
		if self.transports.len() > 8
			|| self.transports.iter().any(|t| matches!(t, TransportDescriptor::Unknown { .. }))
		{
			return Err(CodecError::Malformed("unsupported minted transports"));
		}
		self.signed_bytes = self.unsigned_bytes()?;
		Ok(canonical_request_message(&self.signed_bytes))
	}
	fn unsigned_bytes(&self) -> Result<Vec<u8>> {
		if self.expires_at > 0xffffffffffff || self.transports.len() > 255 {
			return Err(CodecError::Malformed("envelope field out of range"));
		}
		let mut out = vec![3];
		out.extend(self.request_id);
		out.extend(self.chain_hash);
		out.extend(self.receiver_node_id.serialize());
		out.extend(&self.expires_at.to_be_bytes()[2..]);
		match self.amount_sat {
			Some(amount) if amount > 0 && amount <= MAX_AMOUNT_SAT => {
				out.push(1);
				out.extend(amount.to_be_bytes());
			},
			Some(_) => return Err(CodecError::Malformed("amount out of range")),
			None => out.push(0),
		}
		out.extend(self.receipt_hash);
		out.extend(self.encryption_key.serialize());
		out.push(self.transports.len() as u8);
		for t in &self.transports {
			t.encode(&mut out)?;
		}
		if out.len() + 65 > 8192 {
			return Err(CodecError::Malformed("envelope too large"));
		}
		Ok(out)
	}
	pub(crate) fn signing_message(&self) -> String {
		canonical_request_message(&self.signed_bytes)
	}
	pub(crate) fn encode(&self) -> Result<String> {
		if self.signed_bytes.is_empty() || self.signed_bytes.len() + 65 > 8192 {
			return Err(CodecError::Malformed("envelope not prepared"));
		}
		if !verify_message(&self.signing_message(), &self.signature, &self.receiver_node_id) {
			return Err(CodecError::InvalidSignature);
		}
		let mut raw = self.signed_bytes.clone();
		raw.extend(self.signature);
		Ok(URL_SAFE_NO_PAD.encode(raw))
	}
	pub(crate) fn decode(
		encoded: &str, now_ms: u64, expected_chain: &[u8; 32], allow_expired: bool,
	) -> Result<Self> {
		if encoded.is_empty()
			|| encoded.len() > 16384
			|| !encoded.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
		{
			return Err(CodecError::Malformed("invalid base64url envelope"));
		}
		let raw = URL_SAFE_NO_PAD
			.decode(encoded)
			.map_err(|_| CodecError::Malformed("invalid base64url envelope"))?;
		if raw.len() < 220 || raw.len() > 8192 || URL_SAFE_NO_PAD.encode(&raw) != encoded {
			return Err(CodecError::Malformed("invalid envelope length or encoding"));
		}
		let mut r = Reader::new(&raw);
		if r.u8()? != 3 {
			return Err(CodecError::UnsupportedVersion);
		}
		let request_id = r.array()?;
		let chain_hash = r.array()?;
		let receiver_node_id = r.pubkey()?;
		let mut expiry = [0u8; 8];
		expiry[2..].copy_from_slice(r.take(6)?);
		let expires_at = u64::from_be_bytes(expiry);
		let amount_sat = if r.u8()? & 1 != 0 { Some(r.u64()?) } else { None };
		if amount_sat.is_some_and(|amount| amount == 0 || amount > MAX_AMOUNT_SAT) {
			return Err(CodecError::Malformed("amount out of range"));
		}
		let receipt_hash = r.array()?;
		let encryption_key = r.pubkey()?;
		let count = r.u8()?;
		let mut transports = Vec::with_capacity(count as usize);
		for _ in 0..count {
			let kind = r.u8()?;
			transports.push(TransportDescriptor::decode(kind, r.blob16(8192)?)?);
		}
		let signed_bytes = raw[..r.offset].to_vec();
		let signature = r.array()?;
		r.finish()?;
		let env = Self {
			request_id,
			chain_hash,
			receiver_node_id,
			expires_at,
			amount_sat,
			receipt_hash,
			encryption_key,
			transports,
			signature,
			signed_bytes,
		};
		env.check_expiry(now_ms, allow_expired)?;
		if !verify_message(&env.signing_message(), &env.signature, &env.receiver_node_id) {
			return Err(CodecError::WrongSigner);
		}
		if &env.chain_hash != expected_chain {
			return Err(CodecError::WrongChain);
		}
		Ok(env)
	}
	fn check_expiry(&self, now_ms: u64, allow_expired: bool) -> Result<()> {
		if self.expires_at <= now_ms && !allow_expired {
			return Err(CodecError::Expired);
		}
		if self.expires_at.saturating_sub(now_ms) > MAX_REQUEST_TTL_MS {
			return Err(CodecError::ExpiryTooDistant);
		}
		Ok(())
	}
}
pub(crate) fn canonical_request_message(unsigned: &[u8]) -> String {
	format!("beignet-df-req:v3:{}", URL_SAFE_NO_PAD.encode(unsigned))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MessageProof {
	pub pubkey: [u8; 33],
	pub signature: [u8; 65],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProbeProof {
	pub pubkey: [u8; 33],
	pub signature: [u8; 64],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OwnershipProof {
	pub pubkey: Vec<u8>,
	pub signature: [u8; 64],
	pub message_proof: Option<MessageProof>,
	pub probe_proof: Option<ProbeProof>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Offer {
	pub offer_id: [u8; 16],
	pub amount_sat: u64,
	pub txid: [u8; 32],
	pub vout: u32,
	pub value_sat: u64,
	pub sequence: u32,
	pub change_script: Vec<u8>,
	pub max_total_fee_sat: u64,
	pub receipt_hash: [u8; 32],
	pub ownership: OwnershipProof,
}
impl Offer {
	pub(crate) fn encode(&self) -> Result<Vec<u8>> {
		if !matches!(self.ownership.pubkey.len(), 32 | 33) {
			return Err(CodecError::Malformed("ownership key width"));
		}
		let mut f = Fields::new();
		f.put(0, self.offer_id);
		f.put(2, self.amount_sat.to_be_bytes());
		f.put(4, self.txid);
		f.put(6, self.vout.to_be_bytes());
		f.put(8, self.value_sat.to_be_bytes());
		f.put(10, self.sequence.to_be_bytes());
		f.put(12, bounded(&self.change_script, MAX_SCRIPT_BYTES)?);
		f.put(14, self.max_total_fee_sat.to_be_bytes());
		f.put(16, self.receipt_hash);
		f.put(18, &self.ownership.pubkey);
		f.put(20, self.ownership.signature);
		if let Some(p) = &self.ownership.message_proof {
			f.put(21, [p.pubkey.as_slice(), p.signature.as_slice()].concat());
		}
		if let Some(p) = &self.ownership.probe_proof {
			f.put(23, [p.pubkey.as_slice(), p.signature.as_slice()].concat());
		}
		f.encode()
	}
	pub(crate) fn decode(data: &[u8]) -> Result<Self> {
		let f = Fields::decode(data, &[0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 21, 23])?;
		let pubkey = f.need(18)?.to_vec();
		if !matches!(pubkey.len(), 32 | 33) {
			return Err(CodecError::Malformed("ownership key width"));
		}
		let message_proof = f
			.get(21)
			.map(|b| {
				let mut r = Reader::new(b);
				let p = MessageProof { pubkey: r.array()?, signature: r.array()? };
				r.finish()?;
				Ok(p)
			})
			.transpose()?;
		let probe_proof = f
			.get(23)
			.map(|b| {
				let mut r = Reader::new(b);
				let p = ProbeProof { pubkey: r.array()?, signature: r.array()? };
				r.finish()?;
				Ok(p)
			})
			.transpose()?;
		Ok(Self {
			offer_id: f.array(0)?,
			amount_sat: f.u64(2)?,
			txid: f.array(4)?,
			vout: f.u32(6)?,
			value_sat: f.u64(8)?,
			sequence: f.u32(10)?,
			change_script: bounded(f.need(12)?, MAX_SCRIPT_BYTES)?.to_vec(),
			max_total_fee_sat: f.u64(14)?,
			receipt_hash: f.array(16)?,
			ownership: OwnershipProof {
				pubkey,
				signature: f.array(20)?,
				message_proof,
				probe_proof,
			},
		})
	}
	pub(crate) fn outpoint(&self) -> OutPoint {
		OutPoint { txid: txid_from_display(self.txid), vout: self.vout }
	}
	pub(crate) fn ownership_message(&self, receiver: &PublicKey) -> String {
		ownership_message(
			&self.offer_id,
			&self.txid,
			self.vout,
			self.amount_sat,
			&self.receipt_hash,
			receiver,
		)
	}
	pub(crate) fn ownership_digest(&self, receiver: &PublicKey) -> [u8; 32] {
		ownership_digest(
			&self.offer_id,
			&self.txid,
			self.vout,
			self.amount_sat,
			&self.receipt_hash,
			receiver,
		)
	}
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct OfferAck {
	pub offer_id: [u8; 16],
	pub accepted: bool,
	pub reason: Option<String>,
}
impl OfferAck {
	pub(crate) fn encode(&self) -> Result<Vec<u8>> {
		let mut f = Fields::new();
		f.put(0, self.offer_id);
		f.put(2, [u8::from(self.accepted)]);
		if let Some(reason) = &self.reason {
			f.put(3, &reason.as_bytes()[..reason.len().min(200)]);
		}
		f.encode()
	}
	pub(crate) fn decode(data: &[u8]) -> Result<Self> {
		let f = Fields::decode(data, &[0, 2, 3])?;
		let accepted = f.array::<1>(2)?[0];
		if accepted > 1 {
			return Err(CodecError::Malformed("invalid acceptance flag"));
		}
		Ok(Self {
			offer_id: f.array(0)?,
			accepted: accepted == 1,
			reason: f
				.get(3)
				.map(|v| bounded(v, 200).map(|b| String::from_utf8_lossy(b).into_owned()))
				.transpose()?,
		})
	}
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Prevout {
	pub value_sat: u64,
	pub script: Vec<u8>,
}
impl Prevout {
	pub(crate) fn txout(&self) -> TxOut {
		TxOut {
			value: Amount::from_sat(self.value_sat),
			script_pubkey: ScriptBuf::from_bytes(self.script.clone()),
		}
	}
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FundingPubkeys {
	pub local: PublicKey,
	pub remote: PublicKey,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Attestation {
	pub funding_output_index: u32,
	pub local_funding_pubkey: PublicKey,
	pub remote_funding_pubkey: PublicKey,
	pub prior_funding_pubkeys: Option<FundingPubkeys>,
	pub signature: [u8; 65],
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SignRequest {
	pub offer_id: [u8; 16],
	pub raw_tx: Vec<u8>,
	pub prevouts: Vec<Prevout>,
	pub attestation: Attestation,
	pub shared_input_index: Option<u32>,
}
impl SignRequest {
	pub(crate) fn encode(&self) -> Result<Vec<u8>> {
		if self.prevouts.len() > 16 {
			return Err(CodecError::Malformed("too many prevouts"));
		}
		let mut prev = (self.prevouts.len() as u16).to_be_bytes().to_vec();
		for p in &self.prevouts {
			prev.extend(p.value_sat.to_be_bytes());
			put_blob16(&mut prev, bounded(&p.script, MAX_SCRIPT_BYTES)?)?;
		}
		let mut f = Fields::new();
		f.put(0, self.offer_id);
		f.put(2, bounded(&self.raw_tx, MAX_RAW_TX_BYTES)?);
		f.put(4, prev);
		f.put(6, self.attestation.funding_output_index.to_be_bytes());
		f.put(8, self.attestation.local_funding_pubkey.serialize());
		f.put(10, self.attestation.remote_funding_pubkey.serialize());
		f.put(12, self.attestation.signature);
		if let Some(i) = self.shared_input_index {
			f.put(13, i.to_be_bytes());
		}
		if let Some(p) = &self.attestation.prior_funding_pubkeys {
			f.put(15, [p.local.serialize().as_slice(), p.remote.serialize().as_slice()].concat());
		}
		f.encode()
	}
	pub(crate) fn decode(data: &[u8]) -> Result<Self> {
		let f = Fields::decode(data, &[0, 2, 4, 6, 8, 10, 12, 13, 15])?;
		let mut r = Reader::new(f.need(4)?);
		let count = r.u16()?;
		if count > 16 {
			return Err(CodecError::Malformed("too many prevouts"));
		}
		let mut prevouts = Vec::with_capacity(count as usize);
		for _ in 0..count {
			prevouts.push(Prevout {
				value_sat: r.u64()?,
				script: r.blob16(MAX_SCRIPT_BYTES)?.to_vec(),
			});
		}
		r.finish()?;
		let prior_funding_pubkeys = f
			.get(15)
			.map(|v| {
				let mut r = Reader::new(v);
				let p = FundingPubkeys { local: r.pubkey()?, remote: r.pubkey()? };
				r.finish()?;
				Ok(p)
			})
			.transpose()?;
		Ok(Self {
			offer_id: f.array(0)?,
			raw_tx: bounded(f.need(2)?, MAX_RAW_TX_BYTES)?.to_vec(),
			prevouts,
			attestation: Attestation {
				funding_output_index: f.u32(6)?,
				local_funding_pubkey: f.pubkey(8)?,
				remote_funding_pubkey: f.pubkey(10)?,
				signature: f.array(12)?,
				prior_funding_pubkeys,
			},
			shared_input_index: f.get(13).map(read_u32).transpose()?,
		})
	}
	pub(crate) fn transaction(&self) -> Result<Transaction> {
		bitcoin::consensus::deserialize(&self.raw_tx)
			.map_err(|_| CodecError::Malformed("invalid transaction"))
	}
	pub(crate) fn attestation_message(&self) -> Result<String> {
		if let Some(prior) = &self.attestation.prior_funding_pubkeys {
			let shared = self
				.shared_input_index
				.ok_or(CodecError::Malformed("prior keys require a splice input"))?;
			Ok(splice_attestation_message(
				&self.offer_id,
				&self.raw_tx,
				self.attestation.funding_output_index,
				&FundingPubkeys {
					local: self.attestation.local_funding_pubkey,
					remote: self.attestation.remote_funding_pubkey,
				},
				shared,
				prior,
			))
		} else {
			Ok(attestation_message(
				&self.offer_id,
				&self.raw_tx,
				self.attestation.funding_output_index,
				&self.attestation.local_funding_pubkey,
			))
		}
	}
	pub(crate) fn verify_attestation(&self, receiver: &PublicKey) -> bool {
		self.attestation_message()
			.is_ok_and(|m| verify_message(&m, &self.attestation.signature, receiver))
	}
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Witness {
	pub offer_id: [u8; 16],
	pub witness: Vec<Vec<u8>>,
}
impl Witness {
	pub(crate) fn encode(&self) -> Result<Vec<u8>> {
		if self.witness.len() > 8 {
			return Err(CodecError::Malformed("too many witness items"));
		}
		let mut stack = (self.witness.len() as u16).to_be_bytes().to_vec();
		for item in &self.witness {
			put_blob16(&mut stack, bounded(item, 1024)?)?;
		}
		let mut f = Fields::new();
		f.put(0, self.offer_id);
		f.put(2, stack);
		f.encode()
	}
	pub(crate) fn decode(data: &[u8]) -> Result<Self> {
		let f = Fields::decode(data, &[0, 2])?;
		let mut r = Reader::new(f.need(2)?);
		let count = r.u16()?;
		if count > 8 {
			return Err(CodecError::Malformed("too many witness items"));
		}
		let mut witness = Vec::with_capacity(count as usize);
		for _ in 0..count {
			witness.push(r.blob16(1024)?.to_vec());
		}
		r.finish()?;
		Ok(Self { offer_id: f.array(0)?, witness })
	}
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Receipt {
	pub offer_id: [u8; 16],
	pub preimage: [u8; 32],
	pub funding_txid: [u8; 32],
	pub raw_tx: Option<Vec<u8>>,
}
impl Receipt {
	pub(crate) fn encode(&self) -> Result<Vec<u8>> {
		let mut f = Fields::new();
		f.put(0, self.offer_id);
		f.put(2, self.preimage);
		f.put(4, self.funding_txid);
		if let Some(raw) = &self.raw_tx {
			f.put(5, bounded(raw, MAX_RAW_TX_BYTES)?);
		}
		f.encode()
	}
	pub(crate) fn decode(data: &[u8]) -> Result<Self> {
		let f = Fields::decode(data, &[0, 2, 4, 5])?;
		Ok(Self {
			offer_id: f.array(0)?,
			preimage: f.array(2)?,
			funding_txid: f.array(4)?,
			raw_tx: f
				.get(5)
				.map(|b| bounded(b, MAX_RAW_TX_BYTES).map(|v| v.to_vec()))
				.transpose()?,
		})
	}
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RelayAddress {
	To(PublicKey),
	From(PublicKey),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelayFrame {
	pub subtype: u16,
	pub payload: Vec<u8>,
	pub address: RelayAddress,
}
impl RelayFrame {
	pub(crate) fn encode(&self) -> Result<Vec<u8>> {
		let mut f = Fields::new();
		f.put(0, self.subtype.to_be_bytes());
		f.put(2, bounded(&self.payload, MAX_MESSAGE_BYTES)?);
		match self.address {
			RelayAddress::To(p) => f.put(4, p.serialize()),
			RelayAddress::From(p) => f.put(6, p.serialize()),
		};
		f.encode()
	}
	pub(crate) fn decode(data: &[u8]) -> Result<Self> {
		let f = Fields::decode(data, &[0, 2, 4, 6])?;
		let address = match (f.get(4), f.get(6)) {
			(Some(_), None) => RelayAddress::To(f.pubkey(4)?),
			(None, Some(_)) => RelayAddress::From(f.pubkey(6)?),
			_ => return Err(CodecError::Malformed("relay needs exactly one address")),
		};
		Ok(Self { subtype: u16::from_be_bytes(f.array(0)?), payload: f.need(2)?.to_vec(), address })
	}
}

pub(crate) fn derive_offer_id(txid: &[u8; 32], vout: u32, amount_sat: u64) -> [u8; 16] {
	let hash =
		sha256::Hash::hash(format!("{}:{vout}:{amount_sat}", hex(txid)).as_bytes()).to_byte_array();
	let mut id = [0; 16];
	id.copy_from_slice(&hash[..16]);
	id
}
pub(crate) fn ownership_message(
	offer_id: &[u8; 16], txid: &[u8; 32], vout: u32, amount_sat: u64, receipt_hash: &[u8; 32],
	receiver: &PublicKey,
) -> String {
	format!(
		"lfbw-direct-funding-offer:{}:{}:{vout}:{amount_sat}:{}:{}",
		hex(offer_id),
		hex(txid),
		hex(receipt_hash),
		receiver
	)
}
pub(crate) fn ownership_digest(
	offer_id: &[u8; 16], txid: &[u8; 32], vout: u32, amount_sat: u64, receipt_hash: &[u8; 32],
	receiver: &PublicKey,
) -> [u8; 32] {
	sha256::Hash::hash(
		ownership_message(offer_id, txid, vout, amount_sat, receipt_hash, receiver).as_bytes(),
	)
	.to_byte_array()
}
pub(crate) fn attestation_message(
	offer_id: &[u8; 16], raw_tx: &[u8], funding_output_index: u32, local_funding_pubkey: &PublicKey,
) -> String {
	format!(
		"lfbw-direct-funding-attest:{}:{}:{funding_output_index}:{local_funding_pubkey}",
		hex(offer_id),
		sha256::Hash::hash(raw_tx)
	)
}
pub(crate) fn splice_attestation_message(
	offer_id: &[u8; 16], raw_tx: &[u8], funding_output_index: u32, keys: &FundingPubkeys,
	shared_input_index: u32, prior: &FundingPubkeys,
) -> String {
	format!("lfbw-direct-funding-splice-attest:{}:{}:{funding_output_index}:{}:{}:{shared_input_index}:{}:{}",hex(offer_id),sha256::Hash::hash(raw_tx),keys.local,keys.remote,prior.local,prior.remote)
}
/// A never-broadcastable transaction proving control of the payer's coin, bound to this request.
pub(crate) fn ownership_probe_transaction(
	offer: &Offer, coin_script: &[u8], receiver: &PublicKey,
) -> (Transaction, Vec<TxOut>) {
	let mut poison = b"lfbw-direct-funding-poison".to_vec();
	poison.extend(offer.offer_id);
	let poison = sha256::Hash::hash(&poison).to_byte_array();
	let mut script = vec![0x6a, 0x4c, 81];
	script.extend(offer.offer_id);
	script.extend(offer.receipt_hash);
	script.extend(receiver.serialize());
	let input = |previous_output| TxIn {
		previous_output,
		script_sig: ScriptBuf::new(),
		sequence: Sequence(offer.sequence),
		witness: bitcoin::Witness::new(),
	};
	let tx = Transaction {
		version: transaction::Version::TWO,
		lock_time: absolute::LockTime::ZERO,
		input: vec![
			input(offer.outpoint()),
			input(OutPoint { txid: Txid::from_byte_array(poison), vout: 0 }),
		],
		output: vec![TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(script) }],
	};
	let mut poison_script = vec![0x6a, 0x0b];
	poison_script.extend(b"lfbw-poison");
	(
		tx,
		vec![
			TxOut {
				value: Amount::from_sat(offer.value_sat),
				script_pubkey: ScriptBuf::from_bytes(coin_script.to_vec()),
			},
			TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::from_bytes(poison_script) },
		],
	)
}
pub(crate) fn bitcoin_message_hash(message: &str) -> [u8; 32] {
	let prefix = b"Bitcoin Signed Message:\n";
	let mut bytes = bitcoin::consensus::serialize(&bitcoin::VarInt(prefix.len() as u64));
	bytes.extend(prefix);
	bytes.extend(bitcoin::consensus::serialize(&bitcoin::VarInt(message.len() as u64)));
	bytes.extend(message.as_bytes());
	sha256d::Hash::hash(&bytes).to_byte_array()
}
pub(crate) fn txid_from_display(mut txid: [u8; 32]) -> Txid {
	txid.reverse();
	Txid::from_byte_array(txid)
}
pub(crate) fn txid_to_display(txid: Txid) -> [u8; 32] {
	let mut bytes = txid.to_byte_array();
	bytes.reverse();
	bytes
}
pub(crate) fn hex(bytes: &[u8]) -> String {
	use std::fmt::Write;
	let mut out = String::with_capacity(bytes.len() * 2);
	for b in bytes {
		let _ = write!(out, "{b:02x}");
	}
	out
}

fn put_host(out: &mut Vec<u8>, host: &str, port: u16) -> Result<()> {
	if host.len() > 255 {
		return Err(CodecError::Malformed("host too long"));
	}
	out.push(host.len() as u8);
	out.extend(host.as_bytes());
	out.extend(port.to_be_bytes());
	Ok(())
}
fn put_blob16(out: &mut Vec<u8>, value: &[u8]) -> Result<()> {
	let len = u16::try_from(value.len()).map_err(|_| CodecError::Malformed("field too long"))?;
	out.extend(len.to_be_bytes());
	out.extend(value);
	Ok(())
}
fn bounded(value: &[u8], max: usize) -> Result<&[u8]> {
	if value.len() > max {
		Err(CodecError::Malformed("field exceeds bound"))
	} else {
		Ok(value)
	}
}
fn read_u32(value: &[u8]) -> Result<u32> {
	Ok(u32::from_be_bytes(
		value.try_into().map_err(|_| CodecError::Malformed("invalid u32 width"))?,
	))
}
struct Reader<'a> {
	data: &'a [u8],
	offset: usize,
}
impl<'a> Reader<'a> {
	fn new(data: &'a [u8]) -> Self {
		Self { data, offset: 0 }
	}
	fn take(&mut self, n: usize) -> Result<&'a [u8]> {
		let end = self.offset.checked_add(n).ok_or(CodecError::Malformed("length overflow"))?;
		let value =
			self.data.get(self.offset..end).ok_or(CodecError::Malformed("truncated field"))?;
		self.offset = end;
		Ok(value)
	}
	fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
		self.take(N)?.try_into().map_err(|_| CodecError::Malformed("fixed field width"))
	}
	fn u8(&mut self) -> Result<u8> {
		Ok(self.array::<1>()?[0])
	}
	fn u16(&mut self) -> Result<u16> {
		Ok(u16::from_be_bytes(self.array()?))
	}
	fn u64(&mut self) -> Result<u64> {
		Ok(u64::from_be_bytes(self.array()?))
	}
	fn pubkey(&mut self) -> Result<PublicKey> {
		PublicKey::from_slice(self.take(33)?)
			.map_err(|_| CodecError::Malformed("invalid public key"))
	}
	fn blob16(&mut self, max: usize) -> Result<&'a [u8]> {
		let n = self.u16()? as usize;
		if n > max {
			return Err(CodecError::Malformed("field exceeds bound"));
		}
		self.take(n)
	}
	fn host(&mut self) -> Result<(String, u16)> {
		let n = self.u8()? as usize;
		let host = String::from_utf8(self.take(n)?.to_vec())
			.map_err(|_| CodecError::Malformed("invalid host UTF-8"))?;
		Ok((host, self.u16()?))
	}
	fn finish(&self) -> Result<()> {
		if self.offset == self.data.len() {
			Ok(())
		} else {
			Err(CodecError::Malformed("trailing bytes"))
		}
	}
	fn bigsize(&mut self) -> Result<u64> {
		let first = self.u8()?;
		match first {
			0..=252 => Ok(first as u64),
			253 => {
				let n = self.u16()? as u64;
				if n < 253 {
					Err(CodecError::Malformed("noncanonical bigsize"))
				} else {
					Ok(n)
				}
			},
			254 => {
				let n = u32::from_be_bytes(self.array()?) as u64;
				if n < 0x10000 {
					Err(CodecError::Malformed("noncanonical bigsize"))
				} else {
					Ok(n)
				}
			},
			255 => {
				let n = self.u64()?;
				if n < 0x100000000 {
					Err(CodecError::Malformed("noncanonical bigsize"))
				} else {
					Ok(n)
				}
			},
		}
	}
}
fn put_bigsize(out: &mut Vec<u8>, n: u64) {
	if n < 253 {
		out.push(n as u8)
	} else if n <= 0xffff {
		out.push(253);
		out.extend((n as u16).to_be_bytes())
	} else if n <= 0xffffffff {
		out.push(254);
		out.extend((n as u32).to_be_bytes())
	} else {
		out.push(255);
		out.extend(n.to_be_bytes())
	}
}
struct Fields(BTreeMap<u64, Vec<u8>>);
impl Fields {
	fn new() -> Self {
		Self(BTreeMap::new())
	}
	fn put(&mut self, kind: u64, value: impl AsRef<[u8]>) {
		self.0.insert(kind, value.as_ref().to_vec());
	}
	fn get(&self, kind: u64) -> Option<&[u8]> {
		self.0.get(&kind).map(Vec::as_slice)
	}
	fn need(&self, kind: u64) -> Result<&[u8]> {
		self.get(kind).ok_or(CodecError::Malformed("missing required TLV"))
	}
	fn array<const N: usize>(&self, kind: u64) -> Result<[u8; N]> {
		self.need(kind)?.try_into().map_err(|_| CodecError::Malformed("invalid TLV width"))
	}
	fn u32(&self, kind: u64) -> Result<u32> {
		Ok(u32::from_be_bytes(self.array(kind)?))
	}
	fn u64(&self, kind: u64) -> Result<u64> {
		Ok(u64::from_be_bytes(self.array(kind)?))
	}
	fn pubkey(&self, kind: u64) -> Result<PublicKey> {
		let key = self.array::<33>(kind)?;
		PublicKey::from_slice(&key).map_err(|_| CodecError::Malformed("invalid public key"))
	}
	fn encode(&self) -> Result<Vec<u8>> {
		let mut out = Vec::new();
		for (kind, value) in &self.0 {
			put_bigsize(&mut out, *kind);
			put_bigsize(&mut out, value.len() as u64);
			out.extend(value);
		}
		bounded(&out, MAX_MESSAGE_BYTES)?;
		Ok(out)
	}
	fn decode(data: &[u8], known: &[u64]) -> Result<Self> {
		bounded(data, MAX_MESSAGE_BYTES)?;
		let mut r = Reader::new(data);
		let mut out = Self::new();
		let mut previous = None;
		while r.offset < data.len() {
			let kind = r.bigsize()?;
			if previous.is_some_and(|p| kind <= p) {
				return Err(CodecError::Malformed("unordered or duplicate TLV"));
			}
			previous = Some(kind);
			let length = usize::try_from(r.bigsize()?)
				.map_err(|_| CodecError::Malformed("TLV length overflow"))?;
			let value = r.take(length)?;
			if !known.contains(&kind) {
				if kind % 2 == 0 {
					return Err(CodecError::Malformed("unknown required TLV"));
				}
			} else {
				out.put(kind, value);
			}
		}
		Ok(out)
	}
}

#[cfg(test)]
pub(crate) mod tests {
	use super::super::crypto::sign_message;
	use super::*;
	use bitcoin::secp256k1::{Secp256k1, SecretKey};
	use proptest::prelude::*;

	proptest! {
		#[test]
		fn arbitrary_wire_bytes_are_bounded_and_never_panic(data in prop::collection::vec(any::<u8>(), 0..8192)) {
			let _ = Offer::decode(&data);
			let _ = OfferAck::decode(&data);
			let _ = SignRequest::decode(&data);
			let _ = Witness::decode(&data);
			let _ = Receipt::decode(&data);
			let _ = RelayFrame::decode(&data);
			let _ = super::super::crypto::decode_frame(&data);
			let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&data);
			let _ = RequestEnvelope::decode(&encoded, 1_700_000_000_000, &chain(), false);
		}

		#[test]
		fn signed_request_roundtrip_preserves_amount_and_identity(amount in 5_000u64..2_100_000_000_000_000, id in any::<[u8;16]>()) {
			let mut request = decode_fixture();
			request.amount_sat = Some(amount);
			request.request_id = id;
			let text = request.prepare_signature(1_700_000_000_000).unwrap();
			request.signature = sign_message(&text, &SecretKey::from_slice(&[0x11;32]).unwrap());
			let encoded = request.encode().unwrap();
			let restored = RequestEnvelope::decode(&encoded, 1_700_000_000_000, &chain(), false).unwrap();
			prop_assert_eq!(restored.amount_sat, Some(amount));
			prop_assert_eq!(restored.request_id, id);
			prop_assert_eq!(restored.encode().unwrap(), encoded);
		}
	}
	const BEIGNET_FIXTURE: &str = r#"{"envelope":"AwABAgMEBQYHCAkKCwwNDg8GIm5GERoLWcqvEmBD61u_KMNPOl4zKh_Hsrc88YiRDwNPNVvct8wK9yjvPM65YV2QaEu1sspfhZqw8LcEB1hxqgGL0BxWgAEAAAAAAAPQkKurq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urAjxyrdtP3wmvlPDJTX_pKjhqfnDPih2FkWOGuyU1x7GxAwEAExByZWNlaXZlci5leGFtcGxlJgcCAHoNcmVsYXkuZXhhbXBsZSYIAywLfPlTJKB9BTmLJAF03Awr5ETZaxWapsf3seZoaAmRAprCAzXrOHaNIFK-HbvDyPYXhAdFjlHmtK0i8dkXWIlbAQNatGieQApKFgzwHNRHMIRaVHaN-FR9zfBz2WTxCfGMMAAE3q2-7wMAMQMsC3z5UySgfQU5iyQBdNwMK-RE2WsVmqbH97HmaGgJkQ1yZWxheS5leGFtcGxlJgggVKneIFtWiRwyoQMY0Ooqegu6yHI6jU_5QKMP5qYZXYwWHC0e5ODIEE5CnPoEIIUQX8DkSLT81O4kzP_N5azpwQ","offer":"001018fd63549b8f070c7178e4c551837a690208000000000003d0900420a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a106040000000108080000000000061a800a04fffffffd0c16000000000000000000000000000000000000000000000e0800000000000003e81020b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b21221028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7144005050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505","ack":"001018fd63549b8f070c7178e4c551837a69020100030c6e6f206c6971756964697479","sign":"001018fd63549b8f070c7178e4c551837a6902fd012c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c044e00020000000000061a8000161111111111111111111111111111111111111111111100000000000dbba00022222222222222222222222222222222222222222222222222222222222222222222220604000000000821036930f46dd0b16d866d59d1054aa63298b357499cd1862ef16f3f55f1cafceb820a2102eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f2836866190c4107070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070707070d0400000001","witness":"001018fd63549b8f070c7178e4c551837a69026f00020048aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0021028d7500dd4c12685d1f568b4c2b5048e8534b873319f3a8daa612b469132ec7f7","receipt":"001018fd63549b8f070c7178e4c551837a690220c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c30420d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d405fd012c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c","relay":"00020010025801000102030405060708090a0b0c0d0e0f0256b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967000102030405060708090a0b128061c502e64ed070cb032189517fe04b2034c3189d561eca900421034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa","offerId":"18fd63549b8f070c7178e4c551837a69","ownership":"lfbw-direct-funding-offer:18fd63549b8f070c7178e4c551837a69:a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1:1:250000:b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2:03baf7689c0a3558fb604589036a8d1e4b685d909f6e0e2c6018a14049ae64ec26","ownershipDigest":"84a95444aedd16d8176726ca16dffc3daf8c5281b439dcfb2fa5bdac5635a093","bitcoinMessageHash":"5d8e4c151b9f946bd8829b601c01001d629acfd90cc9007230a4246354ce3102","probe":"0200000002a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10100000000fdffffff846ff1fc5363c401cd8fca2bd47ad54c6d27423161ea5aff796b9765ef0d14680000000000fdffffff010000000000000000546a4c5118fd63549b8f070c7178e4c551837a69b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b203baf7689c0a3558fb604589036a8d1e4b685d909f6e0e2c6018a14049ae64ec2600000000","attestation":"lfbw-direct-funding-attest:18fd63549b8f070c7178e4c551837a69:689f40ffaa80db112aa61355eb5285138d9ce7f2889bc069e6ce9d90754f2af2:0:036930f46dd0b16d866d59d1054aa63298b357499cd1862ef16f3f55f1cafceb82","spliceAttestation":"lfbw-direct-funding-splice-attest:18fd63549b8f070c7178e4c551837a69:689f40ffaa80db112aa61355eb5285138d9ce7f2889bc069e6ce9d90754f2af2:0:036930f46dd0b16d866d59d1054aa63298b357499cd1862ef16f3f55f1cafceb82:02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619:1:036930f46dd0b16d866d59d1054aa63298b357499cd1862ef16f3f55f1cafceb82:0324653eac434488002cc06bbfb7f10fe18991e35f9fe4302dbea6d2353dc0ab1c","sendKey":"67458d5ba65d88478a7cb79f3a0960ce6074ec312556c8cbbb0d16c19c1a120f","recvKey":"ca8ea7614324ac2031917ae54ac563cc8a35f6dc0cda3e71b0afca79b933aab1","frame":"01000102030405060708090a0b0c0d0e0f0256b328b30c8bf5839e24058747879408bdb36241dc9c2e7c619faa12b2920967000102030405060708090a0b128061c502e64ed070cb032189517fe04b2034c3189d561eca90"}"#;

	// Generated directly with ts-node from Beignet's envelope.ts, messages.ts and frames.ts,
	// using the fixed keys/amounts in its direct-funding-{envelope,messages,frames}.test.ts.
	pub(crate) fn fixture(name: &str) -> String {
		serde_json::from_str::<serde_json::Value>(BEIGNET_FIXTURE).unwrap()[name]
			.as_str()
			.unwrap()
			.to_owned()
	}
	pub(crate) fn unhex(text: &str) -> Vec<u8> {
		assert_eq!(text.len() % 2, 0);
		(0..text.len())
			.step_by(2)
			.map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
			.collect()
	}
	fn pk(byte: u8) -> PublicKey {
		PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[byte; 32]).unwrap())
	}
	fn chain() -> [u8; 32] {
		unhex("06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f")
			.try_into()
			.unwrap()
	}
	fn decode_fixture() -> RequestEnvelope {
		RequestEnvelope::decode(&fixture("envelope"), 1_700_000_000_000, &chain(), false).unwrap()
	}
	#[test]
	fn beignet_signed_envelope_parity() {
		let env = decode_fixture();
		assert_eq!(env.receiver_node_id, pk(0x11));
		assert_eq!(env.encryption_key, pk(0x33));
		assert_eq!(env.amount_sat, Some(250_000));
		assert_eq!(env.expires_at, 1_700_003_600_000);
		assert_eq!(env.transports.len(), 3);
		assert_eq!(env.encode().unwrap(), fixture("envelope"));
		let mut minted = env.clone();
		minted.signature = [0; 65];
		minted.signed_bytes.clear();
		let message = minted.prepare_signature(1_700_000_000_000).unwrap();
		minted.signature = sign_message(&message, &SecretKey::from_slice(&[0x11; 32]).unwrap());
		assert_eq!(minted.encode().unwrap(), fixture("envelope"));
		assert_eq!(
			env.transports[1].endpoint(pk(0x11)),
			Some((pk(0x44), "relay.example", 9736, true))
		);
	}
	#[test]
	fn beignet_all_message_parity() {
		macro_rules! check {
			($name:literal,$ty:ty) => {{
				let raw = unhex(&fixture($name));
				let value = <$ty>::decode(&raw).unwrap();
				assert_eq!(value.encode().unwrap(), raw);
				assert!(<$ty>::decode(&[raw.clone(), vec![0]].concat()).is_err());
			}};
		}
		check!("offer", Offer);
		check!("ack", OfferAck);
		check!("sign", SignRequest);
		check!("witness", Witness);
		check!("receipt", Receipt);
		check!("relay", RelayFrame);
		let offer = Offer::decode(&unhex(&fixture("offer"))).unwrap();
		assert_eq!(offer.amount_sat, 250_000);
		assert_eq!(offer.value_sat, 400_000);
		assert_eq!(offer.sequence, 0xffff_fffd);
		assert_eq!(offer.offer_id, derive_offer_id(&[0xa1; 32], 1, 250_000));
		assert_eq!(hex(&offer.offer_id), fixture("offerId"));
		assert_eq!(offer.ownership.pubkey, pk(0x21).serialize());
	}
	#[test]
	fn beignet_signed_strings_and_probe_parity() {
		let offer = Offer::decode(&unhex(&fixture("offer"))).unwrap();
		assert_eq!(offer.ownership_message(&pk(0x51)), fixture("ownership"));
		assert_eq!(hex(&offer.ownership_digest(&pk(0x51))), fixture("ownershipDigest"));
		assert_eq!(
			hex(&bitcoin_message_hash(&offer.ownership_message(&pk(0x51)))),
			fixture("bitcoinMessageHash")
		);
		let script = unhex("00141111111111111111111111111111111111111111");
		let (tx, prevouts) = ownership_probe_transaction(&offer, &script, &pk(0x51));
		assert_eq!(hex(&bitcoin::consensus::serialize(&tx)), fixture("probe"));
		assert_eq!(prevouts[0].value.to_sat(), 400_000);
		assert_eq!(prevouts[1].value.to_sat(), 0);
		let sign = SignRequest::decode(&unhex(&fixture("sign"))).unwrap();
		assert_eq!(sign.attestation_message().unwrap(), fixture("attestation"));
		assert_eq!(
			splice_attestation_message(
				&offer.offer_id,
				&sign.raw_tx,
				0,
				&FundingPubkeys { local: pk(0x31), remote: pk(0x41) },
				1,
				&FundingPubkeys { local: pk(0x31), remote: pk(0x42) }
			),
			fixture("spliceAttestation")
		);
	}
	#[test]
	fn envelope_rejects_expired_wrong_chain_bad_signature_and_noncanonical_base64() {
		let encoded = fixture("envelope");
		assert_eq!(
			RequestEnvelope::decode(&encoded, 1_700_003_600_000, &chain(), false),
			Err(CodecError::Expired)
		);
		assert!(RequestEnvelope::decode(&encoded, 1_700_003_600_000, &chain(), true).is_ok());
		assert_eq!(
			RequestEnvelope::decode(&encoded, 0, &chain(), false),
			Err(CodecError::ExpiryTooDistant)
		);
		assert_eq!(
			RequestEnvelope::decode(&encoded, 1_700_000_000_000, &[0; 32], false),
			Err(CodecError::WrongChain)
		);
		assert!(RequestEnvelope::decode(
			&(encoded.clone() + "="),
			1_700_000_000_000,
			&chain(),
			false
		)
		.is_err());
		let mut raw = URL_SAFE_NO_PAD.decode(&encoded).unwrap();
		let last = raw.len() - 1;
		raw[last] ^= 1;
		assert!(RequestEnvelope::decode(
			&URL_SAFE_NO_PAD.encode(raw),
			1_700_000_000_000,
			&chain(),
			false
		)
		.is_err());
		for n in 0..encoded.len() {
			assert!(
				RequestEnvelope::decode(&encoded[..n], 1_700_000_000_000, &chain(), false).is_err()
			);
		}
	}
	#[test]
	fn envelope_preserves_unknown_flag_and_transport_extension_under_signature() {
		let env = decode_fixture();
		let mut raw = env.signed_bytes.clone();
		raw[88] |= 0x80;
		let signature = sign_message(
			&canonical_request_message(&raw),
			&SecretKey::from_slice(&[0x11; 32]).unwrap(),
		);
		raw.extend(signature);
		let encoded = URL_SAFE_NO_PAD.encode(raw);
		let decoded =
			RequestEnvelope::decode(&encoded, 1_700_000_000_000, &chain(), false).unwrap();
		assert_eq!(decoded.encode().unwrap(), encoded);
		let mut env = decode_fixture();
		env.transports = vec![TransportDescriptor::Unknown { kind: 77, value: vec![1, 2, 3] }];
		env.signed_bytes = env.unsigned_bytes().unwrap();
		env.signature =
			sign_message(&env.signing_message(), &SecretKey::from_slice(&[0x11; 32]).unwrap());
		let encoded = env.encode().unwrap();
		let decoded =
			RequestEnvelope::decode(&encoded, 1_700_000_000_000, &chain(), false).unwrap();
		assert_eq!(decoded.transports, env.transports);
		assert_eq!(decoded.encode().unwrap(), encoded);
		assert!(env.prepare_signature(1_700_000_000_000).is_err());
	}
	#[test]
	fn canonical_tlv_rules_and_bounds() {
		let raw = unhex(&fixture("offer"));
		let odd = [raw.clone(), vec![25, 1, 7]].concat();
		assert!(Offer::decode(&odd).is_ok());
		let even = [raw.clone(), vec![24, 1, 7]].concat();
		assert!(Offer::decode(&even).is_err());
		assert!(Offer::decode(&[raw.clone(), vec![0, 0]].concat()).is_err());
		assert!(Offer::decode(&[vec![253, 0, 0], raw[1..].to_vec()].concat()).is_err());
		assert!(Offer::decode(&vec![0; MAX_MESSAGE_BYTES + 1]).is_err());
		let mut offer = Offer::decode(&raw).unwrap();
		offer.change_script = vec![0; 521];
		assert!(offer.encode().is_err());
		offer.change_script.clear();
		offer.ownership.pubkey = vec![0; 34];
		assert!(offer.encode().is_err());
		let mut f = Fields::new();
		f.put(0, 16u16.to_be_bytes());
		f.put(2, []);
		f.put(4, pk(0x11).serialize());
		f.put(6, pk(0x22).serialize());
		assert!(RelayFrame::decode(&f.encode().unwrap()).is_err());
		assert!(Witness { offer_id: [0; 16], witness: vec![vec![]; 9] }.encode().is_err());
		assert!(Witness { offer_id: [0; 16], witness: vec![vec![0; 1025]] }.encode().is_err());
	}
	#[test]
	fn optional_message_and_probe_proofs_roundtrip_and_enforce_exact_widths() {
		let mut offer = Offer::decode(&unhex(&fixture("offer"))).unwrap();
		offer.ownership.message_proof =
			Some(MessageProof { pubkey: pk(0x21).serialize(), signature: [9; 65] });
		offer.ownership.probe_proof = Some(ProbeProof { pubkey: [0; 33], signature: [7; 64] });
		assert_eq!(Offer::decode(&offer.encode().unwrap()).unwrap(), offer);
		let mut f = Fields::decode(
			&offer.encode().unwrap(),
			&[0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 21, 23],
		)
		.unwrap();
		f.put(21, [0; 97]);
		assert!(Offer::decode(&f.encode().unwrap()).is_err());
	}

	#[test]
	fn rotated_splice_attestation_covers_both_funding_pairs_and_shared_input() {
		let mut request = SignRequest::decode(&unhex(&fixture("sign"))).unwrap();
		request.attestation.prior_funding_pubkeys =
			Some(FundingPubkeys { local: pk(0x31), remote: pk(0x42) });
		request.attestation.signature = sign_message(
			&request.attestation_message().unwrap(),
			&SecretKey::from_slice(&[0x51; 32]).unwrap(),
		);
		let encoded = request.encode().unwrap();
		let decoded = SignRequest::decode(&encoded).unwrap();
		assert_eq!(decoded, request);
		assert!(decoded.verify_attestation(&pk(0x51)));
		let mut changed = decoded.clone();
		changed.shared_input_index = Some(0);
		assert!(!changed.verify_attestation(&pk(0x51)));
		let mut changed = decoded.clone();
		changed.attestation.remote_funding_pubkey = pk(0x43);
		assert!(!changed.verify_attestation(&pk(0x51)));
		let mut changed = decoded;
		changed.shared_input_index = None;
		assert!(!changed.verify_attestation(&pk(0x51)));
	}
}
