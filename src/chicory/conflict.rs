//! Bounded payload codecs for Beignet's splice conflict recovery extension.
//!
//! These messages are prompts to verify a conflict against the local chain.
//! Decoding a request or an affirmative acknowledgment never authorizes a
//! rollback. Authentication, quiescence, chain proof and native persistence
//! must be checked separately before changing a funding candidate.

#![forbid(unsafe_code)]

use super::wire::WireError;

/// Request subtype inside the versioned Beignet custom message envelope.
pub const REQUEST_SUBTYPE: u16 = 64;
/// Acknowledgment subtype inside the versioned Beignet custom message envelope.
pub const ACK_SUBTYPE: u16 = 65;
/// Exact request payload size, excluding the envelope and Lightning wire type.
pub const REQUEST_LENGTH: usize = 98;
/// Maximum encoded UTF-8 bytes in an acknowledgment reason.
pub const MAX_REASON_BYTES: usize = 256;
const ACK_FIXED_LENGTH: usize = 67;

/// A claim that a nonshared input of an unconfirmed splice was spent elsewhere.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpliceConflictRequest {
	/// Stable channel identity, authenticated separately against the sending peer.
	pub channel_id: [u8; 32],
	/// Candidate transaction hash in internal byte order, never display order.
	pub splice_txid: [u8; 32],
	/// Competing transaction hash in internal byte order, never display order.
	pub conflict_txid: [u8; 32],
	/// Position of the conflicting input in the candidate transaction.
	pub input_index: u16,
}

impl SpliceConflictRequest {
	/// Encode exactly 98 payload bytes, preserving the transaction hash order.
	pub fn encode(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(REQUEST_LENGTH);
		bytes.extend_from_slice(&self.channel_id);
		bytes.extend_from_slice(&self.splice_txid);
		bytes.extend_from_slice(&self.conflict_txid);
		bytes.extend_from_slice(&self.input_index.to_be_bytes());
		bytes
	}

	/// Reject truncation or trailing bytes. This does not verify the conflict.
	pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
		if bytes.len() != REQUEST_LENGTH {
			return Err(WireError("splice conflict request has an invalid length"));
		}
		Ok(Self {
			channel_id: bytes[..32].try_into().unwrap(),
			splice_txid: bytes[32..64].try_into().unwrap(),
			conflict_txid: bytes[64..96].try_into().unwrap(),
			input_index: u16::from_be_bytes(bytes[96..98].try_into().unwrap()),
		})
	}
}

/// The peer's report about a splice conflict recovery request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpliceConflictAck {
	/// Stable channel identity, authenticated separately against the sending peer.
	pub channel_id: [u8; 32],
	/// Candidate transaction hash in internal byte order, never display order.
	pub splice_txid: [u8; 32],
	/// True reports a durable rollback, subject to independent local validation.
	pub agreed: bool,
	/// Bounded UTF-8 explanation, normally empty for an affirmative reply.
	pub reason: String,
}

impl SpliceConflictAck {
	/// Encode a bounded reason without truncating or normalizing its UTF-8 bytes.
	pub fn encode(&self) -> Result<Vec<u8>, WireError> {
		if self.reason.len() > MAX_REASON_BYTES {
			return Err(WireError("splice conflict acknowledgment reason exceeds its limit"));
		}
		let mut bytes = Vec::with_capacity(ACK_FIXED_LENGTH + self.reason.len());
		bytes.extend_from_slice(&self.channel_id);
		bytes.extend_from_slice(&self.splice_txid);
		bytes.push(u8::from(self.agreed));
		bytes.extend_from_slice(&(self.reason.len() as u16).to_be_bytes());
		bytes.extend_from_slice(self.reason.as_bytes());
		Ok(bytes)
	}

	/// Decode an exact bounded frame with a canonical boolean and valid UTF-8.
	pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
		if bytes.len() < ACK_FIXED_LENGTH || bytes.len() > ACK_FIXED_LENGTH + MAX_REASON_BYTES {
			return Err(WireError("splice conflict acknowledgment has an invalid length"));
		}
		let agreed = match bytes[64] {
			0 => false,
			1 => true,
			_ => return Err(WireError("splice conflict acknowledgment has an invalid boolean")),
		};
		let reason_len = u16::from_be_bytes(bytes[65..67].try_into().unwrap()) as usize;
		if reason_len > MAX_REASON_BYTES || bytes.len() != ACK_FIXED_LENGTH + reason_len {
			return Err(WireError("splice conflict acknowledgment reason has an invalid length"));
		}
		let reason = std::str::from_utf8(&bytes[ACK_FIXED_LENGTH..])
			.map_err(|_| WireError("splice conflict acknowledgment reason is not UTF-8"))?;
		Ok(Self {
			channel_id: bytes[..32].try_into().unwrap(),
			splice_txid: bytes[32..64].try_into().unwrap(),
			agreed,
			reason: reason.to_owned(),
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::chicory::wire::{Envelope, PROTOCOL_VERSION};

	fn request() -> SpliceConflictRequest {
		SpliceConflictRequest {
			channel_id: [0x12; 32],
			splice_txid: core::array::from_fn(|i| i as u8),
			conflict_txid: core::array::from_fn(|i| (i + 32) as u8),
			input_index: 0x0102,
		}
	}

	fn ack(reason: &str) -> SpliceConflictAck {
		SpliceConflictAck {
			channel_id: request().channel_id,
			splice_txid: request().splice_txid,
			agreed: false,
			reason: reason.to_owned(),
		}
	}

	#[test]
	fn request_preserves_reference_offsets_and_internal_txid_order() {
		let request = request();
		let bytes = request.encode();
		assert_eq!(bytes.len(), 98);
		assert_eq!(&bytes[32..64], &(0u8..32).collect::<Vec<_>>());
		assert_eq!(&bytes[64..96], &(32u8..64).collect::<Vec<_>>());
		assert_eq!(&bytes[96..], &[1, 2]);
		assert_eq!(SpliceConflictRequest::decode(&bytes).unwrap(), request);
		for length in 0..bytes.len() {
			assert!(SpliceConflictRequest::decode(&bytes[..length]).is_err());
		}
		let mut trailing = bytes;
		trailing.push(0);
		assert!(SpliceConflictRequest::decode(&trailing).is_err());
	}

	#[test]
	fn acknowledgment_roundtrips_boolean_and_utf8_byte_length() {
		for agreed in [false, true] {
			let mut ack = ack("depth不足");
			ack.agreed = agreed;
			let bytes = ack.encode().unwrap();
			assert_eq!(bytes[64], u8::from(agreed));
			assert_eq!(&bytes[65..67], &[0, 11]);
			assert_eq!(SpliceConflictAck::decode(&bytes).unwrap(), ack);
		}
		assert_eq!(ack("").encode().unwrap().len(), 67);
		let boundary = ack(&"é".repeat(128));
		assert_eq!(boundary.encode().unwrap().len(), 323);
		assert_eq!(SpliceConflictAck::decode(&boundary.encode().unwrap()).unwrap(), boundary);
		assert!(ack(&"é".repeat(129)).encode().is_err());
	}

	#[test]
	fn acknowledgment_rejects_noncanonical_boolean_lengths_and_utf8() {
		let original = ack("x").encode().unwrap();
		for length in 0..original.len() {
			assert!(SpliceConflictAck::decode(&original[..length]).is_err());
		}
		let mut changed = original.clone();
		changed[64] = 2;
		assert!(SpliceConflictAck::decode(&changed).is_err());
		changed = original.clone();
		changed[65..67].copy_from_slice(&257u16.to_be_bytes());
		assert!(SpliceConflictAck::decode(&changed).is_err());
		changed = original.clone();
		changed.push(0);
		assert!(SpliceConflictAck::decode(&changed).is_err());
		for malformed in
			[&[0xff][..], &[0xc0, 0x80], &[0xed, 0xa0, 0x80], &[0xf4, 0x90, 0x80, 0x80]]
		{
			changed = original[..67].to_vec();
			changed[65..67].copy_from_slice(&(malformed.len() as u16).to_be_bytes());
			changed.extend_from_slice(malformed);
			assert!(SpliceConflictAck::decode(&changed).is_err());
		}
	}

	#[test]
	fn conflict_payloads_roundtrip_through_the_existing_envelope() {
		for (subtype, payload) in
			[(REQUEST_SUBTYPE, request().encode()), (ACK_SUBTYPE, ack("").encode().unwrap())]
		{
			let envelope = Envelope { version: PROTOCOL_VERSION, subtype, payload };
			assert_eq!(Envelope::decode(&envelope.encode().unwrap()).unwrap(), envelope);
		}
	}
}
