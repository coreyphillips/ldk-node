//! Shared libFuzzer and standalone smoke entry point for untrusted peer bytes.

#![forbid(unsafe_code)]

use ldk_node::chicory::conflict::{SpliceConflictRequest, SpliceConflictAck};

use ldk_node::chicory::wire::{
	Envelope, JitAck, JitAuthorization, JitQuote, JitQuoteRequest, RelayFrame,
};

/// Decode hostile data through every custom protocol parser and reparse valid encodings.
///
/// This exercises byte parsing only. It does not connect peers, spend funds, or
/// treat decoded requests as authorized. All caller-supplied lengths are bounded
/// inside the production codecs before dependent allocations.
pub fn exercise(data: &[u8]) {
	if let Ok(envelope) = Envelope::decode(data) {
		let encoded = envelope.encode().expect("decoded envelope must encode");
		assert_eq!(Envelope::decode(&encoded).unwrap(), envelope);
		exercise_payload(&envelope.payload);
	}
	exercise_payload(data);
}

fn exercise_payload(data: &[u8]) {
	if let Ok(message) = SpliceConflictRequest::decode(data) {
		assert_eq!(message.encode(), data);
		assert_eq!(SpliceConflictRequest::decode(&message.encode()).unwrap(), message);
	}
	if let Ok(message) = SpliceConflictAck::decode(data) {
		let encoded = message.encode().expect("decoded conflict acknowledgment must encode");
		assert_eq!(encoded, data);
		assert_eq!(SpliceConflictAck::decode(&encoded).unwrap(), message);
	}
	if let Ok(message) = JitAuthorization::decode(data) {
		assert_eq!(JitAuthorization::decode(&message.encode()).unwrap(), message);
	}
	if let Ok(message) = JitQuoteRequest::decode(data) {
		assert_eq!(JitQuoteRequest::decode(&message.encode()).unwrap(), message);
	}
	if let Ok(message) = JitAck::decode(data) {
		// Reasons may be truncated in UTF-8 byte space by the reference protocol.
		let canonical = JitAck::decode(&message.encode()).unwrap();
		assert_eq!(canonical.request_id, message.request_id);
		assert_eq!(canonical.intercept_scid, message.intercept_scid);
		assert_eq!(canonical.accepted, message.accepted);
		assert_eq!(canonical.flat_fee_sat, message.flat_fee_sat);
		assert_eq!(canonical.fee_ppm, message.fee_ppm);
		assert_eq!(canonical.fee_mode, message.fee_mode);
	}
	if let Ok(message) = JitQuote::decode(data) {
		let canonical = JitQuote::decode(&message.encode()).unwrap();
		assert_eq!(canonical.request_id, message.request_id);
		assert_eq!(canonical.accepted, message.accepted);
		assert_eq!(canonical.flat_fee_sat, message.flat_fee_sat);
		assert_eq!(canonical.fee_ppm, message.fee_ppm);
		assert_eq!(canonical.max_client_funding_sats, message.max_client_funding_sats);
		assert_eq!(canonical.funding_sats, message.funding_sats);
	}
	if let Ok(message) = RelayFrame::decode(data) {
		// Dropping ignored optional TLVs can only reduce the bounded frame size.
		let encoded = message.encode().expect("decoded relay must encode");
		assert_eq!(RelayFrame::decode(&encoded).unwrap(), message);
	}
}
