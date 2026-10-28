//! Parser and authenticated-frame fuzzing against the production source files.
#![forbid(unsafe_code)]
#![allow(dead_code)]

#[path = "../../../src/direct_funding/codec.rs"]
mod codec;
#[path = "../../../src/direct_funding/crypto.rs"]
mod crypto;

use base64::Engine;

/// Exercise every untrusted wire parser without creating a wallet or sending funds.
pub fn exercise(data: &[u8]) {
    let _ = codec::Offer::decode(data);
    let _ = codec::OfferAck::decode(data);
    let _ = codec::SignRequest::decode(data);
    let _ = codec::Witness::decode(data);
    let _ = codec::Receipt::decode(data);
    let _ = codec::RelayFrame::decode(data);
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data);
    let _ = codec::RequestEnvelope::decode(&encoded, 1_700_000_000_000, &[0;32], false);
    if let Some(frame) = crypto::decode_frame(data) {
        let _ = crypto::open_frame(&[0;32], &[0;16], codec::OFFER, &frame);
    }
}
