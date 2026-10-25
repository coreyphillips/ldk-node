//! Dependency-free deterministic smoke run of the production wire parsers.
//!
//! Build with `rustc --edition=2021 -O fuzz/wire_smoke.rs -o /tmp/chicory-wire-smoke`.

#![forbid(unsafe_code)]

extern crate self as ldk_node;

#[path = "../src/chicory/wire.rs"]
pub mod wire_codec;

pub use wire_codec as wire;
#[path = "../src/chicory/conflict.rs"]
pub mod conflict_codec;

pub mod chicory {
	pub use crate::conflict_codec as conflict;
	pub use crate::wire_codec as wire;
}

#[path = "wire_boundary.rs"]
mod boundary;

use chicory::wire::{
	Envelope, FeeMode, JitAck, JitAuthorization, JitQuote, JitQuoteRequest, RelayAddress,
	RelayFrame, PROTOCOL_VERSION,
};

fn main() {
	let seeds = [
		chicory::conflict::SpliceConflictRequest { channel_id: [4;32], splice_txid: [5;32],
			conflict_txid: [6;32], input_index: 256 }.encode(),
		chicory::conflict::SpliceConflictAck { channel_id: [4;32], splice_txid: [5;32],
			agreed: false, reason: "unconfirmed conflict".into() }.encode().unwrap(),
		JitAuthorization {
			request_id: [1; 8],
			payment_hash: Some([2; 32]),
			max_amount_msat: 1_000_000,
			expected_total_msat: Some(1_000_000),
			target_remaining_inbound_sat: 25_000,
			expiry_seconds: 3600,
			accepts_skimmed_fee: true,
		}
		.encode(),
		JitAck {
			request_id: [1; 8],
			intercept_scid: u64::MAX,
			accepted: true,
			flat_fee_sat: 7,
			fee_ppm: 25,
			reason: Some("accepted".to_owned()),
			fee_mode: Some(FeeMode::Hop),
		}
		.encode(),
		JitQuoteRequest {
			request_id: [1; 8],
			max_amount_msat: 1_000_000,
			target_remaining_inbound_sat: 25_000,
		}
		.encode(),
		JitQuote {
			request_id: [1; 8],
			accepted: true,
			flat_fee_sat: 7,
			fee_ppm: 25,
			max_client_funding_sats: 100_000,
			funding_sats: 26_000,
			reason: None,
		}
		.encode(),
		RelayFrame { subtype: 16, payload: vec![3; 512], address: RelayAddress::To([2; 33]) }
			.encode()
			.unwrap(),
	];
	let mut runs = 0usize;
	for seed in &seeds {
		for length in 0..=seed.len() {
			boundary::exercise(&seed[..length]);
			runs += 1;
		}
		for offset in 0..seed.len() {
			for replacement in 0..=u8::MAX {
				let mut mutated = seed.clone();
				mutated[offset] = replacement;
				boundary::exercise(&mutated);
				runs += 1;
			}
		}
		let envelope = Envelope { version: PROTOCOL_VERSION, subtype: 1, payload: seed.clone() };
		boundary::exercise(&envelope.encode().unwrap());
		runs += 1;
	}
	for size in [
		0, 1, 3, 4, 23, 24, 30, 31, 38, 39, 67, 68, 69, 252, 253, 254, 32_767, 32_768, 32_769,
		65_528, 65_529, 65_530, 65_533, 65_534, 65_535, 66_000,
	] {
		for byte in [0, 1, 0xfd, 0xfe, 0xff] {
			boundary::exercise(&vec![byte; size]);
			runs += 1;
		}
	}
	// Xorshift is only deterministic test-data generation, never cryptography.
	let mut state = 0x5a51_0321_fedc_ba98u64;
	for size in 0..4096 {
		let bytes: Vec<_> = (0..size)
			.map(|_| {
				state ^= state << 13;
				state ^= state >> 7;
				state ^= state << 17;
				state as u8
			})
			.collect();
		boundary::exercise(&bytes);
		runs += 1;
	}
	println!("Wire parser smoke passed: {runs} deterministic cases");
}
