//! Bounded Beignet receive-service requests. The native backend owns admission
//! and durable settlement. Parsing a request never creates a channel or voucher.

#![forbid(unsafe_code)]

use bitcoin::secp256k1::PublicKey;
use lightning::ln::types::ChannelId;
use serde_json::{json, Value};

const MAX_REQUEST_BYTES: usize = 60_000;
const MAX_RECEIPTS: usize = 483;

/// Terms are exposed only after the backend verifies signer, persistence and
/// negotiated concurrent-v2 support. They do not reserve capacity.
pub(crate) struct Terms {
	pub fee_base_msat: u32,
	pub fee_ppm: u32,
}

/// Only monitor-durable, settled slots may be returned by the backend.
/// Intentionally has no Debug implementation because it contains a preimage.
pub(crate) struct Receipt {
	pub slot: u16,
	pub preimage: [u8; 32],
}

pub(crate) trait Backend {
	fn terms(&self, peer: PublicKey) -> Result<Terms, &'static str>;
	fn settled_receipts(
		&self, peer: PublicKey, channel: ChannelId, epoch: [u8; 32],
	) -> Result<Vec<Receipt>, &'static str>;
}

fn lower_hex<const N: usize>(value: &Value) -> Option<[u8; N]> {
	let value = value.as_str()?;
	if value.len() != N * 2 {
		return None;
	}
	let mut out = [0; N];
	for (byte, pair) in out.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
		let digit = |n| match n {
			b'0'..=b'9' => Some(n - b'0'),
			b'a'..=b'f' => Some(n - b'a' + 10),
			_ => None,
		};
		*byte = digit(pair[0])? * 16 + digit(pair[1])?;
	}
	Some(out)
}

fn hex(bytes: &[u8]) -> String {
	const DIGITS: &[u8; 16] = b"0123456789abcdef";
	let mut result = String::with_capacity(bytes.len() * 2);
	for byte in bytes {
		result.push(DIGITS[(byte >> 4) as usize] as char);
		result.push(DIGITS[(byte & 15) as usize] as char);
	}
	result
}

fn serve(body: &Value, peer: PublicKey, backend: &impl Backend) -> Result<Value, &'static str> {
	match body.get("op").and_then(Value::as_str) {
		Some("quote") => {
			let terms = backend.terms(peer)?;
			// Match the installed phone's exact accepted fee bounds.
			if terms.fee_base_msat > 1_000_000 || terms.fee_ppm > 100_000 {
				return Err("Offline receive terms are unavailable.");
			}
			Ok(json!({"version": 1, "feeBaseMsat": terms.fee_base_msat,
				"feePpm": terms.fee_ppm, "concurrent": true,
				"concurrentVersion": 2, "canFund": false}))
		},
		Some("receipts") => {
			let channel = body
				.get("channelId")
				.and_then(lower_hex::<32>)
				.ok_or("Invalid receive reservation")?;
			let epoch = body
				.get("epochId")
				.and_then(lower_hex::<32>)
				.ok_or("Invalid receive reservation")?;
			let receipts = backend.settled_receipts(peer, ChannelId(channel), epoch)?;
			if receipts.len() > MAX_RECEIPTS {
				return Err("Receive reservation is unavailable.");
			}
			let mut seen = [false; MAX_RECEIPTS];
			for receipt in &receipts {
				if receipt.slot == 0
					|| receipt.slot as usize > MAX_RECEIPTS
					|| core::mem::replace(&mut seen[receipt.slot as usize - 1], true)
				{
					return Err("Receive reservation is unavailable.");
				}
			}
			Ok(json!({"channelId": hex(&channel), "epochId": hex(&epoch),
				"receipts": receipts.into_iter().map(|receipt|
					json!({"k": receipt.slot, "preimage": hex(&receipt.preimage)})
				).collect::<Vec<_>>()}))
		},
		Some("allocate") => Err("This node does not fund offline receive reservations."),
		_ => Err("Invalid receive request"),
	}
}

/// Respond only to a bounded, correlated request from an authenticated peer.
/// Authorization and settled-only filtering are mandatory backend obligations.
pub(crate) fn response(bytes: &[u8], peer: PublicKey, backend: &impl Backend) -> Option<Vec<u8>> {
	if bytes.len() > MAX_REQUEST_BYTES {
		return None;
	}
	let body: Value = serde_json::from_slice(bytes).ok()?;
	let id = body.as_object()?.get("id")?;
	lower_hex::<16>(id)?;
	let reply = match serve(&body, peer, backend) {
		Ok(result) => json!({"id": id, "ok": true, "result": result}),
		Err(error) => json!({"id": id, "ok": false, "error": error}),
	};
	let encoded = serde_json::to_vec(&reply).ok()?;
	(encoded.len() <= super::wire::MAX_PAYLOAD).then_some(encoded)
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::Mutex;

	struct TestBackend {
		peer: PublicKey,
		allow: bool,
		calls: Mutex<usize>,
		slots: Vec<u16>,
		fee_base_msat: u32,
		fee_ppm: u32,
	}
	impl Backend for TestBackend {
		fn terms(&self, peer: PublicKey) -> Result<Terms, &'static str> {
			*self.calls.lock().unwrap() += 1;
			if !self.allow || peer != self.peer {
				return Err("This node does not provide offline receiving.");
			}
			Ok(Terms { fee_base_msat: self.fee_base_msat, fee_ppm: self.fee_ppm })
		}
		fn settled_receipts(
			&self, peer: PublicKey, channel: ChannelId, epoch: [u8; 32],
		) -> Result<Vec<Receipt>, &'static str> {
			*self.calls.lock().unwrap() += 1;
			if peer != self.peer || channel != ChannelId([2; 32]) || epoch != [3; 32] {
				return Err("Unknown receive reservation");
			}
			// A settled slot, with an unpaid slot omitted by the backend.
			Ok(self.slots.iter().map(|slot| Receipt { slot: *slot, preimage: [4; 32] }).collect())
		}
	}
	fn backend(allow: bool) -> TestBackend {
		TestBackend {
			peer: PublicKey::from_slice(&[2; 33]).unwrap(),
			allow,
			calls: Mutex::new(0),
			slots: vec![2],
			fee_base_msat: 500,
			fee_ppm: 1000,
		}
	}
	fn call(body: Value, backend: &TestBackend) -> Value {
		serde_json::from_slice(
			&response(&serde_json::to_vec(&body).unwrap(), backend.peer, backend).unwrap(),
		)
		.unwrap()
	}

	#[test]
	fn malformed_requests_never_reach_backend() {
		let backend = backend(true);
		for bytes in [
			vec![],
			b"null".to_vec(),
			b"[]".to_vec(),
			vec![b' '; MAX_REQUEST_BYTES + 1],
			br#"{"id":"ABCDEF01234567890123456789012345","op":"quote"}"#.to_vec(),
			br#"{"id":123,"op":"quote"}"#.to_vec(),
		] {
			assert!(response(&bytes, backend.peer, &backend).is_none());
		}
		assert_eq!(*backend.calls.lock().unwrap(), 0);
	}

	#[test]
	fn quote_is_correlated_and_admission_is_backend_owned() {
		let body = json!({"id": "01".repeat(16), "op": "quote"});
		let accepted = call(body.clone(), &backend(true));
		assert_eq!(accepted["id"], body["id"]);
		assert_eq!(
			accepted["result"],
			json!({"version":1,"feeBaseMsat":500,
			"feePpm":1000,"concurrent":true,"concurrentVersion":2,"canFund":false})
		);
		assert_eq!(call(body, &backend(false))["ok"], false);
	}

	#[test]
	fn receipts_require_exact_authenticated_reservation() {
		let backend = backend(false);
		// Reading prior durable receipts remains possible when new admission is off.
		let mut body = json!({"id":"01".repeat(16),"op":"receipts",
			"channelId":"02".repeat(32),"epochId":"03".repeat(32)});
		let accepted = call(body.clone(), &backend);
		assert_eq!(accepted["result"]["receipts"], json!([{"k":2,"preimage":"04".repeat(32)}]));
		body["epochId"] = json!("05".repeat(32));
		assert_eq!(call(body, &backend)["ok"], false);
	}

	#[test]
	fn allocation_never_reaches_backend() {
		let backend = backend(true);
		assert_eq!(
			call(json!({"id":"01".repeat(16),"op":"allocate","amountSats":1000}), &backend)["ok"],
			false
		);
		assert_eq!(*backend.calls.lock().unwrap(), 0);
	}

	#[test]
	fn authenticated_identity_and_receipt_bounds_are_enforced() {
		let mut backend = backend(true);
		let body = json!({"id":"01".repeat(16),"op":"receipts",
			"channelId":"02".repeat(32),"epochId":"03".repeat(32)});
		let mut other_key = [2; 33];
		other_key[0] = 3;
		let other_peer = PublicKey::from_slice(&other_key).unwrap();
		let reply: Value = serde_json::from_slice(
			&response(&serde_json::to_vec(&body).unwrap(), other_peer, &backend).unwrap(),
		)
		.unwrap();
		assert_eq!(reply["ok"], false);
		assert!(reply.get("result").is_none());
		for slots in [vec![0], vec![484], vec![1, 1], vec![1; 484]] {
			backend.slots = slots;
			let reply = call(body.clone(), &backend);
			assert_eq!(reply["ok"], false);
			assert!(reply.get("result").is_none());
		}
		backend.slots = (1..=483).collect();
		let reply = call(body, &backend);
		assert_eq!(reply["ok"], true);
		assert_eq!(reply["result"]["receipts"].as_array().unwrap().len(), 483);
	}

	#[test]
	fn quote_rejects_terms_outside_phone_limits() {
		let mut backend = backend(true);
		let body = json!({"id":"01".repeat(16),"op":"quote"});
		backend.fee_base_msat = 1_000_000;
		backend.fee_ppm = 100_000;
		assert_eq!(call(body.clone(), &backend)["ok"], true);
		backend.fee_base_msat += 1;
		assert_eq!(call(body.clone(), &backend)["ok"], false);
		backend.fee_base_msat -= 1;
		backend.fee_ppm += 1;
		assert_eq!(call(body, &backend)["ok"], false);
	}
}
