//! Beignet v3 authenticated frames and request-bound coin ownership proofs.
//!
//! ECDH follows BOLT 8 (SHA256 of the compressed shared point). HKDF-SHA256
//! derives separate directional keys with the request ID as salt. RFC 8439
//! ChaCha20-Poly1305 authenticates `request_id || subtype` and uses a fresh
//! OS-seeded random 96-bit nonce on every transmission, including retries.
//! The node identity key signs requests and attestations; it never encrypts frames.
#![forbid(unsafe_code)]

use bitcoin::hashes::hmac::{Hmac, HmacEngine};
use bitcoin::hashes::{hash160, sha256, sha256d, Hash, HashEngine};
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::ecdh::SharedSecret;
use bitcoin::secp256k1::ecdsa::{RecoverableSignature, RecoveryId, Signature};
use bitcoin::secp256k1::{schnorr, Message, PublicKey, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{Amount, EcdsaSighashType, ScriptBuf, TapSighashType};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use rand::RngCore;
use zeroize::Zeroize;

use super::codec::{
	bitcoin_message_hash, ownership_probe_transaction, CodecError, Offer, MAX_MESSAGE_BYTES,
};

const SENDER_INFO: &[u8] = b"beignet-df:v3:sender-to-receiver";
const RECEIVER_INFO: &[u8] = b"beignet-df:v3:receiver-to-sender";
#[cfg(test)]
const ZBASE32: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// Ephemeral directional keys. Deliberately not Debug; copies are wiped on drop.
#[derive(Clone)]
pub(crate) struct LaneKeys {
	pub send_key: [u8; 32],
	pub recv_key: [u8; 32],
}
impl Drop for LaneKeys {
	fn drop(&mut self) {
		self.send_key.zeroize();
		self.recv_key.zeroize();
	}
}

pub(crate) fn random_secret() -> SecretKey {
	loop {
		let mut bytes = [0; 32];
		rand::rng().fill_bytes(&mut bytes);
		let secret = SecretKey::from_slice(&bytes);
		bytes.zeroize();
		if let Ok(secret) = secret {
			return secret;
		}
	}
}

pub(crate) fn sender_lane_keys(
	ephemeral_secret: &SecretKey, request_key: &PublicKey, request_id: &[u8; 16],
) -> LaneKeys {
	let mut shared = SharedSecret::new(request_key, ephemeral_secret).secret_bytes();
	let keys = LaneKeys {
		send_key: directional_key(&shared, request_id, SENDER_INFO),
		recv_key: directional_key(&shared, request_id, RECEIVER_INFO),
	};
	shared.zeroize();
	keys
}
pub(crate) fn receiver_lane_keys(
	request_secret: &SecretKey, ephemeral_key: &PublicKey, request_id: &[u8; 16],
) -> LaneKeys {
	let sender = sender_lane_keys(request_secret, ephemeral_key, request_id);
	LaneKeys { send_key: sender.recv_key, recv_key: sender.send_key }
}
fn directional_key(shared: &[u8; 32], request_id: &[u8; 16], info: &[u8]) -> [u8; 32] {
	let mut extract = HmacEngine::<sha256::Hash>::new(request_id);
	extract.input(shared);
	let mut prk = Hmac::<sha256::Hash>::from_engine(extract).to_byte_array();
	let mut expand = HmacEngine::<sha256::Hash>::new(&prk);
	expand.input(info);
	expand.input(&[1]);
	let key = Hmac::<sha256::Hash>::from_engine(expand).to_byte_array();
	prk.zeroize();
	key
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SealedFrame {
	pub request_id: Option<[u8; 16]>,
	pub ephemeral_public_key: Option<PublicKey>,
	pub nonce: [u8; 12],
	/// Ciphertext followed by the Poly1305 tag.
	pub ciphertext: Vec<u8>,
}
pub(crate) fn seal_frame(
	key: &[u8; 32], request_id: &[u8; 16], subtype: u16, plaintext: &[u8],
	opening: Option<PublicKey>,
) -> Result<Vec<u8>, CodecError> {
	let mut nonce = [0; 12];
	rand::rng().fill_bytes(&mut nonce);
	seal_with_nonce(key, request_id, subtype, plaintext, opening, nonce)
}
fn seal_with_nonce(
	key: &[u8; 32], request_id: &[u8; 16], subtype: u16, plaintext: &[u8],
	opening: Option<PublicKey>, nonce: [u8; 12],
) -> Result<Vec<u8>, CodecError> {
	if plaintext.len() > MAX_MESSAGE_BYTES {
		return Err(CodecError::Malformed("plaintext exceeds frame bound"));
	}
	let aad = frame_aad(request_id, subtype);
	let ciphertext = ChaCha20Poly1305::new(key.into())
		.encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad })
		.map_err(|_| CodecError::Malformed("frame encryption failed"))?;
	let mut out = Vec::with_capacity(ciphertext.len() + 62);
	if let Some(ephemeral) = opening {
		out.push(1);
		out.extend(request_id);
		out.extend(ephemeral.serialize());
	} else {
		out.push(0);
	}
	out.extend(nonce);
	out.extend(ciphertext);
	Ok(out)
}
pub(crate) fn decode_frame(data: &[u8]) -> Option<SealedFrame> {
	if data.len() > MAX_MESSAGE_BYTES + 78 {
		return None;
	}
	let (offset, request_id, ephemeral_public_key) = match *data.first()? {
		0 => (1, None, None),
		1 => (
			50,
			Some(data.get(1..17)?.try_into().ok()?),
			Some(PublicKey::from_slice(data.get(17..50)?).ok()?),
		),
		_ => return None,
	};
	let nonce = data.get(offset..offset + 12)?.try_into().ok()?;
	let ciphertext = data.get(offset + 12..)?;
	if ciphertext.len() < 16 {
		return None;
	}
	Some(SealedFrame { request_id, ephemeral_public_key, nonce, ciphertext: ciphertext.to_vec() })
}
pub(crate) fn open_frame(
	key: &[u8; 32], request_id: &[u8; 16], subtype: u16, frame: &SealedFrame,
) -> Option<Vec<u8>> {
	if frame.request_id.is_some_and(|id| id != *request_id)
		|| frame.ciphertext.len() > MAX_MESSAGE_BYTES + 16
	{
		return None;
	}
	let aad = frame_aad(request_id, subtype);
	ChaCha20Poly1305::new(key.into())
		.decrypt(Nonce::from_slice(&frame.nonce), Payload { msg: &frame.ciphertext, aad: &aad })
		.ok()
}
fn frame_aad(request_id: &[u8; 16], subtype: u16) -> [u8; 18] {
	let mut aad = [0; 18];
	aad[..16].copy_from_slice(request_id);
	aad[16..].copy_from_slice(&subtype.to_be_bytes());
	aad
}

/// Compact LND-compatible node signature (`31 + recovery_id || r || s`).
pub(crate) fn sign_message(message: &str, secret: &SecretKey) -> [u8; 65] {
	let secp = Secp256k1::signing_only();
	let sig =
		secp.sign_ecdsa_recoverable(&Message::from_digest(lightning_message_hash(message)), secret);
	let (id, bytes) = sig.serialize_compact();
	let mut compact = [0; 65];
	compact[0] = 31 + id.to_i32() as u8;
	compact[1..].copy_from_slice(&bytes);
	compact
}
pub(crate) fn verify_message(message: &str, signature: &[u8; 65], expected: &PublicKey) -> bool {
	recover_message_key(message, signature).is_some_and(|key| key == *expected)
}
pub(crate) fn recover_message_key(message: &str, signature: &[u8; 65]) -> Option<PublicKey> {
	if !(27..=34).contains(&signature[0]) {
		return None;
	}
	let id = RecoveryId::from_i32(((signature[0] - 27) & 3) as i32).ok()?;
	let sig = RecoverableSignature::from_compact(&signature[1..], id).ok()?;
	Secp256k1::verification_only()
		.recover_ecdsa(&Message::from_digest(lightning_message_hash(message)), &sig)
		.ok()
}
fn lightning_message_hash(message: &str) -> [u8; 32] {
	let mut bytes = b"Lightning Signed Message:".to_vec();
	bytes.extend(message.as_bytes());
	sha256d::Hash::hash(&bytes).to_byte_array()
}
#[cfg(test)]
pub(crate) fn compact_from_zbase32(text: &str) -> Result<[u8; 65], CodecError> {
	if text.len() != 104 {
		return Err(CodecError::InvalidSignature);
	}
	let mut output = Vec::with_capacity(65);
	let mut accumulator = 0u16;
	let mut bits = 0;
	for ch in text.bytes() {
		let value =
			ZBASE32.iter().position(|c| *c == ch).ok_or(CodecError::InvalidSignature)? as u16;
		accumulator = (accumulator << 5) | value;
		bits += 5;
		if bits >= 8 {
			bits -= 8;
			output.push((accumulator >> bits) as u8);
			accumulator &= (1 << bits) - 1;
		}
	}
	if accumulator != 0 {
		return Err(CodecError::InvalidSignature);
	}
	output.try_into().map_err(|_| CodecError::InvalidSignature)
}

/// Verify the coin-control proof against a chain-verified output script and the receiver
/// identity from the signed request. Callers must separately verify amount and unspent status.
pub(crate) fn verify_ownership(offer: &Offer, coin_script: &[u8], receiver: &PublicKey) -> bool {
	let p2wpkh = coin_script.len() == 22 && coin_script[..2] == [0, 20];
	let p2tr = coin_script.len() == 34 && coin_script[..2] == [0x51, 32];
	if !p2wpkh && !p2tr {
		return false;
	}
	if let Some(proof) = &offer.ownership.message_proof {
		let key = match PublicKey::from_slice(&proof.pubkey) {
			Ok(k) => k,
			Err(_) => return false,
		};
		if p2wpkh {
			if hash160::Hash::hash(&key.serialize()).as_byte_array() != &coin_script[2..] {
				return false;
			}
		} else {
			let (internal, _) = key.x_only_public_key();
			let (tweaked, _) = internal.tap_tweak(&Secp256k1::verification_only(), None);
			if tweaked.to_x_only_public_key().serialize() != coin_script[2..] {
				return false;
			}
		}
		let mut signature = [0; 64];
		signature.copy_from_slice(&proof.signature[1..]);
		return verify_ecdsa(
			&bitcoin_message_hash(&offer.ownership_message(receiver)),
			&signature,
			&key,
		);
	}
	if let Some(proof) = &offer.ownership.probe_proof {
		let (tx, prevouts) = ownership_probe_transaction(offer, coin_script, receiver);
		let mut cache = SighashCache::new(&tx);
		if p2tr {
			let hash = match cache.taproot_key_spend_signature_hash(
				0,
				&Prevouts::All(&prevouts),
				TapSighashType::Default,
			) {
				Ok(h) => h.to_byte_array(),
				Err(_) => return false,
			};
			return verify_schnorr(&hash, &proof.signature, &coin_script[2..]);
		}
		let key = match PublicKey::from_slice(&proof.pubkey) {
			Ok(k) => k,
			Err(_) => return false,
		};
		if hash160::Hash::hash(&key.serialize()).as_byte_array() != &coin_script[2..] {
			return false;
		}
		let hash = match cache.p2wpkh_signature_hash(
			0,
			&ScriptBuf::from_bytes(coin_script.to_vec()),
			Amount::from_sat(offer.value_sat),
			EcdsaSighashType::All,
		) {
			Ok(h) => h.to_byte_array(),
			Err(_) => return false,
		};
		return verify_ecdsa(&hash, &proof.signature, &key);
	}
	let digest = offer.ownership_digest(receiver);
	if p2tr {
		return verify_schnorr(&digest, &offer.ownership.signature, &coin_script[2..]);
	}
	if offer.ownership.pubkey.len() != 33 {
		return false;
	}
	let key = match PublicKey::from_slice(&offer.ownership.pubkey) {
		Ok(k) => k,
		Err(_) => return false,
	};
	hash160::Hash::hash(&key.serialize()).as_byte_array() == &coin_script[2..]
		&& verify_ecdsa(&digest, &offer.ownership.signature, &key)
}
fn verify_ecdsa(digest: &[u8; 32], signature: &[u8; 64], key: &PublicKey) -> bool {
	let mut signature = match Signature::from_compact(signature) {
		Ok(s) => s,
		Err(_) => return false,
	};
	signature.normalize_s();
	Secp256k1::verification_only()
		.verify_ecdsa(&Message::from_digest(*digest), &signature, key)
		.is_ok()
}
fn verify_schnorr(digest: &[u8; 32], signature: &[u8; 64], key: &[u8]) -> bool {
	let signature = match schnorr::Signature::from_slice(signature) {
		Ok(s) => s,
		Err(_) => return false,
	};
	let key = match XOnlyPublicKey::from_slice(key) {
		Ok(k) => k,
		Err(_) => return false,
	};
	Secp256k1::verification_only()
		.verify_schnorr(&signature, &Message::from_digest(*digest), &key)
		.is_ok()
}

#[cfg(test)]
mod tests {
	use super::super::codec::{
		hex,
		tests::{fixture, unhex},
		MessageProof, OwnershipProof, ProbeProof,
	};
	use super::*;
	use bitcoin::secp256k1::Keypair;

	fn secret(byte: u8) -> SecretKey {
		SecretKey::from_slice(&[byte; 32]).unwrap()
	}
	fn pk(byte: u8) -> PublicKey {
		PublicKey::from_secret_key(&Secp256k1::new(), &secret(byte))
	}
	fn request_id() -> [u8; 16] {
		[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
	}

	#[test]
	fn beignet_hkdf_and_chachapoly_vector() {
		let id = request_id();
		let sender = sender_lane_keys(&secret(9), &pk(0x33), &id);
		let receiver = receiver_lane_keys(&secret(0x33), &pk(9), &id);
		assert_eq!(hex(&sender.send_key), fixture("sendKey"));
		assert_eq!(hex(&sender.recv_key), fixture("recvKey"));
		assert_eq!(sender.send_key, receiver.recv_key);
		assert_eq!(sender.recv_key, receiver.send_key);
		assert_ne!(sender.send_key, sender.recv_key);
		let nonce = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
		let wire =
			seal_with_nonce(&sender.send_key, &id, 16, b"offer body", Some(pk(9)), nonce).unwrap();
		assert_eq!(hex(&wire), fixture("frame"));
		let frame = decode_frame(&wire).unwrap();
		assert_eq!(frame.request_id, Some(id));
		assert_eq!(frame.ephemeral_public_key, Some(pk(9)));
		assert_eq!(open_frame(&receiver.recv_key, &id, 16, &frame), Some(b"offer body".to_vec()));
	}
	#[test]
	fn frames_bind_direction_request_subtype_and_every_ciphertext_byte() {
		let id = request_id();
		let sender = sender_lane_keys(&secret(9), &pk(0x33), &id);
		let wire = seal_frame(&sender.send_key, &id, 16, b"offer body", Some(pk(9))).unwrap();
		let frame = decode_frame(&wire).unwrap();
		assert!(open_frame(&sender.recv_key, &id, 16, &frame).is_none());
		assert!(open_frame(&sender.send_key, &id, 21, &frame).is_none());
		assert!(open_frame(&sender.send_key, &[0; 16], 16, &frame).is_none());
		for i in 0..frame.ciphertext.len() {
			let mut changed = frame.clone();
			changed.ciphertext[i] ^= 1;
			assert!(open_frame(&sender.send_key, &id, 16, &changed).is_none());
		}
		for n in 0..wire.len() {
			if let Some(short) = decode_frame(&wire[..n]) {
				assert!(open_frame(&sender.send_key, &id, 16, &short).is_none());
			}
		}
		let next = seal_frame(&sender.send_key, &id, 16, b"offer body", Some(pk(9))).unwrap();
		assert_ne!(wire, next);
		let continuation = seal_frame(&sender.send_key, &id, 19, b"witness", None).unwrap();
		let frame = decode_frame(&continuation).unwrap();
		assert_eq!(frame.request_id, None);
		assert_eq!(open_frame(&sender.send_key, &id, 19, &frame), Some(b"witness".to_vec()));
		assert!(decode_frame(&vec![0; MAX_MESSAGE_BYTES + 79]).is_none());
		assert!(
			seal_frame(&sender.send_key, &id, 16, &vec![0; MAX_MESSAGE_BYTES + 1], None).is_err()
		);
	}
	#[test]
	fn lightning_signatures_bind_message_and_expected_signer() {
		let message = "direct funding request";
		let signature = sign_message(message, &secret(0x11));
		assert!(verify_message(message, &signature, &pk(0x11)));
		assert!(!verify_message("other", &signature, &pk(0x11)));
		assert!(!verify_message(message, &signature, &pk(0x22)));
		let mut invalid = signature;
		invalid[0] = 255;
		assert!(!verify_message(message, &invalid, &pk(0x11)));
		assert!(compact_from_zbase32("invalid").is_err());
	}
	fn p2wpkh_offer() -> (Offer, Vec<u8>) {
		let mut offer = Offer::decode(&unhex(&fixture("offer"))).unwrap();
		let mut script = vec![0, 20];
		script.extend(hash160::Hash::hash(&pk(0x21).serialize()).to_byte_array());
		offer.ownership = OwnershipProof {
			pubkey: pk(0x21).serialize().to_vec(),
			signature: [0; 64],
			message_proof: None,
			probe_proof: None,
		};
		(offer, script)
	}
	#[test]
	fn p2wpkh_all_ownership_forms_bind_receiver_receipt_and_coin() {
		let secp = Secp256k1::new();
		let receiver = pk(0x51);
		let (base, script) = p2wpkh_offer();
		for mode in 0..3 {
			let mut offer = base.clone();
			match mode {
				0 => {
					offer.ownership.signature = secp
						.sign_ecdsa(
							&Message::from_digest(offer.ownership_digest(&receiver)),
							&secret(0x21),
						)
						.serialize_compact()
				},
				1 => {
					let hash = bitcoin_message_hash(&offer.ownership_message(&receiver));
					let (id, sig) = secp
						.sign_ecdsa_recoverable(&Message::from_digest(hash), &secret(0x21))
						.serialize_compact();
					let mut compact = [0; 65];
					compact[0] = 31 + id.to_i32() as u8;
					compact[1..].copy_from_slice(&sig);
					offer.ownership.message_proof =
						Some(MessageProof { pubkey: pk(0x21).serialize(), signature: compact });
				},
				_ => {
					let (tx, _) = ownership_probe_transaction(&offer, &script, &receiver);
					let hash = SighashCache::new(&tx)
						.p2wpkh_signature_hash(
							0,
							&ScriptBuf::from_bytes(script.clone()),
							Amount::from_sat(offer.value_sat),
							EcdsaSighashType::All,
						)
						.unwrap();
					offer.ownership.probe_proof = Some(ProbeProof {
						pubkey: pk(0x21).serialize(),
						signature: secp
							.sign_ecdsa(&Message::from_digest(hash.to_byte_array()), &secret(0x21))
							.serialize_compact(),
					});
				},
			}
			assert!(verify_ownership(&offer, &script, &receiver));
			assert!(!verify_ownership(&offer, &script, &pk(0x52)));
			let mut changed = offer.clone();
			changed.receipt_hash[0] ^= 1;
			assert!(!verify_ownership(&changed, &script, &receiver));
			let mut other = script.clone();
			other[2] ^= 1;
			assert!(!verify_ownership(&offer, &other, &receiver));
		}
	}
	#[test]
	fn taproot_all_ownership_forms_and_internal_key_tweak() {
		let secp = Secp256k1::new();
		let receiver = pk(0x51);
		let (base, _) = p2wpkh_offer();
		let keypair = Keypair::from_secret_key(&secp, &secret(0x21));
		let tweaked = keypair.tap_tweak(&secp, None);
		let (output, _) = tweaked.public_parts();
		let mut script = vec![0x51, 32];
		script.extend(output.serialize());
		let signing = tweaked.to_keypair();
		for mode in 0..3 {
			let mut offer = base.clone();
			offer.ownership.pubkey = output.serialize().to_vec();
			match mode {
				0 => {
					offer.ownership.signature = secp
						.sign_schnorr_no_aux_rand(
							&Message::from_digest(offer.ownership_digest(&receiver)),
							&signing,
						)
						.serialize()
				},
				1 => {
					let hash = bitcoin_message_hash(&offer.ownership_message(&receiver));
					let (id, sig) = secp
						.sign_ecdsa_recoverable(&Message::from_digest(hash), &secret(0x21))
						.serialize_compact();
					let mut compact = [0; 65];
					compact[0] = 31 + id.to_i32() as u8;
					compact[1..].copy_from_slice(&sig);
					offer.ownership.message_proof =
						Some(MessageProof { pubkey: pk(0x21).serialize(), signature: compact });
				},
				_ => {
					let (tx, prevouts) = ownership_probe_transaction(&offer, &script, &receiver);
					let hash = SighashCache::new(&tx)
						.taproot_key_spend_signature_hash(
							0,
							&Prevouts::All(&prevouts),
							TapSighashType::Default,
						)
						.unwrap();
					offer.ownership.probe_proof = Some(ProbeProof {
						pubkey: [0; 33],
						signature: secp
							.sign_schnorr_no_aux_rand(
								&Message::from_digest(hash.to_byte_array()),
								&signing,
							)
							.serialize(),
					});
				},
			}
			assert!(verify_ownership(&offer, &script, &receiver));
			assert!(!verify_ownership(&offer, &script, &pk(0x52)));
			let mut changed = offer.clone();
			changed.receipt_hash[0] ^= 1;
			assert!(!verify_ownership(&changed, &script, &receiver));
		}
	}
}
