// Copyright (c) 2023 Synonym. MIT license, see LICENSE-BEIGNET.
// Exact vectors copied from Beignet revision fc4b253fde5d3add31c4f0e208e16794bb32e324:
// tests/lightning/ffor-variant-d-vectors.test.ts and
// tests/lightning/fixtures/ffor/concurrent-receive-wire.json.

use super::*;
use crate::ln::ffor_monitor::{CommitmentSnapshot, FforJournal, VoucherOutput};
use crate::sign::{KeysManager, NodeSigner, Recipient};
use bitcoin::secp256k1::SecretKey;

const INIT: &[u8] = include_bytes!("fixtures/d1-init.bin");
const ACCEPT: &[u8] = include_bytes!("fixtures/d1-accept.bin");
const ACTIVATE: &[u8] = include_bytes!("fixtures/d1-activate.bin");
const ACK: &[u8] = include_bytes!("fixtures/d1-ack.bin");
const BOOK: &[u8] = include_bytes!("fixtures/d1-book.bin");
const SYNC: &[u8] = include_bytes!("fixtures/sync-request.bin");

// Model an existing external signer implementation that forwards every older
// required operation but has not opted into the new protocol hooks.
struct DefaultFforSigner {
	inner: Box<KeysManager>,
}
delegate!(DefaultFforSigner, NodeSigner, inner,
	fn get_node_id(, recipient: Recipient) -> Result<PublicKey, ()>,
	fn sign_gossip_message(, msg: crate::ln::msgs::UnsignedGossipMessage) -> Result<Signature, ()>,
	fn sign_message(, msg: &[u8]) -> Result<String, ()>,
	fn ecdh(, recipient: Recipient, other_key: &PublicKey, tweak: Option<&bitcoin::secp256k1::Scalar>) -> Result<bitcoin::secp256k1::ecdh::SharedSecret, ()>,
	fn sign_invoice(, invoice: &lightning_invoice::RawBolt11Invoice, recipient: Recipient) -> Result<bitcoin::secp256k1::ecdsa::RecoverableSignature, ()>,
	fn sign_bolt12_invoice(, invoice: &crate::offers::invoice::UnsignedBolt12Invoice) -> Result<bitcoin::secp256k1::schnorr::Signature, ()>,
	fn get_expanded_key(,) -> crate::ln::inbound_payment::ExpandedKey,
	fn get_peer_storage_key(,) -> crate::sign::PeerStorageKey,
	fn get_receive_auth_key(,) -> crate::sign::ReceiveAuthKey
);

fn hex(s: &str) -> Vec<u8> {
	s.as_bytes()
		.chunks(2)
		.map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
		.collect()
}
fn expected(s: &str) -> [u8; 32] {
	hex(s).try_into().unwrap()
}
fn key(side: &[u8]) -> SecretKey {
	SecretKey::from_slice(&digest(&[b"ffor/", side, b"/node-key"])).unwrap()
}
fn node(side: &[u8]) -> PublicKey {
	PublicKey::from_secret_key(&Secp256k1::new(), &key(side))
}
fn signed(kind: Kind, bytes: &[u8], side: &[u8]) -> SignedMessage {
	sign_with(kind, bytes, &key(side))
}

pub(crate) fn sign_with(kind: Kind, bytes: &[u8], key: &SecretKey) -> SignedMessage {
	let secp = Secp256k1::new();
	let sig = secp.sign_ecdsa(&Message::from_digest(message_digest(kind, bytes)), key);
	SignedMessage::from_parts(kind, bytes, sig.serialize_compact()).unwrap()
}

/// A real signed concurrent-v2 request for native channel lifecycle tests.
pub(crate) fn init_for(
	channel_id: [u8; 32], epoch_id: [u8; 32], receiver: &SecretKey, height: u32, amounts: &[u64],
	fee_base_msat: u32, fee_ppm: u32,
) -> SignedMessage {
	assert!(!amounts.is_empty() && amounts.len() <= MAX_SLOTS);
	let mut bytes = channel_id.to_vec();
	bytes.extend_from_slice(&epoch_id);
	bytes.push(4);
	bytes.extend_from_slice(&amounts.iter().copied().sum::<u64>().to_be_bytes());
	bytes.extend_from_slice(&(amounts.len() as u16).to_be_bytes());
	bytes.extend_from_slice(&amounts.iter().copied().min().unwrap().to_be_bytes());
	bytes.extend_from_slice(&(height + 144).to_be_bytes());
	bytes.extend_from_slice(&(height + 1296).to_be_bytes());
	bytes.extend_from_slice(&fee_base_msat.to_be_bytes());
	bytes.extend_from_slice(&fee_ppm.to_be_bytes());
	bytes.extend_from_slice(&0u64.to_be_bytes());
	bytes.extend_from_slice(&0u16.to_be_bytes());
	bytes.push(9);
	let len = amounts.len() * 8;
	if len <= 0xfc {
		bytes.push(len as u8);
	} else {
		bytes.push(0xfd);
		bytes.extend_from_slice(&(len as u16).to_be_bytes());
	}
	for amount in amounts {
		bytes.extend_from_slice(&amount.to_be_bytes());
	}
	bytes.extend_from_slice(&[17, 2, 0, 2]);
	sign_with(Kind::Init, &bytes, receiver)
}

#[test]
fn exact_appendix_d_signatures_and_transcripts() {
	let secp = Secp256k1::verification_only();
	for (wire, side) in [(INIT, b"R"), (ACCEPT, b"S"), (ACTIVATE, b"R"), (ACK, b"S")] {
		let msg = SignedMessage::decode(wire).unwrap();
		assert_eq!(msg.encode(), wire);
		assert_eq!(msg.verify(&secp, &node(side)), Ok(()));
		assert_eq!(signed(msg.kind, msg.unsigned(), side).encode(), wire);
		assert!(msg.verify(&secp, &node(if side == b"R" { b"S" } else { b"R" })).is_err());
	}
	let init = init_hash(INIT);
	assert_eq!(init, expected("343331edc28e500ea03cbce26983583e66fff33dc9f096a3d6924b8239f68eb8"));
	let setup = setup_hash(&init, ACCEPT);
	assert_eq!(setup, expected("ba34be8afe89e4457543a6e7279f86054f1d6e9038234b786b740e9c905c001f"));
	let (epoch, entries) = decode_book(BOOK).unwrap();
	assert_eq!(encode_book(&epoch, &entries).unwrap(), BOOK);
	let book = book_hash(BOOK);
	assert_eq!(book, expected("8ae276dd460c7b2030287a608677bc51eb9cdef5b7cfc1f73d005e463076510a"));
	let commit = commitment_hash(
		43,
		&expected("c56247558caf290d78e2fe7d948d9605320c012b20fa181db87fc847ce69159b"),
		43,
		&expected("d23aaf74371cdda6cbaf75b7390fdd75b3247dfe90c98d2e19e9802783c349b9"),
	);
	assert_eq!(
		commit,
		expected("723024696ad20b4758b228284620d18fd30750b7051cc64efca23a1417cf1321")
	);
	assert_eq!(
		activation_hash(&setup, &book, &commit, 790000),
		expected("580a4a958e8131b32452741e51d724e0f231cb518896c743fa59de236ac6e716")
	);
	assert_eq!(
		voucher_secret(&epoch, 1).unwrap(),
		expected("8b85975abbc66f6c888e98520b2483c9dd7db4a6bde4365784e31a99f741bf26")
	);
}

#[test]
fn exact_concurrent_sync_vectors_including_maximum_book() {
	for (wire, size, expected_digest) in [
		(SYNC, 194, "f160011cd29bf75eb79ae8377d9f4e900f557569c21843b26162eabcc14a7a39"),
		(
			include_bytes!("fixtures/sync-reply-1.bin").as_slice(),
			241,
			"472908a61410240a29e41342063616f3dfdecd77a3bfaa105adda04a718d226e",
		),
		(
			include_bytes!("fixtures/sync-reply-9.bin").as_slice(),
			514,
			"cbd8c1222796c8c7bd9d8e5cf358a44817fd960a047593579d6dfc398cf46b88",
		),
		(
			include_bytes!("fixtures/sync-reply-483.bin").as_slice(),
			16689,
			"cb6b6609385b29bfd29a3ea804dc7a6d7248fc52a0055e9bace83a2b83c7e658",
		),
	] {
		assert_eq!(wire.len(), size);
		let message = SignedMessage::decode(wire).unwrap();
		assert_eq!(message.encode(), wire);
		assert_eq!(message_digest(message.kind, message.unsigned()), expected(expected_digest));
	}
}

#[test]
fn canonical_extensions_preserve_signed_bytes() {
	let base = SignedMessage::decode(SYNC).unwrap();
	let mut odd = base.unsigned().to_vec();
	odd.extend_from_slice(&[1, 1, 0x99]);
	let parsed = signed(Kind::Sync, &odd, b"R");
	assert_eq!(parsed.tlv(1), Some([0x99].as_slice()));
	assert_eq!(SignedMessage::decode(&parsed.encode()).unwrap(), parsed);
	assert!(parsed.verify(&Secp256k1::verification_only(), &node(b"R")).is_ok());
	for bad in
		[&[2, 0][..], &[1, 0, 1, 0], &[3, 0, 1, 0], &[0xfd, 0, 1, 0], &[1, 0xfd, 0, 0], &[1, 2, 0]]
	{
		let mut data = base.unsigned().to_vec();
		data.extend_from_slice(bad);
		assert!(SignedMessage::from_parts(Kind::Sync, &data, [0; 64]).is_err());
	}
	let mut too_many = base.unsigned().to_vec();
	for i in 0..=MAX_TLVS {
		too_many.extend_from_slice(&[(i * 2 + 1) as u8, 0]);
	}
	assert!(SignedMessage::from_parts(Kind::Sync, &too_many, [0; 64]).is_err());
	assert!(SignedMessage::decode(&vec![0; MAX_BODY + 3]).is_err());
}

#[test]
fn signatures_reject_tampering_truncation_and_high_s() {
	let secp = Secp256k1::verification_only();
	let peer = node(b"R");
	for n in 0..INIT.len() {
		assert!(SignedMessage::decode(&INIT[..n]).and_then(|m| m.verify(&secp, &peer)).is_err());
	}
	for i in 0..INIT.len() {
		let mut wire = INIT.to_vec();
		wire[i] ^= 1;
		assert!(SignedMessage::decode(&wire).and_then(|m| m.verify(&secp, &peer)).is_err());
	}
	let mut wire = INIT.to_vec();
	let order = hex("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
	let len = wire.len();
	let mut borrow = 0i16;
	for i in (0..32).rev() {
		let value = order[i] as i16 - wire[len - 32 + i] as i16 - borrow;
		wire[len - 32 + i] = value as u8;
		borrow = if value < 0 { 1 } else { 0 };
	}
	assert_eq!(SignedMessage::decode(&wire).unwrap().verify(&secp, &peer), Err(Error::Signature));
}

#[test]
fn receipt_bitmap_and_list_are_exact_and_bounded() {
	let original = include_bytes!("fixtures/sync-reply-9.bin");
	let mut wire = original.to_vec();
	wire[2 + 139] |= 0x80;
	assert!(SignedMessage::decode(&wire).is_err());
	let mut wire = original.to_vec();
	wire[2 + 136..2 + 138].copy_from_slice(&484u16.to_be_bytes());
	assert!(SignedMessage::decode(&wire).is_err());
	let mut wire = original.to_vec();
	wire[2 + 128..2 + 136].fill(0);
	assert!(SignedMessage::decode(&wire).is_err());
	let mut wire = original.to_vec();
	wire[2 + 142..2 + 144].copy_from_slice(&2u16.to_be_bytes());
	assert!(SignedMessage::decode(&wire).is_err());
	let mut wire = original.to_vec();
	wire[2 + 140..2 + 142].copy_from_slice(&8u16.to_be_bytes());
	assert!(SignedMessage::decode(&wire).is_err());
}

pub(crate) fn epoch() -> SettlerEpoch {
	let (epoch_id, entries) = decode_book(BOOK).unwrap();
	let mut init = SignedMessage::decode(INIT).unwrap().unsigned().to_vec();
	init.extend_from_slice(&[17, 2, 0, 2]);
	let init = signed(Kind::Init, &init, b"R");
	SettlerEpoch {
		channel_id: init.channel_id,
		epoch_id,
		local_node: node(b"S"),
		remote_node: node(b"R"),
		phase: Phase::Negotiating,
		capability_hold: false,
		activation_mismatch: false,
		activation_ack_pending: false,
		abort_reason: None,
		abort: None,
		messages: vec![init],
		slots: vec![Slot {
			entry: entries[0].clone(),
			preimage: expected("8ae4a313bd01bcfcce12b797ed20603ed56b0f0b9194e7c000e5cbd6fe376517"),
			state: SlotState::Unused,
			upstream: None,
			redeemed: false,
			removal: None,
			chain_removal: None,
		}],
	}
}

#[test]
fn settler_record_is_versioned_bounded_and_validated_on_reload() {
	let record = epoch();
	let bytes = record.encode().unwrap();
	assert!(SettlerEpoch::decode(&bytes).unwrap() == record);
	for n in 0..bytes.len() {
		assert!(SettlerEpoch::decode(&bytes[..n]).is_err());
	}
	let mut trailing = bytes.clone();
	trailing.push(0);
	assert!(SettlerEpoch::decode(&trailing).is_err());
	let mut unknown = bytes.clone();
	unknown[4] = 255;
	assert!(SettlerEpoch::decode(&unknown).is_err());
	let mut bad = record.clone();
	bad.slots[0].preimage[0] ^= 1;
	assert!(bad.encode().is_err());
	let mut bad = record.clone();
	bad.slots[0].state = SlotState::Settling;
	assert!(bad.encode().is_err());
	let mut bad = record.clone();
	bad.phase = Phase::Active;
	assert!(bad.encode().is_err());
	let mut bad = record.clone();
	bad.messages[0] = SignedMessage::decode(INIT).unwrap();
	assert!(bad.encode().is_err());
	let mut bad = record.clone();
	bad.channel_id[0] ^= 1;
	assert!(bad.encode().is_err());
	assert!(SettlerEpoch::decode(&vec![0; 512 * 1024 + 1]).is_err());
}

#[test]
fn archive_never_reuses_epoch_or_hash_and_refuses_capacity() {
	let mut archive = UsedArchive::default();
	archive.reserve([1; 32], [2; 32], &[[3; 32], [4; 32]]).unwrap();
	assert_eq!(UsedArchive::decode(&archive.encode()).unwrap(), archive);
	assert!(archive.reserve([1; 32], [2; 32], &[[5; 32]]).is_err());
	assert!(archive.reserve([8; 32], [9; 32], &[[3; 32]]).is_err());
	assert!(archive.reserve([8; 32], [9; 32], &[[5; 32], [5; 32]]).is_err());
	let before = archive.clone();
	assert!(archive.reserve([1; 32], [2; 32], &[[7; 32]]).is_err());
	assert_eq!(archive, before);
	let mut duplicate = archive.encode();
	let last = duplicate.len() - 34;
	duplicate[last..last + 32].fill(3);
	assert!(UsedArchive::decode(&duplicate).is_err());
	let mut archive = UsedArchive::default();
	for i in 0..4096u32 {
		let hash = digest(&[&i.to_be_bytes()]);
		archive.reserve([1; 32], hash, &[hash]).unwrap();
	}
	assert_eq!(archive.reserve([2; 32], [9; 32], &[[8; 32]]), Err(Error::Limit));
}

#[test]
fn refused_epoch_ids_survive_restart_without_voucher_hashes() {
	let mut archive = UsedArchive::default();
	archive.burn_epoch([1; 32], [2; 32]).unwrap();
	let mut loaded = UsedArchive::decode(&archive.encode()).unwrap();
	assert_eq!(loaded, archive);
	assert!(loaded.burn_epoch([1; 32], [2; 32]).is_err());
	assert!(loaded.reserve([1; 32], [2; 32], &[[3; 32]]).is_err());
	loaded.reserve([4; 32], [2; 32], &[[3; 32]]).unwrap();
	assert!(UsedArchive::decode(&loaded.encode()).unwrap() == loaded);
}

#[test]
fn typed_terms_and_reestablish_are_strict() {
	let value = epoch();
	let terms = value.messages[0].settler_terms().unwrap();
	assert_eq!(terms.amounts_msat, vec![1_000_000]);
	assert_eq!(terms.budget_msat, 1_000_000);
	assert_eq!(terms.expiry, 800000);
	assert_eq!(terms.deadline, 798992);
	assert!(SignedMessage::decode(INIT).unwrap().settler_terms().is_err());
	let base = value.messages[0].unsigned();
	for (offset, replacement) in [(65, [0u8; 8]), (75, [0u8; 8])] {
		let mut bytes = base.to_vec();
		bytes[offset..offset + 8].copy_from_slice(&replacement);
		assert!(signed(Kind::Init, &bytes, b"R").settler_terms().is_err());
	}
	let mut bytes = base.to_vec();
	bytes[87..91].copy_from_slice(&799000u32.to_be_bytes());
	assert!(signed(Kind::Init, &bytes, b"R").settler_terms().is_err());
	for state in 0..=6 {
		let r = Reestablish { epoch_id: [2; 32], state, last_seq: 9, activation_hash: [3; 32] };
		let encoded = r.encode().unwrap();
		assert_eq!(Reestablish::decode(&encoded).unwrap(), r);
		for n in 0..67 {
			assert!(Reestablish::decode(&encoded[..n]).is_err());
		}
	}
	let mut bad = [0; 67];
	bad[32] = 7;
	assert!(Reestablish::decode(&bad).is_err());
}

pub(crate) fn active_epoch() -> SettlerEpoch {
	let mut record = epoch();
	let init = init_hash(&record.messages[0].encode());
	let mut accept = SignedMessage::decode(ACCEPT).unwrap().unsigned().to_vec();
	let end = accept.len();
	accept[end - 32..].copy_from_slice(&init);
	accept.extend_from_slice(&[17, 2, 0, 2]);
	let accept = signed(Kind::Accept, &accept, b"S");
	let setup = setup_hash(&init, &accept.encode());
	let mut act = SignedMessage::decode(ACTIVATE).unwrap().unsigned().to_vec();
	act[64..96].copy_from_slice(&setup);
	let act = signed(Kind::Activate, &act, b"R");
	let h_act = activation_hash(
		&setup,
		&book_hash(BOOK),
		&act.unsigned()[128..160].try_into().unwrap(),
		790000,
	);
	let mut ack = SignedMessage::decode(ACK).unwrap().unsigned().to_vec();
	ack[64..96].copy_from_slice(&h_act);
	let ack = signed(Kind::ActivateAck, &ack, b"S");
	record.messages.extend([accept, act, ack]);
	record.phase = Phase::Active;
	record
}

#[test]
fn custody_records_do_not_publish_unused_preimages_or_forget_reserved_claims() {
	let mut record = active_epoch();
	assert!(SettlerEpoch::decode(&record.encode().unwrap()).unwrap() == record);
	let mut reply = record.channel_id.to_vec();
	reply.extend_from_slice(&record.epoch_id);
	reply.extend_from_slice(&record.messages[3].unsigned()[64..96]);
	reply.extend_from_slice(&[4; 32]);
	reply.extend_from_slice(&1u64.to_be_bytes());
	reply.extend_from_slice(&[0, 1, 1, 0, 1, 0, 1]);
	reply.extend_from_slice(&record.slots[0].preimage);
	record.messages.push(signed(Kind::SyncReply, &reply, b"S"));
	assert!(record.encode().is_err(), "Unused preimages must not appear in a saved receipt");
	record.slots[0].state = SlotState::Settling;
	record.slots[0].upstream = Some(upstream());
	assert!(record.encode().is_err(), "Live sync cannot publish an incomplete upstream claim");
	record.slots[0].state = SlotState::Settled;
	assert!(SettlerEpoch::decode(&record.encode().unwrap()).unwrap() == record);
	let mut wrong = record.clone();
	let last = reply.len();
	reply[last - 1] ^= 1;
	wrong.messages.pop();
	wrong.messages.push(signed(Kind::SyncReply, &reply, b"S"));
	assert!(wrong.encode().is_err());
	record.phase = Phase::Draining;
	let ack = record.messages.iter().find(|m| m.kind == Kind::ActivateAck).unwrap();
	let close = signed(Kind::Close, ack.unsigned(), b"R");
	let mut close_ack = ack.unsigned().to_vec();
	close_ack.extend_from_slice(&[0, 1, 1, 1, 34, 0, 1]);
	close_ack.extend_from_slice(&record.slots[0].preimage);
	record.messages.extend([close, signed(Kind::CloseAck, &close_ack, b"S")]);
	assert!(record.encode().is_ok());
	record.phase = Phase::Closed;
	assert!(
		record.encode().is_err(),
		"Reserved vouchers remain custody until removal evidence exists"
	);
	record.slots[0].redeemed = true;
	record.slots[0].removal =
		Some(Removal { fulfilled: true, local_commitment: 44, remote_commitment: 44 });
	assert!(record.encode().is_ok());
	let mut record = epoch();
	record.slots[0].state = SlotState::Settling;
	record.slots[0].upstream = Some(upstream());
	assert!(record.encode().is_err(), "Setup cannot own a delegated settlement");
}

fn upstream() -> Upstream {
	Upstream {
		counterparty_node_id: node(b"upstream"),
		funding_txo: crate::chain::transaction::OutPoint {
			txid: bitcoin::Txid::from_byte_array([8; 32]),
			index: 17,
		},
		channel_id: [9; 32],
		htlc_id: 42,
	}
}

#[test]
fn abort_evidence_binds_transcript_and_signer_and_survives_reload() {
	for with_accept in [false, true] {
		for local in [false, true] {
			let mut record = if with_accept {
				let mut r = active_epoch();
				r.messages.truncate(2);
				r
			} else {
				epoch()
			};
			record.phase = Phase::Aborted;
			record.abort_reason = Some(6);
			let t_init = init_hash(&record.messages[0].encode());
			let transcript = if with_accept {
				setup_hash(&t_init, &record.messages[1].encode())
			} else {
				t_init
			};
			let mut bytes = record.channel_id.to_vec();
			bytes.extend_from_slice(&record.epoch_id);
			bytes.extend_from_slice(&transcript);
			bytes.extend_from_slice(&[0, 6, 0, 3]);
			bytes.extend_from_slice(b"bye");
			let message = signed(Kind::Abort, &bytes, if local { b"S" } else { b"R" });
			record.abort = Some(AbortRecord { local, message: message.clone() });
			let loaded = SettlerEpoch::decode(&record.encode().unwrap()).unwrap();
			assert!(loaded == record);
			assert_eq!(loaded.abort.unwrap().message.encode(), message.encode());
			let mut wrong = record.clone();
			wrong.abort.as_mut().unwrap().local = !local;
			assert!(wrong.encode().is_err());
			let mut wrong = record.clone();
			wrong.phase = Phase::Active;
			assert!(wrong.encode().is_err());
			let mut wrong = record.clone();
			wrong.abort_reason = Some(1);
			assert!(wrong.encode().is_err());
			let mut bad = bytes.clone();
			bad[64] ^= 1;
			record.abort.as_mut().unwrap().message =
				signed(Kind::Abort, &bad, if local { b"S" } else { b"R" });
			assert!(record.encode().is_err());
		}
	}
	let mut disconnect = epoch();
	disconnect.phase = Phase::Aborted;
	disconnect.abort_reason = Some(6);
	assert!(SettlerEpoch::decode(&disconnect.encode().unwrap()).unwrap() == disconnect);
	let mut impossible = active_epoch();
	impossible.phase = Phase::Aborted;
	impossible.abort_reason = Some(6);
	assert!(impossible.encode().is_err(), "An active epoch cannot become an aborted setup");
}

#[test]
fn upstream_claim_identity_retains_peer_funding_and_htlc_across_restart() {
	let mut record = active_epoch();
	record.slots[0].state = SlotState::Settling;
	record.slots[0].upstream = Some(upstream());
	let loaded = SettlerEpoch::decode(&record.encode().unwrap()).unwrap();
	assert_eq!(loaded.slots[0].upstream, Some(upstream()));
	let mut changed = upstream();
	changed.funding_txo.index += 1;
	assert_ne!(loaded.slots[0].upstream, Some(changed));
	let mut changed = upstream();
	changed.counterparty_node_id = node(b"other");
	assert_ne!(loaded.slots[0].upstream, Some(changed));
	let mut changed = upstream();
	changed.channel_id[0] ^= 1;
	assert_ne!(loaded.slots[0].upstream, Some(changed));
	let mut changed = upstream();
	changed.htlc_id += 1;
	assert_ne!(loaded.slots[0].upstream, Some(changed));
}

#[test]
fn node_signer_ffor_domain_is_bounded_and_explicitly_opted_in() {
	let signer = KeysManager::new(&[47; 32], 1, 0, false);
	assert!(signer.supports_ffor_settler());
	let secp = Secp256k1::verification_only();
	for wire in [ACCEPT, ACK, include_bytes!("fixtures/sync-reply-1.bin")] {
		let msg = SignedMessage::decode(wire).unwrap();
		let digest = settler_signing_digest(msg.kind as u16, msg.unsigned()).unwrap();
		assert_eq!(digest, message_digest(msg.kind, msg.unsigned()));
		let signature = signer.sign_ffor_message(msg.kind as u16, msg.unsigned()).unwrap();
		let signed =
			SignedMessage::from_parts(msg.kind, msg.unsigned(), signature.serialize_compact())
				.unwrap();
		assert_eq!(signed.verify(&secp, &signer.get_node_id(Recipient::Node).unwrap()), Ok(()));
		assert!(secp
			.verify_ecdsa(
				&Message::from_digest(super::digest(&[msg.unsigned()])),
				&signature,
				&signer.get_node_id(Recipient::Node).unwrap()
			)
			.is_err());
		assert!(signer.sign_ffor_message(msg.kind as u16, &msg.unsigned()[..63]).is_err());
	}
	for wire in [INIT, ACTIVATE, SYNC] {
		let msg = SignedMessage::decode(wire).unwrap();
		assert!(signer.sign_ffor_message(msg.kind as u16, msg.unsigned()).is_err());
	}
	assert!(signer.sign_ffor_message(42, &[0; 96]).is_err());
	assert!(signer.sign_ffor_message(Kind::ActivateAck as u16, &vec![0; MAX_BODY]).is_err());
	let external = DefaultFforSigner { inner: Box::new(KeysManager::new(&[48; 32], 1, 0, false)) };
	assert!(!external.supports_ffor_settler());
	assert!(external
		.sign_ffor_message(Kind::ActivateAck as u16, SignedMessage::decode(ACK).unwrap().unsigned())
		.is_err());
	let test_signer =
		crate::util::test_utils::TestKeysInterface::new(&[48; 32], bitcoin::Network::Regtest);
	assert!(test_signer.supports_ffor_settler());
	let body = SignedMessage::decode(ACK).unwrap();
	let sig = test_signer.sign_ffor_message(Kind::ActivateAck as u16, body.unsigned()).unwrap();
	assert!(SignedMessage::from_parts(Kind::ActivateAck, body.unsigned(), sig.serialize_compact())
		.unwrap()
		.verify(&secp, &test_signer.get_node_id(Recipient::Node).unwrap())
		.is_ok());
}

fn driver_setup() -> (KeysManager, PreparedTransition, SetupContext, Policy) {
	let signer = KeysManager::new(&[49; 32], 1, 0, false);
	let init = epoch().messages.remove(0);
	let terms = init.settler_terms().unwrap();
	let context = SetupContext {
		channel_id: init.channel_id,
		remote_node: node(b"R"),
		usable_anchor_channel: true,
		concurrent_features_negotiated: true,
		idle_without_splice: true,
		current_height: terms.deadline - 10,
		next_local_htlc_id: 23,
		local_commitment_number: 42,
		max_accepted_htlcs: 483,
		max_in_flight_msat: u64::MAX,
		minimum_htlc_msat: 1,
		minimum_untrimmed_msat: 1,
		available_after_reserves_and_fee_msat: u64::MAX,
	};
	let policy = Policy {
		max_slots: 483,
		max_budget_msat: u64::MAX,
		max_epoch_blocks: 5040,
		min_fee_base_msat: 0,
		min_fee_ppm: 0,
	};
	let prepared = prepare_setup(None, init, &context, &policy, &signer, &signer).unwrap();
	(signer, prepared, context, policy)
}

fn snapshot_for(journal: &FforJournal) -> CommitmentSnapshot {
	CommitmentSnapshot {
		funding_txo: upstream().funding_txo,
		receiver_number: 43,
		settler_number: 43,
		receiver_txid: bitcoin::Txid::from_byte_array([31; 32]),
		settler_txid: bitcoin::Txid::from_byte_array([32; 32]),
		outputs: journal
			.epoch
			.slots
			.iter()
			.map(|s| VoucherOutput {
				entry: s.entry.clone(),
				receiver_output_index: 2,
				settler_output_index: 3,
			})
			.collect(),
	}
}

fn activation_for(
	journal: &FforJournal, snapshot: &CommitmentSnapshot, height: u32,
) -> SignedMessage {
	activate_for(journal, snapshot, height, &key(b"R"))
}

pub(crate) fn activate_for(
	journal: &FforJournal, snapshot: &CommitmentSnapshot, height: u32, receiver: &SecretKey,
) -> SignedMessage {
	let init = &journal.epoch.messages[0];
	let accept = &journal.epoch.messages[1];
	let setup = setup_hash(&init_hash(&init.encode()), &accept.encode());
	let book = book_hash(
		&encode_book(
			&journal.epoch.epoch_id,
			&journal.epoch.slots.iter().map(|s| s.entry.clone()).collect::<Vec<_>>(),
		)
		.unwrap(),
	);
	let commit = commitment_hash(
		snapshot.receiver_number,
		&snapshot.receiver_txid.to_byte_array(),
		snapshot.settler_number,
		&snapshot.settler_txid.to_byte_array(),
	);
	let mut bytes = journal.epoch.channel_id.to_vec();
	bytes.extend_from_slice(&journal.epoch.epoch_id);
	bytes.extend_from_slice(&setup);
	bytes.extend_from_slice(&book);
	bytes.extend_from_slice(&commit);
	bytes.extend_from_slice(&height.to_be_bytes());
	sign_with(Kind::Activate, &bytes, receiver)
}

fn driver_active() -> (KeysManager, FforJournal, u32) {
	let (signer, setup, ctx, _) = driver_setup();
	let snapshot = snapshot_for(&setup.journal);
	let committed = vouchers_committed(&setup.journal, snapshot.clone()).unwrap();
	let activate = activation_for(&committed.journal, &snapshot, ctx.current_height);
	let active =
		prepare_activate(&committed.journal, activate, &snapshot, ctx.current_height, &signer)
			.unwrap();
	let active = activation_ack_sent(&active.journal).unwrap();
	(signer, active.journal, ctx.current_height)
}

fn delegation(journal: &FforJournal, height: u32) -> DelegationContext {
	let item = &journal.epoch.slots[0];
	let terms = journal.epoch.messages[0].settler_terms().unwrap();
	DelegationContext {
		upstream: upstream(),
		payment_hash: item.entry.payment_hash,
		irrevocably_committed: true,
		current_height: height,
		incoming_cltv: height + 145,
		forwarding_delta: 144,
		incoming_msat: item.entry.amount_msat
			+ terms.fee_base_msat as u64
			+ item.entry.amount_msat * terms.fee_ppm as u64 / 1_000_000,
		forward: ForwardAmount::Plaintext(item.entry.amount_msat),
		verified_advertised_fee: None,
	}
}

fn sync_request(journal: &FforJournal, nonce: u8) -> SignedMessage {
	let ack = journal.epoch.messages.iter().find(|m| m.kind == Kind::ActivateAck).unwrap();
	let mut bytes = journal.epoch.channel_id.to_vec();
	bytes.extend_from_slice(&journal.epoch.epoch_id);
	bytes.extend_from_slice(&ack.unsigned()[64..96]);
	bytes.extend_from_slice(&[nonce; 32]);
	signed(Kind::Sync, &bytes, b"R")
}

#[test]
fn driver_setup_and_activation_require_native_facts_and_defer_every_send() {
	let (signer, setup, mut ctx, policy) = driver_setup();
	assert_eq!(setup.journal.revision, 1);
	assert_eq!(setup.journal.epoch.phase, Phase::Negotiating);
	assert_eq!(setup.after_persistence.len(), 2);
	assert_eq!(setup.after_persistence[1], Action::OfferVouchers);
	assert!(setup.journal.epoch.slots.iter().all(|s| s.state == SlotState::Unused));
	let init = setup.journal.epoch.messages[0].clone();
	ctx.idle_without_splice = false;
	assert!(prepare_setup(None, init.clone(), &ctx, &policy, &signer, &signer).is_err());
	ctx.idle_without_splice = true;
	ctx.available_after_reserves_and_fee_msat = 0;
	assert!(prepare_setup(None, init, &ctx, &policy, &signer, &signer).is_err());
	let snapshot = snapshot_for(&setup.journal);
	let committed = vouchers_committed(&setup.journal, snapshot.clone()).unwrap();
	assert!(committed.after_persistence.is_empty());
	let activate = activation_for(&committed.journal, &snapshot, ctx.current_height);
	let mut wrong = snapshot.clone();
	wrong.settler_number += 1;
	assert!(prepare_activate(
		&committed.journal,
		activate.clone(),
		&wrong,
		ctx.current_height,
		&signer
	)
	.is_err());
	assert!(prepare_activate(
		&committed.journal,
		activate.clone(),
		&snapshot,
		ctx.current_height + 7,
		&signer
	)
	.is_err());
	let active = prepare_activate(
		&committed.journal,
		activate.clone(),
		&snapshot,
		ctx.current_height,
		&signer,
	)
	.unwrap();
	assert!(active.journal.epoch.activation_ack_pending);
	assert_eq!(active.after_persistence.len(), 2);
	assert!(
		prepare_settlement(&active.journal, 1, &delegation(&active.journal, ctx.current_height))
			.is_ok(),
		"Durable ACTIVE keeps upstream offline admission despite a lost ACK-sent marker"
	);
	assert!(matches!(replay_response(&active.journal, &activate), Ok(Action::Send(_))));
	let sent = activation_ack_sent(&active.journal).unwrap();
	assert!(prepare_settlement(&sent.journal, 1, &delegation(&sent.journal, ctx.current_height))
		.is_ok());
}

#[test]
fn driver_claim_custody_and_receipts_survive_restart_without_new_admission() {
	use crate::util::ser::{Readable, Writeable};
	let (signer, active, height) = driver_active();
	let ctx = delegation(&active, height);
	let settling = prepare_settlement(&active, 1, &ctx).unwrap();
	assert_eq!(
		settling.after_persistence,
		vec![Action::ClaimUpstream { slot: 1, upstream: ctx.upstream.clone() }]
	);
	assert_eq!(identify_slot(&settling.journal, &ctx.payment_hash), Some(1));
	assert_eq!(identify_slot(&settling.journal, &[99; 32]), None);
	let bytes = settling.journal.encode();
	let loaded = FforJournal::read(&mut crate::io::Cursor::new(bytes)).unwrap();
	assert_eq!(replay_settling(&loaded), settling.after_persistence);
	let mut wrong = ctx.upstream.clone();
	wrong.funding_txo.index += 1;
	assert!(replay_claim(&loaded, 1, &wrong).is_err());
	assert!(settlement_completed(&loaded, 1, &wrong).is_err());
	assert!(prepare_settlement(&loaded, 1, &ctx).is_err());
	let empty = prepare_sync(&loaded, &sync_request(&loaded, 1), &signer).unwrap();
	let reply = empty.journal.epoch.messages.iter().find(|m| m.kind == Kind::SyncReply).unwrap();
	assert_eq!(&reply.unsigned()[128..136], &[0; 8]);
	assert!(!reply.unsigned().windows(32).any(|v| v == loaded.epoch.slots[0].preimage));
	let completed = settlement_completed(&empty.journal, 1, &ctx.upstream).unwrap();
	let published =
		prepare_sync(&completed.journal, &sync_request(&completed.journal, 2), &signer).unwrap();
	let reply =
		published.journal.epoch.messages.iter().find(|m| m.kind == Kind::SyncReply).unwrap();
	assert_eq!(&reply.unsigned()[128..136], &1u64.to_be_bytes());
	assert!(reply.unsigned().windows(32).any(|v| v == loaded.epoch.slots[0].preimage));
	let repeat =
		prepare_sync(&published.journal, &sync_request(&published.journal, 3), &signer).unwrap();
	let reply = repeat.journal.epoch.messages.iter().find(|m| m.kind == Kind::SyncReply).unwrap();
	assert_eq!(&reply.unsigned()[128..136], &1u64.to_be_bytes());
	assert!(replay_settling(&repeat.journal).is_empty());
	assert!(replay_claim(&repeat.journal, 1, &ctx.upstream).is_ok());
}

#[test]
fn driver_first_use_rejects_bad_fee_amount_deadline_cltv_and_uncommitted_add() {
	let (_, active, height) = driver_active();
	let mut ctx = delegation(&active, height);
	ctx.irrevocably_committed = false;
	assert!(prepare_settlement(&active, 1, &ctx).is_err());
	ctx.irrevocably_committed = true;
	ctx.incoming_msat -= 1;
	assert!(prepare_settlement(&active, 1, &ctx).is_err());
	ctx.incoming_msat += 1;
	ctx.incoming_cltv -= 1;
	assert!(prepare_settlement(&active, 1, &ctx).is_err());
	ctx.incoming_cltv += 1;
	ctx.forward = ForwardAmount::Plaintext(active.epoch.slots[0].entry.amount_msat + 1);
	assert!(prepare_settlement(&active, 1, &ctx).is_err());
	ctx.forward = ForwardAmount::Blinded;
	assert!(prepare_settlement(&active, 1, &ctx).is_ok());
	ctx.current_height = active.epoch.slots[0].entry.deadline;
	assert!(prepare_settlement(&active, 1, &ctx).is_err());
}

#[test]
fn driver_close_preserves_in_flight_obligation_and_abort_never_releases_it() {
	let (signer, active, height) = driver_active();
	let ctx = delegation(&active, height);
	let settling = prepare_settlement(&active, 1, &ctx).unwrap();
	let ack = active.epoch.messages.iter().find(|m| m.kind == Kind::ActivateAck).unwrap();
	let close = signed(Kind::Close, ack.unsigned(), b"R");
	let draining = prepare_close(&settling.journal, close.clone(), &signer).unwrap();
	assert_eq!(draining.journal.epoch.phase, Phase::Draining);
	assert_eq!(draining.journal.epoch.slots[0].state, SlotState::Settling);
	assert!(replay_claim(&draining.journal, 1, &ctx.upstream).is_ok());
	assert!(prepare_abort(&draining.journal, 1, &signer).is_err());
	assert!(matches!(replay_response(&draining.journal, &close), Ok(Action::Send(_))));
	let final_state = settlement_completed(&draining.journal, 1, &ctx.upstream).unwrap();
	assert_eq!(final_state.journal.epoch.slots[0].state, SlotState::Settled);
	let (signer, setup, _, _) = driver_setup();
	let aborted = prepare_abort(&setup.journal, 6, &signer).unwrap();
	assert_eq!(aborted.after_persistence.last(), Some(&Action::CancelSetupVouchers));
	assert!(aborted.journal.epoch.abort.as_ref().unwrap().local);
	assert!(replay_settling(&aborted.journal).is_empty());
}

#[test]
fn driver_reconnect_is_durable_sticky_on_mismatch_and_preserves_offline_service() {
	let (signer, active, height) = driver_active();
	assert!(prepare_disconnect(&active, &signer).unwrap().is_none());
	assert!(prepare_settlement(&active, 1, &delegation(&active, height)).is_ok());
	let peer = reestablish(&active).unwrap();
	let hold = prepare_reestablish(&active, Some(&peer), false, &signer).unwrap();
	assert!(hold.journal.epoch.capability_hold);
	assert!(!hold.journal.epoch.activation_mismatch);
	assert!(prepare_settlement(&hold.journal, 1, &delegation(&hold.journal, height)).is_err());
	assert!(
		prepare_sync(&hold.journal, &sync_request(&hold.journal, 1), &signer).is_ok(),
		"Receipt recovery is an existing obligation"
	);
	let clear = prepare_reestablish(&hold.journal, Some(&peer), true, &signer).unwrap();
	assert!(!clear.journal.epoch.capability_hold);
	assert!(prepare_settlement(&clear.journal, 1, &delegation(&clear.journal, height)).is_ok());
	let mismatch = prepare_reestablish(&clear.journal, None, true, &signer).unwrap();
	assert!(mismatch.journal.epoch.activation_mismatch);
	let retried = prepare_reestablish(&mismatch.journal, Some(&peer), true, &signer).unwrap();
	assert!(
		retried.journal.epoch.activation_mismatch,
		"Later negotiation cannot erase a data loss signal"
	);
	assert!(prepare_settlement(&retried.journal, 1, &delegation(&retried.journal, height)).is_err());
	let mut lost_ack = peer.clone();
	lost_ack.state = 2;
	let replay = prepare_reestablish(&active, Some(&lost_ack), true, &signer).unwrap();
	assert!(replay.journal.epoch.activation_ack_pending);
	assert!(
		matches!(&replay.after_persistence[0], Action::Send(msg) if msg.kind == Kind::ActivateAck)
	);
	assert!(
		prepare_settlement(&replay.journal, 1, &delegation(&replay.journal, height)).is_ok(),
		"Owed home replay cannot disable the separate upstream offline service"
	);
	let delivered = activation_ack_sent(&replay.journal).unwrap();
	assert!(
		prepare_settlement(&delivered.journal, 1, &delegation(&delivered.journal, height)).is_ok()
	);
	let (signer, setup, _, _) = driver_setup();
	let aborted = prepare_disconnect(&setup.journal, &signer).unwrap().unwrap();
	assert_eq!(aborted.journal.epoch.phase, Phase::Aborted);
	assert_eq!(aborted.journal.epoch.abort_reason, Some(6));
}

#[test]
fn driver_voucher_resolution_requires_irrevocable_proof_and_outstanding_claim_completion() {
	let (signer, active, height) = driver_active();
	let ctx = delegation(&active, height);
	let settling = prepare_settlement(&active, 1, &ctx).unwrap();
	let ack = active.epoch.messages.iter().find(|m| m.kind == Kind::ActivateAck).unwrap();
	let close = signed(Kind::Close, ack.unsigned(), b"R");
	let draining = prepare_close(&settling.journal, close, &signer).unwrap();
	let proof = Removal { fulfilled: true, local_commitment: 44, remote_commitment: 44 };
	assert!(prepare_voucher_result(&draining.journal, 1, None, Some(proof.clone())).is_err());
	assert!(prepare_voucher_result(&draining.journal, 1, Some([9; 32]), None).is_err());
	let preimage = draining.journal.epoch.slots[0].preimage;
	let fulfilled = prepare_voucher_result(&draining.journal, 1, Some(preimage), None).unwrap();
	assert!(fulfilled.journal.epoch.slots[0].removal.is_none());
	let removed = prepare_voucher_result(&fulfilled.journal, 1, None, Some(proof)).unwrap();
	assert_eq!(
		removed.journal.epoch.phase,
		Phase::Draining,
		"Upstream claim still needs native completion"
	);
	let closed = settlement_completed(&removed.journal, 1, &ctx.upstream).unwrap();
	assert_eq!(closed.journal.epoch.phase, Phase::Closed);
	let synced = prepare_sync(&closed.journal, &sync_request(&closed.journal, 2), &signer).unwrap();
	assert!(
		matches!(&synced.after_persistence[0], Action::Send(msg) if msg.kind == Kind::CloseAck)
	);
	assert!(replay_claim(&synced.journal, 1, &ctx.upstream).is_ok());
	assert!(prepare_voucher_result(
		&active,
		1,
		None,
		Some(Removal { fulfilled: false, local_commitment: 44, remote_commitment: 44 })
	)
	.is_err());
	let redeemed =
		prepare_voucher_result(&active, 1, Some(active.epoch.slots[0].preimage), None).unwrap();
	assert!(
		prepare_settlement(&redeemed.journal, 1, &delegation(&redeemed.journal, height)).is_err()
	);
	let mut no_tip = delegation(&active, height);
	no_tip.current_height = 0;
	assert!(prepare_settlement(&active, 1, &no_tip).is_err());
}

#[test]
fn concurrent_v2_close_keeps_unpaid_vouchers_reserved() {
	use crate::util::ser::{Readable, Writeable};
	let (signer, active, _) = driver_active();
	let ack = active.epoch.messages.iter().find(|m| m.kind == Kind::ActivateAck).unwrap();
	let close = signed(Kind::Close, ack.unsigned(), b"R");
	let draining = prepare_close(&active, close, &signer).unwrap();
	assert_eq!(draining.journal.epoch.phase, Phase::Draining);
	assert_eq!(draining.journal.epoch.slots[0].state, SlotState::Unused);
	// Concurrent v2 retains even an unpaid slot after the final close bitmap.
	// Its receiver cannot cancel the claim by sending the legacy v1 drain fail.
	let failure = Removal { fulfilled: false, local_commitment: 44, remote_commitment: 44 };
	assert!(prepare_voucher_result(&draining.journal, 1, None, Some(failure.clone())).is_err());
	let mut forged = draining.journal.epoch.clone();
	forged.slots[0].removal = Some(failure);
	assert!(forged.encode().is_err());
	let reloaded = FforJournal::read(&mut &draining.journal.encode()[..]).unwrap();
	assert_eq!(reloaded.epoch.phase, Phase::Draining);
	assert!(reloaded.epoch.slots[0].removal.is_none());
	let preimage = reloaded.epoch.slots[0].preimage;
	let fulfilled = prepare_voucher_result(&reloaded, 1, Some(preimage), None).unwrap();
	let proof = Removal { fulfilled: true, local_commitment: 44, remote_commitment: 44 };
	let closed = prepare_voucher_result(&fulfilled.journal, 1, None, Some(proof)).unwrap();
	assert_eq!(closed.journal.epoch.phase, Phase::Closed);
}

#[test]
fn live_sync_reports_redemption_only_after_two_view_removal() {
	let (signer, active, _) = driver_active();
	let preimage = active.epoch.slots[0].preimage;
	let redeemed = prepare_voucher_result(&active, 1, Some(preimage), None).unwrap();
	let before =
		prepare_sync(&redeemed.journal, &sync_request(&redeemed.journal, 1), &signer).unwrap();
	let reply =
		before.journal.epoch.messages.iter().find(|msg| msg.kind == Kind::SyncReply).unwrap();
	assert_eq!(&reply.unsigned()[128..136], &0u64.to_be_bytes());
	assert!(!reply.unsigned().windows(32).any(|bytes| bytes == preimage));
	// A final close may acknowledge a known claim while its native removal is
	// still pending. A live sync snapshot promises completed redemption instead.
	let ack = redeemed.journal.epoch.messages.iter().find(|m| m.kind == Kind::ActivateAck).unwrap();
	let close = signed(Kind::Close, ack.unsigned(), b"R");
	let draining = prepare_close(&redeemed.journal, close, &signer).unwrap();
	let close_ack =
		draining.journal.epoch.messages.iter().find(|msg| msg.kind == Kind::CloseAck).unwrap();
	assert!(close_ack.unsigned().windows(32).any(|bytes| bytes == preimage));
	let proof = Removal { fulfilled: true, local_commitment: 44, remote_commitment: 44 };
	let removed = prepare_voucher_result(&before.journal, 1, None, Some(proof)).unwrap();
	let after =
		prepare_sync(&removed.journal, &sync_request(&removed.journal, 2), &signer).unwrap();
	let reply =
		after.journal.epoch.messages.iter().find(|msg| msg.kind == Kind::SyncReply).unwrap();
	assert_eq!(&reply.unsigned()[128..136], &1u64.to_be_bytes());
	assert!(reply.unsigned().windows(32).any(|bytes| bytes == preimage));
	let mut forged = after.journal.epoch.clone();
	forged.slots[0].removal = None;
	assert!(forged.encode().is_err(), "Serialized live receipts require the same native proof");
}

#[test]
fn chain_resolution_preserves_claim_custody_and_exact_replay() {
	let (signer, active, height) = driver_active();
	let ctx = delegation(&active, height);
	let settling = prepare_settlement(&active, 1, &ctx).unwrap();
	let ack = active.epoch.messages.iter().find(|m| m.kind == Kind::ActivateAck).unwrap();
	let draining =
		prepare_close(&settling.journal, signed(Kind::Close, ack.unsigned(), b"R"), &signer)
			.unwrap();
	let proof = ChainRemoval {
		commitment_txid: [1; 32],
		output_index: Some(3),
		resolving_txid: [2; 32],
		fulfilled: false,
	};
	let resolved = prepare_chain_resolution(&draining.journal, 1, proof.clone()).unwrap();
	assert_eq!(resolved.journal.epoch.phase, Phase::Draining);
	assert_eq!(resolved.journal.epoch.slots[0].state, SlotState::Settling);
	assert_eq!(resolved.journal.epoch.slots[0].upstream.as_ref(), Some(&ctx.upstream));
	assert!(resolved.journal.epoch.slots[0].removal.is_none());
	assert!(resolved.after_persistence.is_empty());
	assert_eq!(replay_settling(&resolved.journal).len(), 1);
	assert!(replay_claim(&resolved.journal, 1, &ctx.upstream).is_ok());
	let duplicate = prepare_chain_resolution(&resolved.journal, 1, proof.clone()).unwrap();
	assert!(duplicate.journal.epoch == resolved.journal.epoch);
	assert!(duplicate.after_persistence.is_empty());
	let mut conflict = proof;
	conflict.resolving_txid = [3; 32];
	assert!(prepare_chain_resolution(&duplicate.journal, 1, conflict).is_err());
	let closed = settlement_completed(&duplicate.journal, 1, &ctx.upstream).unwrap();
	assert_eq!(closed.journal.epoch.phase, Phase::Closed);
	let encoded = closed.journal.epoch.encode().unwrap();
	assert!(SettlerEpoch::decode(&encoded).unwrap() == closed.journal.epoch);
	let mut old_version = encoded.clone();
	old_version[4] = 3;
	assert_eq!(SettlerEpoch::decode(&old_version).err(), Some(Error::Unsupported));
	for len in 0..encoded.len() {
		assert!(SettlerEpoch::decode(&encoded[..len]).is_err());
	}
}

#[test]
fn chain_resolution_blocks_new_delegation_and_reports_only_fulfilled_outcome() {
	let (signer, active, height) = driver_active();
	let absent = ChainRemoval {
		commitment_txid: [1; 32],
		output_index: None,
		resolving_txid: [1; 32],
		fulfilled: false,
	};
	let failed = prepare_chain_resolution(&active, 1, absent.clone()).unwrap();
	assert_eq!(failed.journal.epoch.phase, Phase::Active);
	assert!(!failed.journal.epoch.slots[0].redeemed);
	assert!(prepare_settlement(&failed.journal, 1, &delegation(&failed.journal, height)).is_err());
	let sync = prepare_sync(&failed.journal, &sync_request(&failed.journal, 1), &signer).unwrap();
	let reply = sync.journal.epoch.messages.iter().find(|m| m.kind == Kind::SyncReply).unwrap();
	assert_eq!(&reply.unsigned()[128..136], &0u64.to_be_bytes());
	let mut malformed = absent.clone();
	malformed.resolving_txid = [9; 32];
	assert!(prepare_chain_resolution(&active, 1, malformed).is_err());
	let mut malformed = absent;
	malformed.fulfilled = true;
	assert!(prepare_chain_resolution(&active, 1, malformed).is_err());
	let fulfilled = ChainRemoval {
		commitment_txid: [1; 32],
		output_index: Some(3),
		resolving_txid: [2; 32],
		fulfilled: true,
	};
	let paid = prepare_chain_resolution(&active, 1, fulfilled).unwrap();
	assert!(paid.journal.epoch.slots[0].redeemed);
	let mut forged = paid.journal.epoch.clone();
	forged.slots[0].redeemed = false;
	assert!(forged.encode().is_err());
	assert_eq!(paid.journal.epoch.slots[0].state, SlotState::Unused);
	assert!(prepare_settlement(&paid.journal, 1, &delegation(&paid.journal, height)).is_err());
	let sync = prepare_sync(&paid.journal, &sync_request(&paid.journal, 1), &signer).unwrap();
	let reply = sync.journal.epoch.messages.iter().find(|m| m.kind == Kind::SyncReply).unwrap();
	assert_eq!(&reply.unsigned()[128..136], &1u64.to_be_bytes());
	assert!(reply.unsigned().windows(32).any(|bytes| bytes == active.epoch.slots[0].preimage));
	let mut forged = sync.journal.epoch.clone();
	forged.slots[0].chain_removal = None;
	assert!(forged.encode().is_err());
}

#[test]
fn preactivation_chain_evidence_never_invents_activation() {
	let (signer, setup, _, _) = driver_setup();
	let snapshot = snapshot_for(&setup.journal);
	let proof = ChainRemoval {
		commitment_txid: [1; 32],
		output_index: Some(0),
		resolving_txid: [2; 32],
		fulfilled: true,
	};
	let resolved = prepare_chain_resolution(&setup.journal, 1, proof).unwrap();
	assert_eq!(resolved.journal.epoch.phase, Phase::Negotiating);
	assert!(!resolved.journal.epoch.slots[0].redeemed);
	assert!(vouchers_committed(&resolved.journal, snapshot).is_err());
	let aborted = prepare_abort(&resolved.journal, 6, &signer).unwrap();
	assert_eq!(aborted.journal.epoch.phase, Phase::Aborted);
	assert_eq!(
		aborted.journal.epoch.slots[0].chain_removal,
		resolved.journal.epoch.slots[0].chain_removal
	);
}

#[test]
fn pure_parser_fuzz_entry_exercises_vectors_and_state_boundaries() {
	let (_, active, _) = driver_active();
	let mut archive = UsedArchive::default();
	archive
		.reserve(
			active.epoch.channel_id,
			active.epoch.epoch_id,
			&[active.epoch.slots[0].entry.payment_hash],
		)
		.unwrap();
	let mut corpus = vec![
		INIT.to_vec(),
		ACCEPT.to_vec(),
		ACTIVATE.to_vec(),
		ACK.to_vec(),
		SYNC.to_vec(),
		active.epoch.encode().unwrap(),
		archive.encode(),
		reestablish(&active).unwrap().encode().unwrap().to_vec(),
	];
	corpus.push(vec![0; MAX_BODY + 3]);
	corpus.push(vec![0; 512 * 1024 + 1]);
	for seed in corpus {
		fuzz_parsers(&seed);
		if seed.len() > 4096 {
			continue;
		}
		for len in 0..seed.len().min(2048) {
			fuzz_parsers(&seed[..len]);
			let mut mutated = seed.clone();
			mutated[len] ^= 0xff;
			fuzz_parsers(&mutated);
		}
	}
}
