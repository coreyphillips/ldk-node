use super::*;
use bitcoin::{absolute, transaction, EcdsaSighashType, TxIn, TxOut};
use lightning::ln::chan_utils::make_funding_redeemscript;

fn key(byte: u8) -> (SecretKey, PublicKey) {
	let secret = SecretKey::from_slice(&[byte; 32]).unwrap();
	(secret, PublicKey::from_secret_key(&Secp256k1::new(), &secret))
}

fn node() -> crate::Node {
	let config = Config {
		storage_dir_path: std::env::temp_dir()
			.join(format!("ldk-df-receiver-test-{}", rand::random::<u64>()))
			.to_str()
			.unwrap()
			.to_owned(),
		network: bitcoin::Network::Regtest,
		primary_node_id: Some(key(2).1),
		..Default::default()
	};
	let mut builder = crate::Builder::from_config(config);
	builder.set_chain_source_esplora(
		"http://127.0.0.1:1".to_owned(),
		Some(crate::config::EsploraSyncConfig { background_sync_config: None }),
	);
	builder.build().unwrap()
}

fn reload(node: &crate::Node) -> Result<Receiver, BuildError> {
	Receiver::new(
		node.channel_manager.clone(),
		node.keys_manager.clone(),
		node.chain_source.clone(),
		node.fee_estimator.clone(),
		node.kv_store.clone(),
		node.config.clone(),
		Arc::new(Transport::new(node.node_id())),
	)
}

fn fixture(node: &crate::Node, signed: bool) -> (String, Session, Transaction) {
	let receiver = &node.direct_funding.receiver;
	let minted = receiver.mint(Some(20_000), 60, "localhost".to_owned(), 9735).unwrap();
	let record = receiver.state.lock().unwrap().requests[&minted.request_id].clone();
	let envelope = receiver.envelope(&record).unwrap();
	let (payer, pubkey) = key(9);
	let coin_script = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::hash(&pubkey.serialize()));
	let offer = Offer {
		offer_id: codec::derive_offer_id(&[6; 32], 0, 20_000),
		amount_sat: 20_000,
		txid: [6; 32],
		vout: 0,
		value_sat: 100_000,
		sequence: Sequence::ENABLE_RBF_NO_LOCKTIME.0,
		change_script: coin_script.to_bytes(),
		max_total_fee_sat: 1000,
		receipt_hash: envelope.receipt_hash,
		ownership: codec::OwnershipProof {
			pubkey: pubkey.serialize().to_vec(),
			signature: [0; 64],
			message_proof: None,
			probe_proof: None,
		},
	};
	let funding_script = make_funding_redeemscript(&key(3).1, &key(4).1);
	let mut transaction = Transaction {
		version: transaction::Version::TWO,
		lock_time: absolute::LockTime::ZERO,
		input: vec![TxIn {
			previous_output: offer.outpoint(),
			sequence: Sequence(offer.sequence),
			..Default::default()
		}],
		output: vec![
			TxOut { value: Amount::from_sat(20_000), script_pubkey: funding_script.to_p2wsh() },
			TxOut { value: Amount::from_sat(79_000), script_pubkey: coin_script.clone() },
		],
	};
	let details = FundingSigningDetails {
		unsigned_transaction: transaction.clone(),
		prevouts: vec![TxOut {
			value: Amount::from_sat(100_000),
			script_pubkey: coin_script.clone(),
		}],
		shared_input_index: None,
		funding_output_index: 0,
		funding_redeem_script: funding_script,
		previous_funding_redeem_script: None,
		local_witnesses_submitted: false,
	};
	let request =
		make_sign_request(&offer, &details, &node.keys_manager.get_node_secret_key()).unwrap();
	let hash = bitcoin::sighash::SighashCache::new(&transaction)
		.p2wpkh_signature_hash(0, &coin_script, Amount::from_sat(100_000), EcdsaSighashType::All)
		.unwrap();
	let signature = Secp256k1::new()
		.sign_ecdsa(&bitcoin::secp256k1::Message::from_digest(hash.to_byte_array()), &payer);
	let mut signature = signature.serialize_der().to_vec();
	signature.push(EcdsaSighashType::All as u8);
	let witness = vec![signature, pubkey.serialize().to_vec()];
	transaction.input[0].witness = bitcoin::Witness::from_slice(&witness);
	let session = Session {
		offer: offer.encode().unwrap(),
		ephemeral: key(8).1.to_string(),
		route: SavedRoute::from_route(Route { peer: key(2).1, relay_target: Some(pubkey) }),
		user_channel_id: 42,
		channel_id: signed.then(|| codec::hex(&[5; 32])),
		is_splice: false,
		created_at: now_ms() - SESSION_TIMEOUT_MS - 1,
		sign_request: signed.then(|| request.encode().unwrap()),
		witness: signed.then_some(witness),
		funding_txid: signed.then(|| transaction.compute_txid().to_string()),
		mempool_seen: false,
		confirmed: false,
		failed: false,
	};
	(minted.request_id, session, transaction)
}

fn save(node: &crate::Node, id: &str, session: Session) {
	node.direct_funding
		.receiver
		.update(|state| {
			let record = state.requests.get_mut(id).unwrap();
			record.attempts = 1;
			record.session = Some(session);
			Ok(())
		})
		.unwrap();
}

fn expire(node: &crate::Node, id: &str) {
	let receiver = &node.direct_funding.receiver;
	receiver
		.update(|state| {
			let record = state.requests.get_mut(id).unwrap();
			let mut envelope = receiver.envelope(record)?;
			envelope.expires_at = now_ms() - 1;
			let message = envelope.prepare_signature(now_ms() - 1000).unwrap();
			envelope.signature =
				crypto::sign_message(&message, &node.keys_manager.get_node_secret_key());
			record.envelope = envelope.encode().unwrap();
			record.expires_at = envelope.expires_at;
			Ok(())
		})
		.unwrap();
}

#[test]
fn expired_precommitment_open_without_native_state_releases_busy_after_restart() {
	let node = node();
	let (id, session, _) = fixture(&node, false);
	save(&node, &id, session);
	let restored = reload(&node).unwrap();
	assert!(restored.has_pending());
	node.runtime.block_on(restored.tick());
	assert!(!restored.has_pending());
	assert_eq!(restored.payments()[0].status, Status::Failed);
	assert_eq!(reload(&node).unwrap().payments()[0].status, Status::Failed);
}

#[test]
fn persisted_witness_is_never_released_by_timeout_or_missing_native_state() {
	let node = node();
	let (id, session, _) = fixture(&node, true);
	save(&node, &id, session.clone());
	let restored = reload(&node).unwrap();
	assert_eq!(restored.invalidate(&id), Err(Error::Busy));
	assert!(restored
		.resume_witness(&restored.state.lock().unwrap().requests[&id], &session)
		.is_err());
	node.runtime.block_on(restored.tick());
	assert!(restored.has_pending());
	assert_eq!(reload(&node).unwrap().payments()[0].status, Status::SignedPending);
}

#[test]
fn invalidation_persists_and_rejects_offers_without_chain_access() {
	let node = node();
	let (id, session, _) = fixture(&node, false);
	let receiver = &node.direct_funding.receiver;
	receiver.invalidate(&id).unwrap();
	let restored = reload(&node).unwrap();
	let record = restored.state.lock().unwrap().requests[&id].clone();
	assert!(record.revoked);
	let offer = Offer::decode(&session.offer).unwrap();
	node.runtime
		.block_on(restored.admit(
			&id,
			record,
			offer,
			session.offer.clone(),
			key(8).1,
			session.route.route().unwrap(),
		))
		.unwrap();
	assert!(!restored.has_pending());
	assert_eq!(restored.transport.take_messages().len(), 1);
}

#[test]
fn chain_receipt_requires_exact_approved_transaction_and_witness() {
	let node = node();
	let (_, session, mut transaction) = fixture(&node, true);
	assert!(observed_transaction_matches(&session, &transaction));
	transaction.input[0].witness.clear();
	assert!(!observed_transaction_matches(&session, &transaction));
	transaction.input[0].witness = bitcoin::Witness::from_slice(session.witness.as_ref().unwrap());
	transaction.output[0].value = Amount::from_sat(19_999);
	assert!(!observed_transaction_matches(&session, &transaction));
}

#[test]
fn corrupt_signed_status_or_witness_prevents_restore() {
	for case in 0..4 {
		let node = node();
		let (id, mut session, _) = fixture(&node, true);
		match case {
			0 => session.witness.as_mut().unwrap()[0][4] ^= 1,
			1 => session.confirmed = true,
			2 => session.funding_txid = Some(codec::hex(&[1; 32])),
			_ => session.failed = true,
		}
		save(&node, &id, session);
		assert!(reload(&node).is_err());
	}
}

#[test]
fn confirmed_history_survives_expiry_and_does_not_capture_next_funding() {
	let node = node();
	let (id, mut session, _) = fixture(&node, true);
	session.mempool_seen = true;
	session.confirmed = true;
	save(&node, &id, session);
	let receiver = &node.direct_funding.receiver;
	expire(&node, &id);
	let (_, active, transaction) = fixture(&node, false);
	assert_eq!(receiver.payments().len(), 1);
	assert_eq!(
		receiver.funding_ready(
			ChannelId::from_bytes([5; 32]),
			key(2).1,
			active.user_channel_id,
			&transaction
		),
		Ok(false)
	);
	assert_eq!(reload(&node).unwrap().payments()[0].status, Status::Confirmed);
}

#[test]
fn completed_history_exceeds_request_journal_limit_without_retaining_secrets() {
	let node = node();
	let mut ids = Vec::new();
	for _ in 0..MAX_RECORDS + 2 {
		let (id, mut session, _) = fixture(&node, true);
		session.mempool_seen = true;
		session.confirmed = true;
		save(&node, &id, session);
		expire(&node, &id);
		ids.push(id);
	}
	let receiver = &node.direct_funding.receiver;
	receiver.archive_expired(now_ms()).unwrap();
	assert!(receiver.state.lock().unwrap().requests.is_empty());
	assert_eq!(receiver.payments().len(), MAX_RECORDS + 2);
	assert_eq!(reload(&node).unwrap().payments().len(), MAX_RECORDS + 2);
	assert!(receiver.mint(Some(20_000), 60, "localhost".to_owned(), 9735).is_ok());
	assert_eq!(receiver.invalidate(&ids[0]), Err(Error::Busy));
	let bytes = KVStoreSync::read(&*node.kv_store, NAMESPACE, HISTORY_NAMESPACE, &ids[0]).unwrap();
	let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
	assert_eq!(json.as_object().unwrap().len(), 6);
	for secret in ["secret", "preimage", "witness", "offer", "sign_request", "route"] {
		assert!(json.get(secret).is_none());
	}
}

#[test]
fn archive_before_journal_removal_is_deduplicated_after_restart() {
	let node = node();
	let (id, mut session, _) = fixture(&node, true);
	session.mempool_seen = true;
	session.confirmed = true;
	save(&node, &id, session);
	expire(&node, &id);
	let before = KVStoreSync::read(&*node.kv_store, NAMESPACE, "", STORE_KEY).unwrap();
	node.direct_funding.receiver.archive_expired(now_ms()).unwrap();
	// Simulate a crash after the archive write and before removing the journal entry.
	KVStoreSync::write(&*node.kv_store, NAMESPACE, "", STORE_KEY, before).unwrap();
	let restored = reload(&node).unwrap();
	assert_eq!(restored.payments().len(), 1);
	restored.archive_expired(now_ms()).unwrap();
	assert!(restored.state.lock().unwrap().requests.is_empty());
	assert_eq!(reload(&node).unwrap().payments().len(), 1);
}

#[test]
fn existing_offer_replay_uses_stored_primary_after_configuration_change() {
	let node = node();
	let (id, session, _) = fixture(&node, true);
	save(&node, &id, session.clone());
	let mut restored = reload(&node).unwrap();
	let mut config = (*node.config).clone();
	config.primary_node_id = Some(key(12).1);
	restored.config = Arc::new(config);
	let record = restored.state.lock().unwrap().requests[&id].clone();
	let envelope = restored.envelope(&record).unwrap();
	let keys = crypto::sender_lane_keys(&key(8).0, &envelope.encryption_key, &envelope.request_id);
	let payload = crypto::seal_frame(
		&keys.send_key,
		&envelope.request_id,
		codec::OFFER,
		&session.offer,
		Some(key(8).1),
	)
	.unwrap();
	node.runtime.block_on(restored.handle(Inbound {
		route: session.route.route().unwrap(),
		subtype: codec::OFFER,
		payload,
	}));
	let messages = restored.transport.take_messages();
	assert_eq!(messages.len(), 2); // acknowledgment and the identical signing request
	assert!(messages.iter().all(|(peer, _)| *peer == key(2).1));
	assert!(restored.has_pending());
}
