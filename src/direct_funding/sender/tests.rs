use super::*;
use bitcoin::{absolute, transaction, Sequence, TxIn};
use lightning::chain::Listen;
use lightning::util::persist::KVStore;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};

fn key(byte: u8) -> (SecretKey, PublicKey) {
	let secret = SecretKey::from_slice(&[byte; 32]).unwrap();
	(secret, PublicKey::from_secret_key(&Secp256k1::new(), &secret))
}
fn request_envelope(receiver: &SecretKey, amount: Option<u64>) -> RequestEnvelope {
	let mut env = RequestEnvelope {
		request_id: [7; 16],
		chain_hash: bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest)
			.block_hash()
			.to_byte_array(),
		receiver_node_id: PublicKey::from_secret_key(&Secp256k1::new(), receiver),
		expires_at: now_ms() + 60_000,
		amount_sat: amount,
		receipt_hash: sha256::Hash::hash(&[9; 32]).to_byte_array(),
		encryption_key: key(3).1,
		transports: vec![codec::TransportDescriptor::DirectPeer {
			host: "localhost".to_owned(),
			port: 9735,
		}],
		signature: [0; 65],
		signed_bytes: vec![],
	};
	let message = env.prepare_signature(now_ms()).unwrap();
	env.signature = crypto::sign_message(&message, receiver);
	env
}
fn fixture(splice: bool) -> (Offer, Vec<u8>, RequestEnvelope, SignRequest, SecretKey) {
	let (receiver, local) = key(1);
	let remote = key(2).1;
	let script = ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([4; 20])).to_bytes();
	let env = request_envelope(&receiver, Some(20_000));
	let offer = Offer {
		offer_id: [5; 16],
		amount_sat: 20_000,
		txid: [6; 32],
		vout: 1,
		value_sat: 100_000,
		sequence: PAYER_SEQUENCE,
		change_script: ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([8; 20]))
			.to_bytes(),
		max_total_fee_sat: 1_000,
		receipt_hash: env.receipt_hash,
		ownership: OwnershipProof {
			pubkey: local.serialize().to_vec(),
			signature: [0; 64],
			message_proof: None,
			probe_proof: None,
		},
	};
	let funding_script = make_funding_redeemscript(&local, &remote).to_p2wsh();
	let mut tx = Transaction {
		version: transaction::Version::TWO,
		lock_time: absolute::LockTime::ZERO,
		input: vec![TxIn {
			previous_output: offer.outpoint(),
			sequence: Sequence(PAYER_SEQUENCE),
			..Default::default()
		}],
		output: vec![
			TxOut {
				value: Amount::from_sat(if splice { 220_000 } else { 20_000 }),
				script_pubkey: funding_script.clone(),
			},
			TxOut {
				value: Amount::from_sat(79_000),
				script_pubkey: ScriptBuf::from_bytes(offer.change_script.clone()),
			},
		],
	};
	let mut prevouts = vec![codec::Prevout { value_sat: offer.value_sat, script: script.clone() }];
	if splice {
		tx.input.push(TxIn {
			previous_output: OutPoint { txid: Txid::from_byte_array([10; 32]), vout: 0 },
			sequence: Sequence(PAYER_SEQUENCE),
			..Default::default()
		});
		prevouts.push(codec::Prevout { value_sat: 200_000, script: funding_script.to_bytes() });
	}
	let mut req = SignRequest {
		offer_id: offer.offer_id,
		raw_tx: bitcoin::consensus::serialize(&tx),
		prevouts,
		attestation: codec::Attestation {
			funding_output_index: 0,
			local_funding_pubkey: local,
			remote_funding_pubkey: remote,
			prior_funding_pubkeys: None,
			signature: [0; 65],
		},
		shared_input_index: splice.then_some(1),
	};
	resign(&mut req, &receiver);
	(offer, script, env, req, receiver)
}
fn resign(request: &mut SignRequest, secret: &SecretKey) {
	request.attestation.signature =
		crypto::sign_message(&request.attestation_message().unwrap(), secret);
}
fn mutate_tx(request: &mut SignRequest, secret: &SecretKey, f: impl FnOnce(&mut Transaction)) {
	let mut tx = request.transaction().unwrap();
	f(&mut tx);
	request.raw_tx = bitcoin::consensus::serialize(&tx);
	resign(request, secret);
}
fn verdict(
	offer: &Offer, script: &[u8], env: &RequestEnvelope, request: &SignRequest,
) -> Result<Verified, Error> {
	verify_sign_request(offer, script, env, request, 100, |_| false)
}

#[test]
fn accepts_open_and_splice_and_binds_exact_payer_fee() {
	for splice in [false, true] {
		let (offer, script, env, request, _) = fixture(splice);
		assert_eq!(verdict(&offer, &script, &env, &request).unwrap().fee_sats, 1000);
	}
}
#[test]
fn refuses_fee_theft_even_with_a_valid_receiver_attestation() {
	let (offer, script, env, mut request, receiver) = fixture(true);
	mutate_tx(&mut request, &receiver, |tx| tx.output[1].value = Amount::from_sat(78_999));
	assert!(matches!(verdict(&offer, &script, &env, &request), Err(Error::InvalidFunding)));
}
#[test]
fn refuses_splice_that_does_not_preserve_existing_capacity() {
	let (offer, script, env, mut request, receiver) = fixture(true);
	mutate_tx(&mut request, &receiver, |tx| tx.output[0].value = Amount::from_sat(218_999));
	assert!(verdict(&offer, &script, &env, &request).is_err());
}
#[test]
fn refuses_foreign_attestation_wrong_funding_output_and_second_wallet_coin() {
	let (offer, script, env, mut request, receiver) = fixture(true);
	resign(&mut request, &key(12).0);
	assert!(verdict(&offer, &script, &env, &request).is_err());
	resign(&mut request, &receiver);
	let shared = request.transaction().unwrap().input[1].previous_output;
	assert!(verify_sign_request(&offer, &script, &env, &request, 100, |outpoint| outpoint
		== shared)
	.is_err());
	mutate_tx(&mut request, &receiver, |tx| tx.output[0].script_pubkey = ScriptBuf::new());
	assert!(verdict(&offer, &script, &env, &request).is_err());
}
#[test]
fn refuses_duplicate_input_changed_sequence_and_future_locktime() {
	for case in 0..4 {
		let (offer, script, env, mut request, receiver) = fixture(false);
		mutate_tx(&mut request, &receiver, |tx| match case {
			0 => tx.input.push(tx.input[0].clone()),
			1 => tx.input[0].sequence = Sequence::MAX,
			2 => tx.lock_time = absolute::LockTime::from_consensus(245),
			_ => tx.lock_time = absolute::LockTime::from_consensus(500_000_000),
		});
		if case == 0 {
			request.prevouts.push(request.prevouts[0].clone());
		}
		assert!(verdict(&offer, &script, &env, &request).is_err());
	}
}
#[test]
fn refuses_fabricated_payer_prevout_and_wrong_offer() {
	let (offer, script, env, mut request, _) = fixture(false);
	request.prevouts[0].value_sat += 1;
	assert!(verdict(&offer, &script, &env, &request).is_err());
	request.prevouts[0].value_sat -= 1;
	request.offer_id = [0; 16];
	assert!(verdict(&offer, &script, &env, &request).is_err());
}
#[test]
fn accepts_rotated_splice_keys_only_with_signed_prior_keys() {
	let (offer, script, env, mut request, receiver) = fixture(true);
	let prior = codec::FundingPubkeys { local: key(13).1, remote: key(14).1 };
	request.prevouts[1].script =
		make_funding_redeemscript(&prior.local, &prior.remote).to_p2wsh().to_bytes();
	request.attestation.prior_funding_pubkeys = Some(prior);
	assert!(verdict(&offer, &script, &env, &request).is_err());
	resign(&mut request, &receiver);
	assert!(verdict(&offer, &script, &env, &request).is_ok());
}
#[test]
fn amountless_and_fixed_requests_have_exact_amount_rules() {
	assert_eq!(resolve_amount(None, None).unwrap(), None);
	assert_eq!(resolve_amount(None, Some(50)).unwrap(), Some(50));
	assert_eq!(resolve_amount(Some(50), None).unwrap(), Some(50));
	for invalid in [0, 51, u64::MAX] {
		assert_eq!(resolve_amount(Some(50), Some(invalid)), Err(Error::AmountMismatch));
	}
}

#[test]
fn splice_accepts_existing_shared_witness_but_refuses_a_payer_witness_before_signing() {
	let (offer, script, env, mut request, receiver) = fixture(true);
	mutate_tx(&mut request, &receiver, |tx| tx.input[1].witness.push([42; 64]));
	assert!(verdict(&offer, &script, &env, &request).is_ok());
	mutate_tx(&mut request, &receiver, |tx| tx.input[0].witness.push([42; 64]));
	assert!(verdict(&offer, &script, &env, &request).is_err());
}

#[cfg(not(feature = "uniffi"))]
struct Fixture {
	node: crate::Node,
	sender: Sender,
}
#[cfg(not(feature = "uniffi"))]
impl Fixture {
	fn new(address_type: crate::config::AddressType, value: u64) -> Self {
		let config = Config {
			storage_dir_path: std::env::temp_dir()
				.join(format!("ldk-df-sender-test-{}", rand::random::<u64>()))
				.to_str()
				.unwrap()
				.to_owned(),
			network: bitcoin::Network::Regtest,
			address_type,
			..Default::default()
		};
		let mut builder = crate::Builder::from_config(config);
		builder.set_chain_source_esplora(
			"http://127.0.0.1:1".to_owned(),
			Some(crate::config::EsploraSyncConfig { background_sync_config: None }),
		);
		let node = builder.build().unwrap();
		let address = node.wallet.get_new_address().unwrap();
		let tx = Transaction {
			version: transaction::Version::TWO,
			lock_time: absolute::LockTime::ZERO,
			input: vec![TxIn {
				previous_output: OutPoint { txid: Txid::from_byte_array([42; 32]), vout: 0 },
				..Default::default()
			}],
			output: vec![TxOut {
				value: Amount::from_sat(value),
				script_pubkey: address.script_pubkey(),
			}],
		};
		let mut block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
		block.header.prev_blockhash = block.block_hash();
		block.header.time += 1;
		block.header.nonce += 1;
		block.txdata = vec![tx];
		block.header.merkle_root = block.compute_merkle_root().unwrap();
		node.wallet.block_connected(&block, 1);
		let sender = Self::sender(&node);
		Self { node, sender }
	}
	fn sender(node: &crate::Node) -> Sender {
		Sender::new(
			node.wallet.clone(),
			node.chain_source.clone(),
			node.kv_store.clone(),
			node.config.clone(),
			node.channel_manager.clone(),
		)
		.unwrap()
	}
	fn begin(&self) -> (RequestEnvelope, Record) {
		let envelope = request_envelope(&key(1).0, Some(20_000));
		let encoded = envelope.encode().unwrap();
		let record = self.sender.begin(&encoded, &envelope, 20_000, 1000).unwrap();
		(envelope, record)
	}
	fn commit(&self) -> (RequestEnvelope, Record, SignRequest) {
		let (env, record) = self.begin();
		let offer = record.offer().unwrap();
		let request = funding_request(&offer, &record.coin_script);
		let verified = verdict(&offer, &record.coin_script, &env, &request).unwrap();
		let signed = self
			.node
			.wallet
			.sign_direct_funding_input(
				&record.request_id,
				offer.outpoint(),
				verified.tx.clone(),
				&verified.prevouts,
			)
			.unwrap();
		let witness =
			Witness { offer_id: offer.offer_id, witness: signed.to_vec() }.encode().unwrap();
		self.sender.commit(&record.request_id, &request, &verified, witness).unwrap();
		let committed = self.sender.record(&record.request_id).unwrap();
		(env, committed, request)
	}
}

fn funding_request(offer: &Offer, coin_script: &[u8]) -> SignRequest {
	let (receiver, local) = key(1);
	let remote = key(2).1;
	let tx = Transaction {
		version: transaction::Version::TWO,
		lock_time: absolute::LockTime::ZERO,
		input: vec![TxIn {
			previous_output: offer.outpoint(),
			sequence: Sequence(PAYER_SEQUENCE),
			..Default::default()
		}],
		output: vec![
			TxOut {
				value: Amount::from_sat(offer.amount_sat),
				script_pubkey: make_funding_redeemscript(&local, &remote).to_p2wsh(),
			},
			TxOut {
				value: Amount::from_sat(offer.value_sat - offer.amount_sat - 1000),
				script_pubkey: ScriptBuf::from_bytes(offer.change_script.clone()),
			},
		],
	};
	let mut request = SignRequest {
		offer_id: offer.offer_id,
		raw_tx: bitcoin::consensus::serialize(&tx),
		prevouts: vec![codec::Prevout { value_sat: offer.value_sat, script: coin_script.to_vec() }],
		attestation: codec::Attestation {
			funding_output_index: 0,
			local_funding_pubkey: local,
			remote_funding_pubkey: remote,
			prior_funding_pubkeys: None,
			signature: [0; 65],
		},
		shared_input_index: None,
	};
	resign(&mut request, &receiver);
	request
}

/// Authenticated peer which audits the durable store exactly when a witness would leave.
struct TestTransport {
	incoming: VecDeque<(u16, Vec<u8>)>,
	sent: Mutex<Vec<(u16, Vec<u8>)>>,
	keys: LaneKeys,
	envelope: RequestEnvelope,
	store: Arc<DynStore>,
	fail_witness: bool,
}
impl TestTransport {
	fn new(envelope: RequestEnvelope, record: &Record, store: Arc<DynStore>) -> Self {
		let ephemeral = PublicKey::from_secret_key(
			&Secp256k1::new(),
			&SecretKey::from_slice(&record.ephemeral_secret).unwrap(),
		);
		let keys = crypto::receiver_lane_keys(&key(3).0, &ephemeral, &envelope.request_id);
		Self {
			incoming: VecDeque::new(),
			sent: Mutex::new(Vec::new()),
			keys,
			envelope,
			store,
			fail_witness: false,
		}
	}
	fn queue(&mut self, subtype: u16, bytes: Vec<u8>) {
		let sealed = crypto::seal_frame(
			&self.keys.send_key,
			&self.envelope.request_id,
			subtype,
			&bytes,
			None,
		)
		.unwrap();
		self.incoming.push_back((subtype, sealed));
	}
	fn sent_count(&self, subtype: u16) -> usize {
		self.sent.lock().unwrap().iter().filter(|(kind, _)| *kind == subtype).count()
	}
}
impl SenderTransport for TestTransport {
	fn send(&self, subtype: u16, sealed: Vec<u8>) -> Result<(), Error> {
		let frame = crypto::decode_frame(&sealed).unwrap();
		let plain =
			crypto::open_frame(&self.keys.recv_key, &self.envelope.request_id, subtype, &frame)
				.unwrap();
		if subtype == codec::WITNESS {
			let bytes = KVStoreSync::read(&*self.store, STORE_NAMESPACE, "", STORE_KEY).unwrap();
			let records: Vec<Record> = serde_json::from_slice(&bytes).unwrap();
			let record = records
				.iter()
				.find(|record| record.request_id == codec::hex(&self.envelope.request_id))
				.unwrap();
			assert!(
				record.status.committed(),
				"witness must never leave before journal commitment"
			);
			assert_eq!(record.witness.as_ref(), Some(&plain));
			if self.fail_witness {
				return Err(Error::Unavailable);
			}
		}
		self.sent.lock().unwrap().push((subtype, plain));
		Ok(())
	}
	fn receive<'a>(
		&'a mut self,
	) -> Pin<Box<dyn Future<Output = Option<(u16, Vec<u8>)>> + Send + 'a>> {
		Box::pin(async move { self.incoming.pop_front() })
	}
}

#[cfg(not(feature = "uniffi"))]
#[tokio::test(flavor = "multi_thread")]
async fn committed_restart_replays_exact_witness_and_retains_coin_after_disconnect() {
	for address_type in
		[crate::config::AddressType::NativeSegwit, crate::config::AddressType::Taproot]
	{
		let f = Fixture::new(address_type, 100_000);
		let (env, record, request) = f.commit();
		let restarted = Fixture::sender(&f.node);
		let mut transport = TestTransport::new(env, &record, f.node.kv_store.clone());
		transport.queue(codec::SIGN_REQUEST, request.encode().unwrap());
		let result = restarted.send(&record.request, None, 1000, &mut transport).await.unwrap();
		assert_eq!(result.status, SenderPaymentStatus::SignedPending);
		assert!(result.caveat.is_some());
		assert_eq!(transport.sent_count(codec::WITNESS), 1);
		assert!(f.node.wallet.get_spendable_utxos(&f.node.channel_manager).unwrap().is_empty());
		assert_eq!(restarted.record(&record.request_id).unwrap().witness, record.witness);
	}
}

#[cfg(not(feature = "uniffi"))]
#[tokio::test(flavor = "multi_thread")]
async fn committed_request_never_signs_changed_transaction_and_returns_pending() {
	let f = Fixture::new(crate::config::AddressType::NativeSegwit, 100_000);
	let (env, record, mut request) = f.commit();
	mutate_tx(&mut request, &key(1).0, |tx| tx.output[1].value -= Amount::from_sat(1));
	let mut transport = TestTransport::new(env, &record, f.node.kv_store.clone());
	transport.queue(codec::SIGN_REQUEST, request.encode().unwrap());
	let result = f.sender.send(&record.request, Some(1), 1000, &mut transport).await.unwrap();
	assert_eq!(result.status, SenderPaymentStatus::SignedPending);
	assert_eq!(result.amount_sats, 20_000, "committed amount cannot be edited on retry");
	assert_eq!(transport.sent_count(codec::WITNESS), 0);
	assert_eq!(f.sender.record(&record.request_id).unwrap().witness, record.witness);
}

#[cfg(not(feature = "uniffi"))]
#[tokio::test(flavor = "multi_thread")]
async fn resumed_offer_obeys_a_lower_fee_ceiling_before_committing() {
	let f = Fixture::new(crate::config::AddressType::NativeSegwit, 100_000);
	let (env, record) = f.begin();
	let request = funding_request(&record.offer().unwrap(), &record.coin_script);
	let mut transport = TestTransport::new(env, &record, f.node.kv_store.clone());
	transport.queue(codec::SIGN_REQUEST, request.encode().unwrap());
	assert!(matches!(
		f.sender.send(&record.request, None, 999, &mut transport).await,
		Err(Error::InvalidFunding)
	));
	assert_eq!(transport.sent_count(codec::WITNESS), 0);
	let aborted = f.sender.record(&record.request_id).unwrap();
	assert_eq!(aborted.status, SenderPaymentStatus::Aborted);
	assert!(aborted.witness.is_none());
	assert_eq!(f.node.wallet.get_spendable_utxos(&f.node.channel_manager).unwrap().len(), 1);
}

#[cfg(not(feature = "uniffi"))]
#[tokio::test(flavor = "multi_thread")]
async fn native_wallet_signs_splice_with_peer_witness_and_replays_after_peer_witness_changes() {
	for address_type in
		[crate::config::AddressType::NativeSegwit, crate::config::AddressType::Taproot]
	{
		let f = Fixture::new(address_type, 100_000);
		let (env, record) = f.begin();
		let offer = record.offer().unwrap();
		let mut request = funding_request(&offer, &record.coin_script);
		let shared_script = request.transaction().unwrap().output[0].script_pubkey.to_bytes();
		mutate_tx(&mut request, &key(1).0, |tx| {
			tx.input.push(TxIn {
				previous_output: OutPoint { txid: Txid::from_byte_array([55; 32]), vout: 0 },
				sequence: Sequence(PAYER_SEQUENCE),
				witness: bitcoin::Witness::from_slice(&[vec![42; 64]]),
				..Default::default()
			});
			tx.output[0].value += Amount::from_sat(200_000);
		});
		request.prevouts.push(codec::Prevout { value_sat: 200_000, script: shared_script });
		request.shared_input_index = Some(1);
		resign(&mut request, &key(1).0);
		let verified = verdict(&offer, &record.coin_script, &env, &request).unwrap();
		let signed = f
			.node
			.wallet
			.sign_direct_funding_input(
				&record.request_id,
				offer.outpoint(),
				verified.tx.clone(),
				&verified.prevouts,
			)
			.unwrap();
		let witness =
			Witness { offer_id: offer.offer_id, witness: signed.to_vec() }.encode().unwrap();
		f.sender.commit(&record.request_id, &request, &verified, witness.clone()).unwrap();
		let restarted = Fixture::sender(&f.node);
		mutate_tx(&mut request, &key(1).0, |tx| {
			tx.input[1].witness.clear();
			tx.input[1].witness.push([43; 64]);
		});
		let mut transport = TestTransport::new(env, &record, f.node.kv_store.clone());
		transport.queue(codec::SIGN_REQUEST, request.encode().unwrap());
		let result = restarted.send(&record.request, None, 1000, &mut transport).await.unwrap();
		assert_eq!(result.status, SenderPaymentStatus::SignedPending);
		assert_eq!(transport.sent_count(codec::WITNESS), 1);
		assert_eq!(restarted.record(&record.request_id).unwrap().witness, Some(witness));
	}
}

#[cfg(not(feature = "uniffi"))]
#[test]
fn retention_evicts_only_expired_terminal_requests_and_preserves_live_reservations() {
	let f = Fixture::new(crate::config::AddressType::NativeSegwit, 100_000);
	let (env, live) = f.begin();
	let mut expired_request = String::new();
	{
		let mut state = f.sender.state.lock().unwrap();
		for index in 1..MAX_RECORDS {
			let mut envelope = env.clone();
			envelope.request_id[..8].copy_from_slice(&(index as u64).to_be_bytes());
			envelope.expires_at = now_ms() - 1;
			let message = envelope.prepare_signature(now_ms() - 60_000).unwrap();
			envelope.signature = crypto::sign_message(&message, &key(1).0);
			let mut record = live.clone();
			record.request_id = codec::hex(&envelope.request_id);
			record.request = envelope.encode().unwrap();
			record.status = SenderPaymentStatus::Aborted;
			record.created_at = now_ms().saturating_sub(RETENTION_MS + 1);
			expired_request = record.request.clone();
			state.records.insert(record.request_id.clone(), record);
		}
	}
	f.sender.make_record_room().unwrap();
	assert_eq!(f.sender.list().len(), 1);
	assert!(f.sender.record(&live.request_id).is_some());
	assert!(matches!(f.sender.prepare(&expired_request, None), Err(Error::Expired)));
	assert!(f.node.wallet.get_spendable_utxos(&f.node.channel_manager).unwrap().is_empty());
	assert_eq!(Fixture::sender(&f.node).list().len(), 1);
}

#[cfg(not(feature = "uniffi"))]
#[tokio::test(flavor = "multi_thread")]
async fn receipt_is_verified_but_never_substitutes_for_chain_confirmation() {
	for valid in [false, true] {
		let f = Fixture::new(crate::config::AddressType::NativeSegwit, 100_000);
		let (env, record, request) = f.commit();
		let mut transport = TestTransport::new(env, &record, f.node.kv_store.clone());
		transport.queue(
			codec::RECEIPT,
			Receipt {
				offer_id: record.offer().unwrap().offer_id,
				preimage: [if valid { 9 } else { 8 }; 32],
				funding_txid: codec::txid_to_display(request.transaction().unwrap().compute_txid()),
				raw_tx: None,
			}
			.encode()
			.unwrap(),
		);
		let result = f.sender.send(&record.request, None, 1000, &mut transport).await.unwrap();
		assert_eq!(result.status, SenderPaymentStatus::SignedPending);
		assert_eq!(f.sender.record(&record.request_id).unwrap().receipt_preimage.is_some(), valid);
		assert_eq!(
			Fixture::sender(&f.node).record(&record.request_id).unwrap().receipt_preimage.is_some(),
			valid
		);
		assert!(f.node.wallet.get_spendable_utxos(&f.node.channel_manager).unwrap().is_empty());
	}
}

#[cfg(not(feature = "uniffi"))]
#[test]
fn corrupt_committed_signature_or_fee_fails_closed_on_restart() {
	let f = Fixture::new(crate::config::AddressType::NativeSegwit, 100_000);
	let (_, record, _) = f.commit();
	validate_record(&record, &f.sender.chain_hash).unwrap();
	let mut altered = record.clone();
	altered.fee_sats = Some(999);
	assert_eq!(validate_record(&altered, &f.sender.chain_hash), Err(Error::PersistenceFailed));
	let mut witness = Witness::decode(record.witness.as_ref().unwrap()).unwrap();
	witness.witness[0][10] ^= 1;
	altered = record;
	altered.witness = Some(witness.encode().unwrap());
	assert_eq!(validate_record(&altered, &f.sender.chain_hash), Err(Error::PersistenceFailed));
}

struct FaultStore {
	inner: Arc<DynStore>,
	fail_write: AtomicBool,
}
impl KVStoreSync for FaultStore {
	fn read(&self, primary: &str, secondary: &str, key: &str) -> lightning::io::Result<Vec<u8>> {
		KVStoreSync::read(&*self.inner, primary, secondary, key)
	}
	fn write(
		&self, primary: &str, secondary: &str, key: &str, bytes: Vec<u8>,
	) -> lightning::io::Result<()> {
		if self.fail_write.load(Ordering::SeqCst) {
			return Err(lightning::io::Error::new(ErrorKind::Other, "injected journal failure"));
		}
		KVStoreSync::write(&*self.inner, primary, secondary, key, bytes)
	}
	fn remove(
		&self, primary: &str, secondary: &str, key: &str, lazy: bool,
	) -> lightning::io::Result<()> {
		KVStoreSync::remove(&*self.inner, primary, secondary, key, lazy)
	}
	fn list(&self, primary: &str, secondary: &str) -> lightning::io::Result<Vec<String>> {
		KVStoreSync::list(&*self.inner, primary, secondary)
	}
}
type StoreFuture<T> = Pin<Box<dyn Future<Output = lightning::io::Result<T>> + Send + 'static>>;
impl KVStore for FaultStore {
	fn read(&self, p: &str, s: &str, k: &str) -> StoreFuture<Vec<u8>> {
		let result = KVStoreSync::read(self, p, s, k);
		Box::pin(async move { result })
	}
	fn write(&self, p: &str, s: &str, k: &str, bytes: Vec<u8>) -> StoreFuture<()> {
		let result = KVStoreSync::write(self, p, s, k, bytes);
		Box::pin(async move { result })
	}
	fn remove(&self, p: &str, s: &str, k: &str, lazy: bool) -> StoreFuture<()> {
		let result = KVStoreSync::remove(self, p, s, k, lazy);
		Box::pin(async move { result })
	}
	fn list(&self, p: &str, s: &str) -> StoreFuture<Vec<String>> {
		let result = KVStoreSync::list(self, p, s);
		Box::pin(async move { result })
	}
}

#[cfg(not(feature = "uniffi"))]
#[tokio::test(flavor = "multi_thread")]
async fn failed_commit_write_never_releases_witness_even_on_retry() {
	let mut f = Fixture::new(crate::config::AddressType::NativeSegwit, 100_000);
	let (env, record) = f.begin();
	let store =
		Arc::new(FaultStore { inner: f.node.kv_store.clone(), fail_write: AtomicBool::new(true) });
	f.sender.store = store;
	let offer = record.offer().unwrap();
	let request = funding_request(&offer, &record.coin_script);
	let verified = verdict(&offer, &record.coin_script, &env, &request).unwrap();
	let signature = f
		.node
		.wallet
		.sign_direct_funding_input(
			&record.request_id,
			offer.outpoint(),
			verified.tx.clone(),
			&verified.prevouts,
		)
		.unwrap();
	let witness =
		Witness { offer_id: offer.offer_id, witness: signature.to_vec() }.encode().unwrap();
	assert_eq!(
		f.sender.commit(&record.request_id, &request, &verified, witness),
		Err(Error::PersistenceFailed)
	);
	let mut transport = TestTransport::new(env, &record, f.node.kv_store.clone());
	transport.queue(codec::SIGN_REQUEST, request.encode().unwrap());
	let result = f.sender.send(&record.request, None, 1000, &mut transport).await.unwrap();
	assert_eq!(result.status, SenderPaymentStatus::SignedPending);
	assert!(result.caveat.is_some());
	assert_eq!(transport.sent_count(codec::OFFER), 0);
	assert_eq!(transport.sent_count(codec::WITNESS), 0);
	assert_eq!(Fixture::sender(&f.node).list()[0].status, SenderPaymentStatus::Offered);
	assert!(f.node.wallet.get_spendable_utxos(&f.node.channel_manager).unwrap().is_empty());
}

#[cfg(not(feature = "uniffi"))]
#[tokio::test(flavor = "multi_thread")]
async fn postcommit_transport_or_storage_failure_returns_existing_payment() {
	for storage_failure in [false, true] {
		let mut f = Fixture::new(crate::config::AddressType::NativeSegwit, 100_000);
		let (env, record, request) = f.commit();
		let mut transport = TestTransport::new(env, &record, f.node.kv_store.clone());
		if storage_failure {
			f.sender.store = Arc::new(FaultStore {
				inner: f.node.kv_store.clone(),
				fail_write: AtomicBool::new(true),
			});
			transport.queue(
				codec::RECEIPT,
				Receipt {
					offer_id: record.offer().unwrap().offer_id,
					preimage: [9; 32],
					funding_txid: codec::txid_to_display(
						request.transaction().unwrap().compute_txid(),
					),
					raw_tx: None,
				}
				.encode()
				.unwrap(),
			);
		} else {
			transport.fail_witness = true;
			transport.queue(codec::SIGN_REQUEST, request.encode().unwrap());
		}
		let result = f.sender.send(&record.request, None, 1000, &mut transport).await.unwrap();
		assert_eq!(result.status, SenderPaymentStatus::SignedPending);
		assert!(result.caveat.is_some());
		assert_eq!(result.funding_txid, record.funding_txid);
		assert!(f.node.wallet.get_spendable_utxos(&f.node.channel_manager).unwrap().is_empty());
		assert_eq!(Fixture::sender(&f.node).list()[0].status, SenderPaymentStatus::SignedPending);
	}
}
#[cfg(not(feature = "uniffi"))]
#[test]
fn native_wallet_ownership_proofs_work_for_segwit_and_large_taproot_coins() {
	for address_type in
		[crate::config::AddressType::NativeSegwit, crate::config::AddressType::Taproot]
	{
		let f = Fixture::new(address_type, 100_000_000);
		let (envelope, record) = f.begin();
		assert!(crypto::verify_ownership(
			&record.offer().unwrap(),
			&record.coin_script,
			&envelope.receiver_node_id
		));
		validate_record(&record, &f.sender.chain_hash).unwrap();
		assert!(f.node.wallet.get_spendable_utxos(&f.node.channel_manager).unwrap().is_empty());
		let restored = Fixture::sender(&f.node);
		assert_eq!(restored.list().len(), 1);
		assert!(f.node.wallet.get_spendable_utxos(&f.node.channel_manager).unwrap().is_empty());
		assert_eq!(
			restored.record(&record.request_id).unwrap().ephemeral_secret,
			record.ephemeral_secret
		);
	}
}
#[cfg(not(feature = "uniffi"))]
#[test]
fn corrupt_store_fails_closed_instead_of_forgetting_reserved_coin() {
	let f = Fixture::new(crate::config::AddressType::NativeSegwit, 100_000);
	f.begin();
	KVStoreSync::write(&*f.node.kv_store, STORE_NAMESPACE, "", STORE_KEY, b"corrupt".to_vec())
		.unwrap();
	assert!(Sender::new(
		f.node.wallet.clone(),
		f.node.chain_source.clone(),
		f.node.kv_store.clone(),
		f.node.config.clone(),
		f.node.channel_manager.clone()
	)
	.is_err());
	assert!(f.node.wallet.get_spendable_utxos(&f.node.channel_manager).unwrap().is_empty());
}
#[cfg(not(feature = "uniffi"))]
#[test]
fn proven_prewitness_abort_persists_before_releasing_coin() {
	let f = Fixture::new(crate::config::AddressType::NativeSegwit, 100_000);
	let (_, record) = f.begin();
	f.sender.abort(&record.request_id, Error::Declined).unwrap();
	assert_eq!(Fixture::sender(&f.node).list()[0].status, SenderPaymentStatus::Aborted);
	assert_eq!(f.node.wallet.get_spendable_utxos(&f.node.channel_manager).unwrap().len(), 1);
}
