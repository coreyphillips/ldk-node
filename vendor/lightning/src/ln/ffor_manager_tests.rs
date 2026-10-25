use super::*;
use crate::chain::ChannelMonitorUpdateStatus;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::ChannelMessageHandler;
use crate::sign::KeysManager;

#[test]
fn native_ffor_idle_custom_drain_does_not_wake_or_persist() {
	let chanmon_cfgs = create_chanmon_cfgs(1);
	let node_cfgs = create_node_cfgs(1, &chanmon_cfgs);
	let node_chanmgrs = create_node_chanmgrs(1, &node_cfgs, &[None]);
	let nodes = create_network(1, &node_cfgs, &node_chanmgrs);
	for enabled in [false, true] {
		nodes[0].node.set_ffor_policy(FforPolicy { enabled, ..Default::default() }).unwrap();
		nodes[0].node.get_event_or_persistence_needed_future().poll_is_complete();
		nodes[0].node.get_and_clear_needs_persistence();
		for _ in 0..100 {
			assert!(nodes[0].node.get_and_clear_pending_ffor_messages().is_empty());
			assert!(nodes[0].node.get_and_clear_pending_splice_conflict_responses().is_empty());
			assert!(!nodes[0].node.get_event_or_persistence_needed_future().poll_is_complete());
			assert!(!nodes[0].node.get_and_clear_needs_persistence());
		}
	}
}

#[test]
fn native_ffor_sync_without_custody_allocates_no_runtime_state() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut config = test_default_anchors_channel_config();
	config.channel_handshake_config.announce_for_forwarding = false;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_, channel) = open_zero_conf_channel_with_value(&nodes[0], &nodes[1], None, 100_000, 10_000_000);
	let signer = KeysManager::new(&nodes[1].node_seed, 0, 0, true);
	let mut bytes = channel.0.to_vec();
	bytes.extend_from_slice(&[0; 96]);
	let message = ffor::tests::sign_with(ffor::Kind::Sync, &bytes, &signer.get_node_secret_key()).encode();
	assert!(nodes[0].node.handle_ffor_message(&nodes[1].node.get_our_node_id(), ffor::Kind::Sync as u16, &message[2..]).is_err());
	let runtime = nodes[0].node.ffor_runtime.lock().unwrap();
	assert!(runtime.requests.is_empty() && runtime.started.is_empty() && runtime.sync_rate.is_empty());
}

fn send_signed(node: &Node<'_, '_, '_>, peer: PublicKey, message: &ffor::SignedMessage) {
	let bytes = message.encode();
	node.node.handle_ffor_message(&peer, message.kind as u16, &bytes[2..]).unwrap();
}

/// Complete the real BOLT quiescence handshake after the settler requested it.
fn complete_stfu(settler: &Node<'_, '_, '_>, receiver: &Node<'_, '_, '_>) {
	let s = settler.node.get_our_node_id();
	let r = receiver.node.get_our_node_id();
	let request = get_event_msg!(settler, MessageSendEvent::SendStfu, r);
	receiver.node.handle_stfu(s, &request);
	let response = get_event_msg!(receiver, MessageSendEvent::SendStfu, s);
	settler.node.handle_stfu(r, &response);
}

fn exit_receiver_quiescence(receiver: &Node<'_, '_, '_>, settler: &Node<'_, '_, '_>, channel: ChannelId) {
	let peers = receiver.node.per_peer_state.read().unwrap();
	let mut state = peers[&settler.node.get_our_node_id()].lock().unwrap();
	state.channel_by_id.get_mut(&channel).unwrap().as_funded_mut().unwrap().exit_quiescence();
}

#[test]
fn native_ffor_setup_waits_for_monitor_persistence() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut config = test_default_anchors_channel_config();
	config.channel_handshake_config.announce_for_forwarding = false;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	for manager in &node_chanmgrs { manager.set_ffor_policy(FforPolicy { enabled: true, ..Default::default() }).unwrap(); }
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	for node in &nodes { connect_blocks(node, 100); }
	let (_, channel) = open_zero_conf_channel_with_value(&nodes[0], &nodes[1], None, 100_000, 10_000_000);
	let peer = nodes[1].node.get_our_node_id();
	let receiver = KeysManager::new(&nodes[1].node_seed, 0, 0, true);
	let init = ffor::tests::init_for(channel.0, [31; 32], &receiver.get_node_secret_key(),
		nodes[0].best_block_info().1, &[2_000_000], 0, 0);
	assert!(nodes[0].node.supports_ffor_settler(&peer));
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	send_signed(&nodes[0], peer, &init);
	nodes[0].node.ffor_progress();
	check_added_monitors!(nodes[0], 1);
	assert!(nodes[0].node.get_and_clear_pending_ffor_messages().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[0].node.ffor_runtime.lock().unwrap().homes[&channel].durable.is_none());
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	let (latest, _) = nodes[0].chain_monitor.get_latest_mon_update_id(channel);
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(channel, latest);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	let messages = nodes[0].node.get_and_clear_pending_ffor_messages();
	assert_eq!(messages.len(), 1);
	assert_eq!(messages[0].message_type, ffor::Kind::Accept as u16);
	let updates = get_htlc_update_msgs!(nodes[0], peer);
	assert_eq!(updates.update_add_htlcs.len(), 1);
	check_added_monitors!(nodes[0], 1);
	nodes[1].node.handle_update_add_htlc(nodes[0].node.get_our_node_id(), &updates.update_add_htlcs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], updates.commitment_signed, false);
	nodes[1].node.get_and_clear_pending_events();
}

/// Establish an active book using actual native commitments and signed wires.
/// The ordinary native receiver leaves the committed voucher HTLCs parked by
/// not processing its forwarding event. It does not fabricate settler custody.
pub(crate) fn activate_native_book(settler: &Node<'_, '_, '_>, receiver: &Node<'_, '_, '_>,
	channel: ChannelId, amounts: &[u64]) -> FforJournal {
	let s = settler.node.get_our_node_id();
	let r = receiver.node.get_our_node_id();
	let signer = KeysManager::new(&receiver.node_seed, 0, 0, true);
	let height = settler.best_block_info().1;
	let init = ffor::tests::init_for(channel.0, [47; 32], &signer.get_node_secret_key(), height, amounts, 0, 0);
	send_signed(settler, r, &init);
	settler.node.ffor_progress();
	check_added_monitors!(settler, 1);
	let accept = settler.node.get_and_clear_pending_ffor_messages();
	assert_eq!(accept.len(), 1);
	assert_eq!(accept[0].message_type, ffor::Kind::Accept as u16);
	let updates = get_htlc_update_msgs!(settler, r);
	assert_eq!(updates.update_add_htlcs.len(), amounts.len());
	check_added_monitors!(settler, 1);
	for add in &updates.update_add_htlcs { receiver.node.handle_update_add_htlc(s, add); }
	commitment_signed_dance!(receiver, settler, updates.commitment_signed, false);
	receiver.node.get_and_clear_pending_events();
	{
		let peers = settler.node.per_peer_state.read().unwrap();
		let mut state = peers[&r].lock().unwrap();
		let chan = state.channel_by_id.get_mut(&channel).unwrap().as_funded_mut().unwrap();
		let msg = chan.request_ffor_quiescence(&settler.logger).unwrap().unwrap();
		state.pending_msg_events.push(MessageSendEvent::SendStfu { node_id: r, msg });
	}
	complete_stfu(settler, receiver);
	let previous = settler.node.ffor_current(&channel).unwrap();
	let snapshot = {
		let peers = settler.node.per_peer_state.read().unwrap();
		let state = peers[&r].lock().unwrap();
		state.channel_by_id[&channel].as_funded().unwrap()
			.ffor_commitment_snapshot(&previous.epoch, &settler.logger).unwrap()
	};
	let activate = ffor::tests::activate_for(&previous, &snapshot, height, &signer.get_node_secret_key());
	send_signed(settler, r, &activate);
	settler.node.ffor_progress();
	let ack = settler.node.get_and_clear_pending_ffor_messages();
	assert_eq!(ack.len(), 1);
	assert_eq!(ack[0].message_type, ffor::Kind::ActivateAck as u16);
	check_added_monitors!(settler, 3);
	exit_receiver_quiescence(receiver, settler, channel);
	let journal = settler.node.ffor_runtime.lock().unwrap().homes[&channel].durable.clone().unwrap();
	assert_eq!(journal.epoch.phase, ffor::Phase::Active);
	assert!(!journal.epoch.activation_ack_pending);
	journal
}

#[test]
fn native_ffor_vouchers_and_activation() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut config = test_default_anchors_channel_config();
	config.channel_handshake_config.announce_for_forwarding = false;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	for manager in &node_chanmgrs { manager.set_ffor_policy(FforPolicy { enabled: true, ..Default::default() }).unwrap(); }
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	for node in &nodes { connect_blocks(node, 100); }
	let (_, channel) = open_zero_conf_channel_with_value(&nodes[0], &nodes[1], None, 100_000, 10_000_000);
	let journal = activate_native_book(&nodes[0], &nodes[1], channel, &[2_000_000, 2_000_000]);
	assert_eq!(journal.epoch.slots.len(), 2);
	assert!(journal.epoch.slots.iter().all(|slot| slot.state == SlotState::Unused));
}

#[test]
fn native_ffor_redemption_waits_for_native_commitment_persistence() {
	do_redemption(false);
}

#[test]
fn native_ffor_redemption_restart_recovers_finalized_proof() {
	do_redemption(true);
}

fn do_redemption(restart: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut config = test_default_anchors_channel_config();
	config.channel_handshake_config.announce_for_forwarding = false;
	let persister;
	let new_chain_monitor;
	let reloaded;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
	for manager in &node_chanmgrs { manager.set_ffor_policy(FforPolicy { enabled: true, ..Default::default() }).unwrap(); }
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	for node in &nodes { connect_blocks(node, 100); }
	let (_, channel) = open_zero_conf_channel_with_value(&nodes[0], &nodes[1], None, 100_000, 10_000_000);
	let journal = activate_native_book(&nodes[0], &nodes[1], channel, &[2_000_000]);
	let s = nodes[0].node.get_our_node_id();
	let r = nodes[1].node.get_our_node_id();
	let slot = &journal.epoch.slots[0];
	let funding_txo = get_monitor!(nodes[1], channel).get_funding_txo();
	nodes[1].node.claim_mpp_part(HTLCClaimSource { counterparty_node_id: s, funding_txo,
		channel_id: channel, htlc_id: slot.entry.htlc_id }, PaymentPreimage(slot.preimage), None, None, |_, _| (None, None));
	check_added_monitors!(nodes[1], 1);
	let fulfill = get_htlc_update_msgs!(nodes[1], s);
	assert_eq!(fulfill.update_fulfill_htlcs.len(), 1);
	nodes[0].node.handle_update_fulfill_htlc(r, fulfill.update_fulfill_htlcs[0].clone());
	nodes[0].node.ffor_progress();
	assert!(!nodes[0].node.ffor_current(&channel).unwrap().epoch.slots[0].redeemed);
	check_added_monitors!(nodes[0], 0);

	// Withhold the holder commitment that first records the native fulfill.
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[0].node.handle_commitment_signed_batch_test(r, &fulfill.commitment_signed);
	check_added_monitors!(nodes[0], 1);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(!nodes[0].node.ffor_current(&channel).unwrap().epoch.slots[0].redeemed);
	let (update, _) = nodes[0].chain_monitor.get_latest_mon_update_id(channel);
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(channel, update);
	let (extra, final_raa) = do_main_commitment_signed_dance(&nodes[0], &nodes[1], false);
	assert!(extra.is_none());
	assert!(!nodes[0].node.ffor_current(&channel).unwrap().epoch.slots[0].redeemed);

	// Finalization itself also waits for the counterparty revocation monitor.
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[0].node.handle_revoke_and_ack(r, &final_raa);
	check_added_monitors!(nodes[0], 1);
	nodes[0].node.ffor_progress();
	assert!(!nodes[0].node.ffor_current(&channel).unwrap().epoch.slots[0].redeemed);
	if restart {
		// The persister saved the revocation but the process lost its completion
		// notification. Recover the proof from the monitor with admission off.
		let manager = nodes[0].node.encode();
		let monitor = get_monitor!(nodes[0], channel).encode();
		reload_node!(nodes[0], config, &manager, &[&monitor], persister, new_chain_monitor, reloaded);
		assert!(!nodes[0].node.ffor_settler_enabled());
	} else {
		let (update, _) = nodes[0].chain_monitor.get_latest_mon_update_id(channel);
		nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(channel, update);
	}
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	nodes[0].node.ffor_progress();
	let durable = nodes[0].node.ffor_runtime.lock().unwrap().homes[&channel].durable.clone().unwrap();
	assert!(durable.epoch.slots[0].redeemed);
	assert!(durable.epoch.slots[0].removal.as_ref().unwrap().fulfilled);
	assert!(nodes[0].node.settled_ffor_receipts(&r, &channel, &journal.epoch.epoch_id).unwrap().is_empty());
	assert_eq!(nodes[0].node.list_channels()[0].is_usable, !restart);
	nodes[0].chain_monitor.added_monitors.lock().unwrap().clear();
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
}

#[test]
fn native_ffor_chain_resolution_waits_for_custody_journal() {
	use crate::chain::Confirm;
	use crate::chain::channelmonitor::{ChannelMonitorUpdateStep, ANTI_REORG_DELAY};
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut config = test_default_anchors_channel_config();
	config.channel_handshake_config.announce_for_forwarding = false;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	for manager in &node_chanmgrs { manager.set_ffor_policy(FforPolicy { enabled: true, ..Default::default() }).unwrap(); }
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	for node in &nodes { connect_blocks(node, 100); }
	let (funding, channel) = open_zero_conf_channel_with_value(&nodes[0], &nodes[1], None, 100_000, 10_000_000);
	let journal = activate_native_book(&nodes[0], &nodes[1], channel, &[2_000_000]);
	let peer = nodes[1].node.get_our_node_id();
	let commitment = get_local_commitment_txn!(nodes[0], channel).remove(0);
	check_spends!(&commitment, funding);
	let spend = get_monitor!(nodes[0], channel).ffor_test_holder_htlc_transactions().remove(0);
	spend.verify(|outpoint| {
		assert_eq!(outpoint.txid, commitment.compute_txid());
		commitment.output.get(outpoint.vout as usize).cloned()
	}).unwrap();
	nodes[0].node.force_close_broadcasting_latest_txn(&channel, &peer, "test onchain voucher".to_owned()).unwrap();
	nodes[0].node.get_and_clear_pending_msg_events();
	nodes[0].node.get_and_clear_pending_events();
	nodes[0].chain_monitor.added_monitors.lock().unwrap().clear();
	nodes[0].chain_monitor.monitor_updates.lock().unwrap().clear();
	let chain = &nodes[0].chain_monitor.chain_monitor;
	let height = journal.epoch.slots[0].entry.expiry + 1;
	let header = create_dummy_header(nodes[0].best_block_hash(), 17);
	chain.transactions_confirmed(&header, &[(0, &commitment)], height);
	chain.best_block_updated(&header, height);
	let next = create_dummy_header(header.block_hash(), 18);
	chain.transactions_confirmed(&next, &[(0, &spend)], height + 1);
	chain.best_block_updated(&next, height + ANTI_REORG_DELAY - 1);
	nodes[0].node.get_and_clear_pending_msg_events();
	assert!(nodes[0].node.ffor_current(&channel).unwrap().epoch.slots[0].chain_removal.is_none());
	chain.best_block_updated(&next, height + ANTI_REORG_DELAY);
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[0].node.get_and_clear_pending_msg_events();
	let staged = nodes[0].node.ffor_current(&channel).unwrap();
	assert!(staged.epoch.slots[0].chain_removal.is_some());
	assert!(nodes[0].node.ffor_runtime.lock().unwrap().homes[&channel].durable.as_ref().unwrap().epoch.slots[0].chain_removal.is_none());
	assert!(!nodes[0].chain_monitor.monitor_updates.lock().unwrap()[&channel].iter().any(|update|
		update.updates.iter().any(|step| matches!(step, ChannelMonitorUpdateStep::ReleasePaymentComplete { .. }))));
	let (update, _) = nodes[0].chain_monitor.get_latest_mon_update_id(channel);
	chain.force_channel_monitor_updated(channel, update);
	nodes[0].node.get_and_clear_pending_msg_events();
	assert!(nodes[0].node.ffor_runtime.lock().unwrap().homes[&channel].durable.as_ref().unwrap().epoch.slots[0].chain_removal.is_some());
	assert_eq!(nodes[0].chain_monitor.monitor_updates.lock().unwrap()[&channel].iter().flat_map(|update| &update.updates)
		.filter(|step| matches!(step, ChannelMonitorUpdateStep::ReleasePaymentComplete { .. })).count(), 1);
	nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(nodes[0].node.ffor_current(&channel).unwrap().revision, staged.revision);
	nodes[0].chain_monitor.added_monitors.lock().unwrap().clear();
	nodes[0].node.get_and_clear_pending_events();
}

#[test]
fn native_ffor_offline_claim_crosses_three_persistence_barriers() {
	do_offline_claim(false, false, false);
}

#[test]
fn native_ffor_restart_replays_durable_settling() {
	do_offline_claim(true, false, false);
}

#[test]
fn native_ffor_closed_upstream_replay_has_one_pending_claim() {
	do_offline_claim(false, true, false);
}

#[test]
fn native_ffor_restart_after_upstream_splice_preserves_historical_binding() {
	do_offline_claim(true, false, true);
}

fn do_offline_claim(restart: bool, close_upstream: bool, splice_upstream: bool) {
	use crate::routing::router::{Route, RouteHop};
	let chanmon_cfgs = create_chanmon_cfgs(3);
	let node_cfgs = create_node_cfgs(3, &chanmon_cfgs);
	let mut config = test_default_anchors_channel_config();
	config.channel_handshake_config.announce_for_forwarding = false;
	config.accept_forwards_to_priv_channels = true;
	let persister;
	let new_chain_monitor;
	let reloaded;
	let mut payer_config = config.clone();
	payer_config.channel_handshake_config.announce_for_forwarding = splice_upstream;
	let node_chanmgrs = create_node_chanmgrs(3, &node_cfgs, &[Some(payer_config), Some(config.clone()), Some(config.clone())]);
	for manager in &node_chanmgrs { manager.set_ffor_policy(FforPolicy { enabled: true, ..Default::default() }).unwrap(); }
	let mut nodes = create_network(3, &node_cfgs, &node_chanmgrs);
	for node in &nodes { connect_blocks(node, 100); }
	let upstream = if splice_upstream {
		let channel = create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 10_000_000).2;
		let height = nodes[2].best_block_info().1;
		let missing: Vec<_> = nodes[0].blocks.lock().unwrap().iter()
			.filter(|(_, block_height)| *block_height > height).map(|(block, _)| block.clone()).collect();
		for block in missing { connect_block(&nodes[2], &block); }
		channel
	} else {
		open_zero_conf_channel_with_value(&nodes[0], &nodes[1], None, 100_000, 10_000_000).1
	};
	let (_, home) = open_zero_conf_channel_with_value(&nodes[1], &nodes[2], None, 100_000, 10_000_000);
	let journal = activate_native_book(&nodes[1], &nodes[2], home, &[2_000_000]);
	let payer = nodes[0].node.get_our_node_id();
	let settler = nodes[1].node.get_our_node_id();
	let receiver = nodes[2].node.get_our_node_id();
	let first = nodes[0].node.list_channels()[0].get_outbound_payment_scid().unwrap();
	let last = nodes[2].node.list_channels()[0].get_inbound_payment_scid().unwrap();
	let payment_hash = PaymentHash(journal.epoch.slots[0].entry.payment_hash);
	let preimage = PaymentPreimage(journal.epoch.slots[0].preimage);
	nodes[1].node.peer_disconnected(receiver);
	nodes[2].node.peer_disconnected(settler);
	let hop = |pubkey, short_channel_id, fee_msat, cltv_expiry_delta| RouteHop {
		pubkey, node_features: NodeFeatures::empty(), short_channel_id,
		channel_features: ChannelFeatures::empty(), fee_msat, cltv_expiry_delta, maybe_announced_channel: false,
	};
	let route = Route { paths: vec![Path { hops: vec![hop(settler, first, 0, 72), hop(receiver, last, 2_000_000, 72)], blinded_tail: None }], route_params: None };
	nodes[0].node.send_payment_with_route(route, payment_hash, RecipientOnionFields::secret_only(PaymentSecret([77; 32])), PaymentId([78; 32])).unwrap();
	check_added_monitors!(nodes[0], 1);
	let adds = get_htlc_update_msgs!(nodes[0], settler);
	assert_eq!(adds.update_add_htlcs.len(), 1);
	nodes[1].node.handle_update_add_htlc(payer, &adds.update_add_htlcs[0]);
	commitment_signed_dance!(nodes[1], nodes[0], adds.commitment_signed, false);
	for _ in 0..3 { chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress); }
	for _ in 0..2 { if nodes[1].node.needs_pending_htlc_processing() { nodes[1].node.process_pending_htlc_forwards(); } }
	check_added_monitors!(nodes[1], 1);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[1].node.settled_ffor_receipts(&receiver, &home, &journal.epoch.epoch_id).unwrap().is_empty());
	assert_eq!(nodes[1].node.ffor_current(&home).unwrap().epoch.slots[0].state, SlotState::Settling);
	assert_eq!(nodes[1].node.ffor_runtime.lock().unwrap().homes[&home].durable.as_ref().unwrap().epoch.slots[0].state, SlotState::Unused);
	let admitted_upstream = nodes[1].node.ffor_current(&home).unwrap().epoch.slots[0].upstream.clone().unwrap();
	if splice_upstream {
		use crate::events::bump_transaction::sync::WalletSourceSync;
		use crate::ln::funding::{FundingTxInput, SpliceContribution};
		use crate::ln::splicing_tests::{splice_channel, lock_splice_after_blocks};
		chanmon_cfgs[1].persister.update_rets.lock().unwrap().clear();
		let input = provide_anchor_utxo_reserves(&nodes, 1, bitcoin::Amount::from_sat(40_000));
		let contribution = SpliceContribution::SpliceIn {
			value: bitcoin::Amount::from_sat(20_000),
			inputs: vec![FundingTxInput::new_p2wpkh(input, 0).unwrap()],
			change_script: Some(nodes[0].wallet_source.get_change_script().unwrap()),
		};
		nodes[0].tx_broadcaster.txn_broadcast();
		nodes[1].tx_broadcaster.txn_broadcast();
		let candidate = splice_channel(&nodes[0], &nodes[1], upstream, contribution);
		mine_transaction(&nodes[0], &candidate);
		mine_transaction(&nodes[1], &candidate);
		lock_splice_after_blocks(&nodes[0], &nodes[1], 5);
		assert_ne!(get_monitor!(nodes[1], upstream).get_funding_txo(), admitted_upstream.funding_txo);
		assert_eq!(nodes[1].node.ffor_current(&home).unwrap().epoch.slots[0].upstream, Some(admitted_upstream.clone()));
		for _ in 0..2 { chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress); }
	}
	if close_upstream {
		// Closing the upstream cannot undo already admitted home custody. Its
		// preimage now goes directly to the retained native upstream monitor.
		chanmon_cfgs[1].persister.update_rets.lock().unwrap().clear();
		nodes[1].node.force_close_broadcasting_latest_txn(&upstream, &payer, "test pending delegated claim".to_owned()).unwrap();
		nodes[1].node.get_and_clear_pending_msg_events();
		nodes[1].node.get_and_clear_pending_events();
		check_added_monitors!(nodes[1], 1);
		for _ in 0..2 { chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress); }
	}

	// Home SETTLING is durable, then the native upstream preimage update starts.
	let (home_settling, _) = nodes[1].chain_monitor.get_latest_mon_update_id(home);
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(home, home_settling);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	check_added_monitors!(nodes[1], 1);
	for _ in 0..100 { nodes[1].node.replay_ffor_claims(); }
	check_added_monitors!(nodes[1], 0);
	{
		let peers = nodes[1].node.per_peer_state.read().unwrap();
		let state = peers[&payer].lock().unwrap();
		assert_eq!(state.monitor_update_blocked_actions[&upstream].iter()
			.filter(|action| matches!(action, MonitorUpdateCompletionAction::FforUpstreamClaimed { .. })).count(), 1);
	}
	assert!(nodes[1].node.settled_ffor_receipts(&receiver, &home, &journal.epoch.epoch_id).unwrap().is_empty());
	assert_eq!(nodes[1].node.ffor_current(&home).unwrap().epoch.slots[0].state, SlotState::Settling);

	if restart {
		// Simulate a crash after the upstream persister saved its preimage but
		// before delivering its completion notification. The home is SETTLING.
		let manager = nodes[1].node.encode();
		let home_monitor = get_monitor!(nodes[1], home).encode();
		let upstream_monitor = get_monitor!(nodes[1], upstream).encode();
		reload_node!(nodes[1], config.clone(), &manager, &[&home_monitor, &upstream_monitor], persister, new_chain_monitor, reloaded);
		nodes[0].node.peer_disconnected(settler);
		assert!(!nodes[1].node.ffor_settler_enabled());
		assert!(nodes[1].node.ffor_transport_enabled());
		nodes[1].node.get_and_clear_pending_msg_events();
		nodes[1].node.replay_ffor_claims();
		let receipts = nodes[1].node.settled_ffor_receipts(&receiver, &home, &journal.epoch.epoch_id).unwrap();
		assert_eq!(receipts.len(), 1);
		assert_eq!(receipts[0].preimage, preimage.0);
		assert_eq!(nodes[1].node.ffor_current(&home).unwrap().epoch.slots[0].upstream,
			Some(admitted_upstream));
		nodes[1].chain_monitor.added_monitors.lock().unwrap().clear();
		nodes[1].node.get_and_clear_pending_events();
		return;
	}

	// Only the actual upstream persistence completion can stage home SETTLED.
	let (upstream_claim, _) = nodes[1].chain_monitor.get_latest_mon_update_id(upstream);
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(upstream, upstream_claim);
	let fulfills = if close_upstream {
		assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
		None
	} else {
		let fulfills = get_htlc_update_msgs!(nodes[1], payer);
		assert_eq!(fulfills.update_fulfill_htlcs.len(), 1);
		assert_eq!(fulfills.update_fulfill_htlcs[0].payment_preimage, preimage);
		Some(fulfills)
	};
	check_added_monitors!(nodes[1], 1);
	for _ in 0..100 { nodes[1].node.replay_ffor_claims(); }
	check_added_monitors!(nodes[1], 0);
	assert!(nodes[1].node.settled_ffor_receipts(&receiver, &home, &journal.epoch.epoch_id).unwrap().is_empty());
	let (home_settled, _) = nodes[1].chain_monitor.get_latest_mon_update_id(home);
	assert!(home_settled > home_settling);
	nodes[1].chain_monitor.chain_monitor.force_channel_monitor_updated(home, home_settled);
	assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
	let receipts = nodes[1].node.settled_ffor_receipts(&receiver, &home, &journal.epoch.epoch_id).unwrap();
	assert_eq!(receipts.len(), 1);
	assert_eq!(receipts[0].preimage, preimage.0);

	chanmon_cfgs[1].persister.set_update_ret(ChannelMonitorUpdateStatus::Completed);
	if let Some(fulfills) = fulfills {
		nodes[0].node.handle_update_fulfill_htlc(settler, fulfills.update_fulfill_htlcs[0].clone());
		expect_payment_sent(&nodes[0], preimage, Some(Some(0)), false, false);
		commitment_signed_dance!(nodes[0], nodes[1], fulfills.commitment_signed, false);
		expect_payment_path_successful!(nodes[0]);
	}
	nodes[1].node.get_and_clear_pending_events();
}

#[test]
fn native_ffor_reconnect_waits_for_durable_metadata_and_ack() {
	do_reconnect_barrier(false);
}

#[test]
fn native_ffor_reconnect_staging_failure_keeps_gate_closed() {
	do_reconnect_barrier(true);
}

fn do_reconnect_barrier(reject_first: bool) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut config = test_default_anchors_channel_config();
	config.channel_handshake_config.announce_for_forwarding = false;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config)]);
	for manager in &node_chanmgrs { manager.set_ffor_policy(FforPolicy { enabled: true, ..Default::default() }).unwrap(); }
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	for node in &nodes { connect_blocks(node, 100); }
	let (_, channel) = open_zero_conf_channel_with_value(&nodes[0], &nodes[1], None, 100_000, 10_000_000);
	let journal = activate_native_book(&nodes[0], &nodes[1], channel, &[2_000_000]);
	let s = nodes[0].node.get_our_node_id();
	let r = nodes[1].node.get_our_node_id();
	nodes[0].node.peer_disconnected(r);
	nodes[1].node.peer_disconnected(s);
	// Disabled admission retains transport support for existing obligations.
	nodes[0].node.set_ffor_policy(FforPolicy::default()).unwrap();
	assert!(!nodes[0].node.ffor_settler_enabled());
	assert!(nodes[0].node.ffor_transport_enabled());
	connect_nodes(&nodes[0], &nodes[1]);
	let s_reestablish = get_event_msg!(nodes[0], MessageSendEvent::SendChannelReestablish, r);
	let mut r_reestablish = get_event_msg!(nodes[1], MessageSendEvent::SendChannelReestablish, s);
	r_reestablish.ffor_epoch = Some(ffor::Reestablish { epoch_id: journal.epoch.epoch_id,
		state: ffor::Phase::VouchersCommitted as u8, last_seq: 0, activation_hash: [0; 32] }.encode().unwrap());
	if reject_first {
		// Exercise a real staging refusal at the bounded pending-transition cap.
		let mut runtime = nodes[0].node.ffor_runtime.lock().unwrap();
		let home = runtime.homes.get_mut(&channel).unwrap();
		for revision in 0..(2 * ffor::MAX_SLOTS + 32) as u64 {
			let token = FforPersistenceToken { channel_id: channel, epoch_id: journal.epoch.epoch_id,
				revision, update_id: home.persisted_update_id + 1 };
			home.pending.insert(revision, PendingTransition { token, journal: journal.clone(), actions: Vec::new() });
		}
	}
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[0].node.handle_channel_reestablish(r, &r_reestablish);
	nodes[1].node.handle_channel_reestablish(s, &s_reestablish);
	nodes[1].node.get_and_clear_pending_msg_events();
	if reject_first {
		assert!(!nodes[0].node.ffor_runtime.lock().unwrap().replay_gates[&channel].validated);
		nodes[0].node.ffor_runtime.lock().unwrap().homes.get_mut(&channel).unwrap().pending.clear();
		nodes[0].node.ffor_reestablished(r, &r_reestablish);
	}
	check_added_monitors!(nodes[0], 1);
	// A marker for ordinary channel traffic must stay behind both barriers.
	let marker = MessageSendEvent::SendStfu { node_id: r, msg: msgs::Stfu { channel_id: channel, initiator: false } };
	let mut wire_events = vec![marker];
	nodes[0].node.ffor_filter_replay_events(&mut wire_events);
	assert!(wire_events.is_empty());
	assert!(nodes[0].node.get_and_clear_pending_ffor_messages().is_empty());
	let (update, _) = nodes[0].chain_monitor.get_latest_mon_update_id(channel);
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(channel, update);
	let normal = nodes[0].node.get_and_clear_pending_msg_events();
	assert!(!normal.iter().any(|message| matches!(message, MessageSendEvent::SendStfu { .. })));
	let ack = nodes[0].node.get_and_clear_pending_ffor_messages();
	assert_eq!(ack.len(), 1);
	assert_eq!(ack[0].message_type, ffor::Kind::ActivateAck as u16);
	check_added_monitors!(nodes[0], 1);
	let normal = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(normal.iter().filter(|message| matches!(message, MessageSendEvent::SendStfu { .. })).count(), 1);
	assert!(nodes[0].node.ffor_runtime.lock().unwrap().replay_gates[&channel].ready);
}
