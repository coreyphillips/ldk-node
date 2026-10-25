use super::*;
use crate::chain::ChannelMonitorUpdateStatus;
use crate::events::bump_transaction::sync::WalletSourceSync;
use crate::ln::functional_test_utils::*;
use crate::ln::funding::{FundingTxInput, SpliceContribution};
use crate::ln::msgs::ChannelMessageHandler;
use crate::ln::splicing_tests::splice_channel;

fn pause_for_conflict(node: &Node<'_, '_, '_>, peer: PublicKey, channel: ChannelId) {
	node.node.handle_stfu(peer, &msgs::Stfu { channel_id: channel, initiator: true });
	let response = get_event_msg!(node, MessageSendEvent::SendStfu, peer);
	assert!(!response.initiator);
}

#[test]
fn native_splice_conflict_ack_waits_for_persistence() {
	do_splice_conflict(false, None);
}

#[test]
fn native_splice_conflict_restart_replays_exact_receipt() {
	do_splice_conflict(true, None);
}

#[test]
fn native_splice_conflict_terminal_monitor_rejects_stale_manager() {
	do_splice_conflict(false, Some(false));
}

#[test]
fn native_splice_conflict_restored_original_still_rejects_stale_manager() {
	do_splice_conflict(false, Some(true));
}

fn do_splice_conflict(restart: bool, terminal_reorg_back: Option<bool>) {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let config = test_default_anchors_channel_config();
	let persister;
	let terminal_persister;
	let new_chain_monitor;
	let terminal_chain_monitor;
	let reloaded;
	let terminal_manager;
	let node_chanmgrs =
		create_node_chanmgrs(2, &node_cfgs, &[Some(config.clone()), Some(config.clone())]);
	let mut nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let (_, _, channel, _) =
		create_announced_chan_between_nodes_with_value(&nodes, 0, 1, 100_000, 10_000_000);
	let peer = nodes[1].node.get_our_node_id();
	let original = nodes[0].node.list_channels()[0].funding_txo.unwrap();
	let input_transaction =
		provide_anchor_utxo_reserves(&nodes, 1, bitcoin::Amount::from_sat(40_000));
	let inputs = vec![FundingTxInput::new_p2wpkh(input_transaction.clone(), 1).unwrap()];
	let contribution = SpliceContribution::SpliceIn {
		value: bitcoin::Amount::from_sat(20_000),
		inputs,
		change_script: Some(nodes[1].wallet_source.get_change_script().unwrap()),
	};
	let candidate = splice_channel(&nodes[1], &nodes[0], channel, contribution);
	assert!(nodes[0]
		.node
		.splice_conflict_candidate(&channel, &peer, candidate.compute_txid())
		.is_err());
	let index = candidate
		.input
		.iter()
		.position(|input| input.previous_output != original.into_bitcoin_outpoint())
		.unwrap() as u16;
	let mut conflict = candidate.clone();
	conflict.input = vec![candidate.input[index as usize].clone()];
	conflict.output.truncate(1);
	conflict.output[0].value = bitcoin::Amount::from_sat(1_000);
	let conflict = nodes[1].wallet_source.sign_tx(conflict).unwrap();
	conflict
		.verify(|outpoint| {
			assert_eq!(outpoint.txid, input_transaction.compute_txid());
			input_transaction.output.get(outpoint.vout as usize).cloned()
		})
		.unwrap();
	for node in &nodes {
		mine_transaction(node, &conflict);
	}
	let confirmation_height = nodes[0].best_block_info().1;
	let confirmation_hash = nodes[0].best_block_hash();
	for node in &nodes {
		connect_blocks(node, 5);
	}
	pause_for_conflict(&nodes[0], peer, channel);
	let admitted =
		nodes[0].node.splice_conflict_candidate(&channel, &peer, candidate.compute_txid()).unwrap();
	assert!(nodes[0]
		.node
		.splice_conflict_candidate(
			&channel,
			&nodes[0].node.get_our_node_id(),
			candidate.compute_txid()
		)
		.is_err());
	assert!(nodes[0].node.splice_conflict_runtime.lock().unwrap().homes.is_empty());
	assert_eq!(admitted.transaction, candidate);
	assert_eq!(admitted.shared_funding_outpoint, original.into_bitcoin_outpoint());
	let tip = admitted.best_block;
	assert!(tip.height >= 6);
	assert!(nodes[0]
		.node
		.revert_conflicted_splice(
			&channel,
			&peer,
			candidate.compute_txid(),
			conflict.clone(),
			index,
			tip.height - 4,
			tip.block_hash,
			tip
		)
		.is_err());
	let shared_index = candidate
		.input
		.iter()
		.position(|input| input.previous_output == admitted.shared_funding_outpoint)
		.unwrap() as u16;
	assert!(nodes[0]
		.node
		.revert_conflicted_splice(
			&channel,
			&peer,
			candidate.compute_txid(),
			conflict.clone(),
			shared_index,
			confirmation_height,
			confirmation_hash,
			tip
		)
		.is_err());
	// Even when the selected proof input is external, spending the shared input
	// elsewhere in the conflict cannot restore a usable original channel.
	let mut shared_conflict = candidate.clone();
	shared_conflict.output[0].value -= bitcoin::Amount::from_sat(1);
	assert!(nodes[0]
		.node
		.revert_conflicted_splice(
			&channel,
			&peer,
			candidate.compute_txid(),
			shared_conflict,
			index,
			confirmation_height,
			confirmation_hash,
			tip
		)
		.is_err());
	check_added_monitors!(nodes[0], 0);
	chanmon_cfgs[0].persister.set_update_ret(ChannelMonitorUpdateStatus::InProgress);
	nodes[0]
		.node
		.revert_conflicted_splice(
			&channel,
			&peer,
			candidate.compute_txid(),
			conflict.clone(),
			index,
			confirmation_height,
			confirmation_hash,
			tip,
		)
		.unwrap();
	check_added_monitors!(nodes[0], 1);
	assert!(nodes[0].node.get_and_clear_pending_splice_conflict_responses().is_empty());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[0]
		.node
		.replay_splice_conflict_response(
			&channel,
			&peer,
			candidate.compute_txid(),
			conflict.compute_txid(),
			index
		)
		.unwrap());
	assert!(nodes[0].node.get_and_clear_pending_splice_conflict_responses().is_empty());
	let (update, _) = nodes[0].chain_monitor.get_latest_mon_update_id(channel);
	nodes[0].chain_monitor.chain_monitor.force_channel_monitor_updated(channel, update);
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	if restart {
		// The retirement was saved, but its response never reached the transport.
		let manager = nodes[0].node.encode();
		let monitor = get_monitor!(nodes[0], channel).encode();
		reload_node!(
			nodes[0],
			config.clone(),
			&manager,
			&[&monitor],
			persister,
			new_chain_monitor,
			reloaded
		);
		nodes[1].node.peer_disconnected(nodes[0].node.get_our_node_id());
		let mut reconnect = ReconnectArgs::new(&nodes[0], &nodes[1]);
		reconnect.send_channel_ready = (false, true);
		reconnect.send_announcement_sigs = (true, true);
		reconnect_nodes(reconnect);
		assert!(nodes[0].node.get_and_clear_pending_splice_conflict_responses().is_empty());
		pause_for_conflict(&nodes[0], peer, channel);
		assert!(nodes[0]
			.node
			.replay_splice_conflict_response(
				&channel,
				&peer,
				candidate.compute_txid(),
				conflict.compute_txid(),
				index
			)
			.unwrap());
	}
	let response = nodes[0].node.get_and_clear_pending_splice_conflict_responses();
	assert_eq!(response.len(), 1);
	assert!(response[0].agreed);
	assert_eq!(response[0].splice_txid, candidate.compute_txid());
	assert_eq!(nodes[0].node.list_channels()[0].funding_txo, Some(original));
	assert!(nodes[0].node.list_channels()[0].is_usable);
	assert!(nodes[0].node.get_and_clear_pending_splice_conflict_responses().is_empty());
	assert_eq!(get_monitor!(nodes[0], channel).get_splice_conflict_records().len(), 1);

	// Replays require a newly authenticated peer-owned pause and exact identity.
	assert!(nodes[0]
		.node
		.replay_splice_conflict_response(
			&channel,
			&peer,
			candidate.compute_txid(),
			conflict.compute_txid(),
			index
		)
		.is_err());
	pause_for_conflict(&nodes[0], peer, channel);
	assert!(nodes[0]
		.node
		.replay_splice_conflict_response(
			&channel,
			&peer,
			candidate.compute_txid(),
			candidate.compute_txid(),
			index
		)
		.is_err());
	assert!(nodes[0]
		.node
		.replay_splice_conflict_response(
			&channel,
			&peer,
			candidate.compute_txid(),
			conflict.compute_txid(),
			index
		)
		.unwrap());
	assert_eq!(nodes[0].node.get_and_clear_pending_splice_conflict_responses().len(), 1);
	check_added_monitors!(nodes[0], 0);

	// Emulate the receiver applying the same proven rewind after its ACK, using
	// the native transition rather than deleting its pending funding monitor.
	let primary = nodes[0].node.get_our_node_id();
	pause_for_conflict(&nodes[1], primary, channel);
	nodes[1]
		.node
		.revert_conflicted_splice(
			&channel,
			&primary,
			candidate.compute_txid(),
			conflict,
			index,
			confirmation_height,
			confirmation_hash,
			tip,
		)
		.unwrap();
	nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(nodes[1].node.get_and_clear_pending_splice_conflict_responses().len(), 1);
	check_added_monitors!(nodes[1], 1);
	let _ = send_payment(&nodes[0], &[&nodes[1]], 100_000);
	assert_eq!(nodes[0].node.list_channels()[0].funding_txo, Some(original));
	assert_eq!(nodes[1].node.list_channels()[0].funding_txo, Some(original));

	// A response queued for an old transport session must never release a new
	// pause. A repeated authenticated request binds the durable receipt anew.
	pause_for_conflict(&nodes[0], peer, channel);
	let conflict_txid =
		get_monitor!(nodes[0], channel).get_splice_conflict_records()[0].conflict_txid;
	assert!(nodes[0]
		.node
		.replay_splice_conflict_response(
			&channel,
			&peer,
			candidate.compute_txid(),
			conflict_txid,
			index
		)
		.unwrap());
	nodes[0].node.peer_disconnected(peer);
	nodes[1].node.peer_disconnected(primary);
	reconnect_nodes(ReconnectArgs::new(&nodes[0], &nodes[1]));
	pause_for_conflict(&nodes[0], peer, channel);
	assert!(nodes[0].node.get_and_clear_pending_splice_conflict_responses().is_empty());
	{
		let peers = nodes[0].node.per_peer_state.read().unwrap();
		let state = peers[&peer].lock().unwrap();
		assert!(state.channel_by_id[&channel].as_funded().unwrap().is_peer_initiated_quiescence());
	}
	assert!(nodes[0]
		.node
		.replay_splice_conflict_response(
			&channel,
			&primary,
			candidate.compute_txid(),
			conflict_txid,
			index
		)
		.is_err());
	assert!(nodes[0].node.splice_conflict_runtime.lock().unwrap().responses.is_empty());
	for _ in 0..8 {
		assert!(nodes[0]
			.node
			.replay_splice_conflict_response(
				&channel,
				&peer,
				candidate.compute_txid(),
				conflict_txid,
				index
			)
			.unwrap());
	}
	assert_eq!(nodes[0].node.get_and_clear_pending_splice_conflict_responses().len(), 1);
	assert!(nodes[0].node.list_channels()[0].is_usable);
	if let Some(reorg_back) = terminal_reorg_back {
		let manager = nodes[0].node.encode();
		let (_, monitor) = <(BlockHash, crate::chain::channelmonitor::ChannelMonitor<_>)>::read(
			&mut io::Cursor::new(get_monitor!(nodes[0], channel).encode()),
			(nodes[0].keys_manager, nodes[0].keys_manager),
		).unwrap();
		assert!(!monitor.is_retired_funding_terminal());
		let broadcaster = crate::util::test_utils::TestBroadcaster::with_blocks(
			nodes[0].tx_broadcaster.blocks.clone(),
		);
		// Only the monitor observes a replacement branch. The saved manager is
		// from before this onchain event, with identical monitor update IDs.
		let fork = create_dummy_header(confirmation_hash, 71);
		monitor.best_block_updated(&fork, confirmation_height - 1, &broadcaster,
			nodes[0].fee_estimator, &nodes[0].logger);
		let branch = create_dummy_header(fork.block_hash(), 72);
		monitor.transactions_confirmed(&branch, &[(0, &candidate)], confirmation_height,
			&broadcaster, nodes[0].fee_estimator, &nodes[0].logger);
		monitor.best_block_updated(&branch, confirmation_height, &broadcaster,
			nodes[0].fee_estimator, &nodes[0].logger);
		if reorg_back {
			monitor.transaction_unconfirmed(&candidate.compute_txid(), &broadcaster,
				nodes[0].fee_estimator, &nodes[0].logger);
			assert_eq!(monitor.get_funding_txo(), original);
		}
		assert!(monitor.is_retired_funding_terminal());
		assert!(!monitor.get_and_clear_pending_monitor_events().is_empty());
		assert!(monitor.get_and_clear_pending_monitor_events().is_empty());
		{
			let peers = nodes[0].node.per_peer_state.read().unwrap();
			let peer_state = peers[&peer].lock().unwrap();
			let channel = peer_state.channel_by_id[&channel].as_funded().unwrap();
			assert_eq!(channel.context.get_latest_monitor_update_id(), monitor.get_latest_update_id());
			assert!(channel.get_cur_holder_commitment_transaction_number() <= monitor.get_cur_holder_commitment_number());
			assert!(channel.get_cur_counterparty_commitment_transaction_number() <= monitor.get_cur_counterparty_commitment_number());
			assert!(channel.get_revoked_counterparty_commitment_transaction_number() <= monitor.get_min_seen_secret());
		}
		let encoded = monitor.encode();
		nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().clear();
		reload_node!(nodes[0], config, &manager, &[&encoded], terminal_persister,
			terminal_chain_monitor, terminal_manager);
		assert!(nodes[0].node.list_channels().is_empty());
		let events = nodes[0].node.get_and_clear_pending_events();
		assert!(events.iter().any(|event| matches!(event, Event::ChannelClosed {
			channel_id, reason: ClosureReason::OutdatedChannelManager, ..
		} if *channel_id == channel)));
		check_added_monitors!(nodes[0], 1);
		assert!(get_monitor!(nodes[0], channel).is_retired_funding_terminal());
		assert!(!nodes[0].tx_broadcaster.txn_broadcasted.lock().unwrap().iter().any(|transaction|
			transaction.input.iter().any(|input| input.previous_output.txid == candidate.compute_txid())),
			"Restart must never broadcast the revoked archived holder commitment");
	}
}
