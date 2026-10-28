// This file is Copyright its original authors, visible in version control
// history.
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Tests that test the creation of dual-funded channels in ChannelManager.

use crate::chain::chaininterface::{ConfirmationTarget, LowerBoundedFeeEstimator};
use crate::events::Event;
use crate::ln::channel::PendingV2Channel;
use crate::ln::functional_test_utils::*;
use crate::ln::msgs::{BaseMessageHandler, ChannelMessageHandler, MessageSendEvent};
use crate::util::errors::APIError;
use crate::util::ser::{LengthReadable, Writeable};
use crate::util::test_utils::{TestFeeEstimator, TestKeysInterface, TestLogger};
use bitcoin::constants::ChainHash;
use bitcoin::Network;

#[test]
fn test_confirmed_inbound_v2_policy() {
	for enabled in [false, true] {
		for manual in [false, true] {
			let chanmon_cfgs = create_chanmon_cfgs(2);
			let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
			let mut receiver_config = test_default_channel_config();
			receiver_config.accept_inbound_channels_v2 = enabled;
			receiver_config.manually_accept_inbound_channels = manual;
			// A zero configured minimum cannot turn this opt-in into trusted funding.
			receiver_config.channel_handshake_config.minimum_depth = 0;
			let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(receiver_config)]);
			let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
			let opener_id = nodes[0].node.get_our_node_id();
			let receiver_id = nodes[1].node.get_our_node_id();
			assert_eq!(nodes[1].node.init_features().supports_dual_fund(), enabled);
			let estimator = TestFeeEstimator::new(15000);
			let estimator = LowerBoundedFeeEstimator::new(&estimator);
			let keys = TestKeysInterface::new(&[42; 32], Network::Testnet);
			let logger = TestLogger::new();
			let channel = PendingV2Channel::<&TestKeysInterface>::new_outbound(
				&estimator,
				&&keys,
				&&keys,
				receiver_id,
				&nodes[1].node.init_features(),
				1_000_000,
				Vec::new(),
				42,
				&test_default_channel_config(),
				0,
				42,
				ConfirmationTarget::NonAnchorChannelFee,
				&logger,
			)
			.unwrap();
			let open =
				channel.get_open_channel_v2(ChainHash::using_genesis_block(Network::Testnet));
			nodes[1].node.handle_open_channel_v2(opener_id, &open);
			if !enabled {
				assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
				let events = nodes[1].node.get_and_clear_pending_msg_events();
				assert_eq!(events.len(), 1);
				assert!(matches!(events[0], MessageSendEvent::HandleError { .. }));
				assert!(nodes[1].node.list_channels().is_empty());
				continue;
			}
			if manual {
				let request = get_event!(nodes[1], Event::OpenChannelRequest);
				assert!(matches!(request, Event::OpenChannelRequest { .. }));
				assert!(nodes[1].node.get_and_clear_pending_msg_events().is_empty());
				let error = nodes[1]
					.node
					.accept_inbound_channel_from_trusted_peer_0conf(
						&open.common_fields.temporary_channel_id,
						&opener_id,
						43,
						None,
					)
					.unwrap_err();
				assert!(matches!(error, APIError::APIMisuseError { .. }));
				// Rejected misuse preserves the request for ordinary acceptance.
				nodes[1]
					.node
					.accept_inbound_channel(
						&open.common_fields.temporary_channel_id,
						&opener_id,
						43,
						None,
					)
					.unwrap();
			}
			let accept = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannelV2, opener_id);
			assert_eq!(accept.funding_satoshis, 0);
			assert!(accept.common_fields.minimum_depth > 0);
			let encoded = accept.encode();
			let decoded =
				crate::ln::msgs::AcceptChannelV2::read_from_fixed_length_buffer(&mut &encoded[..])
					.unwrap();
			assert_eq!(decoded.common_fields.minimum_depth, accept.common_fields.minimum_depth);
			assert_eq!(decoded.funding_satoshis, 0);
			assert_eq!(nodes[1].node.list_channels().len(), 1);
			check_added_monitors(&nodes[1], 0);
		}
	}
}

#[test]
fn test_confirmed_inbound_v2_rejects_zero_conf_type() {
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut config = test_default_channel_config();
	config.accept_inbound_channels_v2 = true;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let estimator = TestFeeEstimator::new(15000);
	let estimator = LowerBoundedFeeEstimator::new(&estimator);
	let keys = TestKeysInterface::new(&[42; 32], Network::Testnet);
	let logger = TestLogger::new();
	let channel = PendingV2Channel::<&TestKeysInterface>::new_outbound(
		&estimator,
		&&keys,
		&&keys,
		nodes[1].node.get_our_node_id(),
		&nodes[1].node.init_features(),
		1_000_000,
		Vec::new(),
		42,
		&test_default_channel_config(),
		0,
		42,
		ConfirmationTarget::NonAnchorChannelFee,
		&logger,
	)
	.unwrap();
	let mut open = channel.get_open_channel_v2(ChainHash::using_genesis_block(Network::Testnet));
	open.common_fields.channel_type.as_mut().unwrap().set_zero_conf_required();
	open.common_fields.channel_type.as_mut().unwrap().set_scid_privacy_required();
	nodes[1].node.handle_open_channel_v2(nodes[0].node.get_our_node_id(), &open);
	let events = nodes[1].node.get_and_clear_pending_msg_events();
	assert_eq!(events.len(), 1);
	assert!(matches!(events[0], MessageSendEvent::HandleError { .. }));
	assert!(nodes[1].node.list_channels().is_empty());
	assert!(nodes[1].node.get_and_clear_pending_events().is_empty());
	check_added_monitors(&nodes[1], 0);
}

#[test]
fn test_external_v2_funding_signing_details_and_broadcast() {
	use crate::events::bump_transaction::sync::WalletSourceSync;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut receiver_config = test_default_channel_config();
	receiver_config.accept_inbound_channels_v2 = true;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(receiver_config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let payer_id = nodes[0].node.get_our_node_id();
	let primary_id = nodes[1].node.get_our_node_id();
	let coin = provide_anchor_utxo_reserves(&nodes, 1, bitcoin::Amount::from_sat(150_000));
	let inputs = vec![crate::ln::funding::FundingTxInput::new_p2wpkh(coin, 0).unwrap()];
	let change = nodes[0].wallet_source.get_change_script().unwrap();
	let temporary = nodes[0]
		.node
		.create_channel_v2(primary_id, 100_000, inputs, change.clone(), 1000, 42, None)
		.unwrap();
	assert!(nodes[0].node.funding_signing_details(&temporary, &primary_id).is_err());
	let open = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannelV2, primary_id);
	assert_eq!(open.funding_feerate_sat_per_1000_weight, 1000);
	nodes[1].node.handle_open_channel_v2(payer_id, &open);
	let accept = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannelV2, payer_id);
	nodes[0].node.handle_accept_channel_v2(primary_id, &accept);
	let channel_id = nodes[0].node.list_channels()[0].channel_id;
	assert_ne!(temporary, channel_id);
	assert_eq!(nodes[1].node.list_channels()[0].channel_id, channel_id);
	let mut ready = None;
	for _ in 0..20 {
		for (from, to) in [(0usize, 1usize), (1, 0)] {
			let source = nodes[from].node.get_our_node_id();
			for message in nodes[from].node.get_and_clear_pending_msg_events() {
				match message {
					MessageSendEvent::SendTxAddInput { msg, .. } => {
						nodes[to].node.handle_tx_add_input(source, &msg)
					},
					MessageSendEvent::SendTxAddOutput { msg, .. } => {
						nodes[to].node.handle_tx_add_output(source, &msg)
					},
					MessageSendEvent::SendTxComplete { msg, .. } => {
						nodes[to].node.handle_tx_complete(source, &msg)
					},
					MessageSendEvent::UpdateHTLCs { updates, .. } => {
						for signature in updates.commitment_signed {
							nodes[to].node.handle_commitment_signed(source, &signature);
						}
					},
					MessageSendEvent::SendTxSignatures { msg, .. } => {
						nodes[to].node.handle_tx_signatures(source, &msg)
					},
					other => panic!("Unexpected funding message: {:?}", other),
				}
			}
		}
		for event in nodes[0].node.get_and_clear_pending_events() {
			match event {
				Event::FundingTransactionReadyForSigning { unsigned_transaction, .. } => {
					ready = Some(unsigned_transaction)
				},
				other => panic!("Unexpected pre-sign event: {:?}", other),
			}
		}
		if ready.is_some() {
			break;
		}
	}
	let unsigned = ready.expect("v2 negotiation must reach external signing");
	let details = nodes[0].node.funding_signing_details(&channel_id, &primary_id).unwrap();
	assert_eq!(details.unsigned_transaction, unsigned);
	assert_eq!(details.prevouts.len(), unsigned.input.len());
	assert_eq!(details.shared_input_index, None);
	assert_eq!(details.previous_funding_redeem_script, None);
	assert!(!details.local_witnesses_submitted);
	let funding_output = &unsigned.output[details.funding_output_index as usize];
	assert_eq!(funding_output.value.to_sat(), 100_000);
	assert_eq!(funding_output.script_pubkey, details.funding_redeem_script.to_p2wsh());
	assert!(unsigned.output.iter().any(|output| output.script_pubkey == change));
	assert!(nodes[0].tx_broadcaster.txn_broadcast().is_empty());
	let signed = nodes[0].wallet_source.sign_tx(unsigned).unwrap();
	nodes[0].node.funding_transaction_signed(&channel_id, &primary_id, signed).unwrap();
	for message in nodes[0].node.get_and_clear_pending_msg_events() {
		match message {
			MessageSendEvent::SendTxSignatures { msg, .. } => {
				nodes[1].node.handle_tx_signatures(payer_id, &msg)
			},
			other => panic!("Unexpected post-sign message: {:?}", other),
		}
	}
	assert_eq!(nodes[0].tx_broadcaster.txn_broadcast().len(), 1);
	assert_eq!(nodes[1].tx_broadcaster.txn_broadcast().len(), 1);
	assert!(nodes[0].node.abandon_unfunded_channel(&channel_id, &primary_id).is_err());
	for node in &nodes {
		let events = node.node.get_and_clear_pending_events();
		assert!(
			events.iter().any(|event| matches!(event, Event::ChannelPending { .. })),
			"{:?}",
			events
		);
		check_added_monitors(node, 1);
	}
	// An unsolicited accept_channel2 must never remove a funded channel or its obligations.
	let mut replay = accept;
	replay.common_fields.temporary_channel_id = channel_id;
	nodes[0].node.handle_accept_channel_v2(primary_id, &replay);
	let messages = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(messages.len(), 1);
	assert!(matches!(messages[0], MessageSendEvent::HandleError { .. }));
	assert_eq!(nodes[0].node.list_channels()[0].channel_id, channel_id);
	assert!(nodes[0].node.get_and_clear_pending_events().is_empty());
	check_added_monitors(&nodes[0], 0);
}

#[test]
fn test_external_v2_refuses_unfunded_and_zero_conf_requests() {
	use crate::events::bump_transaction::sync::WalletSourceSync;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut config = test_default_channel_config();
	config.accept_inbound_channels_v2 = true;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let peer = nodes[1].node.get_our_node_id();
	let inputs = create_dual_funding_utxos_with_prev_txs(&nodes[0], &[1_000]);
	let change = nodes[0].wallet_source.get_change_script().unwrap();
	assert!(nodes[0]
		.node
		.create_channel_v2(peer, 100_000, inputs, change.clone(), 1000, 42, None)
		.is_err());
	let inputs = create_dual_funding_utxos_with_prev_txs(&nodes[0], &[150_000]);
	let mut config = test_default_channel_config();
	config.channel_handshake_config.require_zero_conf = true;
	assert!(nodes[0]
		.node
		.create_channel_v2(peer, 100_000, inputs, change, 1000, 42, Some(config))
		.is_err());
	assert!(nodes[0].node.get_and_clear_pending_msg_events().is_empty());
	assert!(nodes[0].node.list_channels().is_empty());
}

#[test]
fn test_external_v2_rejects_counterparty_contribution_and_zero_conf_accept() {
	use crate::events::bump_transaction::sync::WalletSourceSync;
	for (contribution, minimum_depth) in [(1_000, 1), (0, 0)] {
		let chanmon_cfgs = create_chanmon_cfgs(2);
		let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
		let mut config = test_default_channel_config();
		config.accept_inbound_channels_v2 = true;
		let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(config)]);
		let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
		let peer = nodes[1].node.get_our_node_id();
		let opener = nodes[0].node.get_our_node_id();
		let inputs = create_dual_funding_utxos_with_prev_txs(&nodes[0], &[150_000]);
		let change = nodes[0].wallet_source.get_change_script().unwrap();
		nodes[0].node.create_channel_v2(peer, 100_000, inputs, change, 1000, 42, None).unwrap();
		let open = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannelV2, peer);
		nodes[1].node.handle_open_channel_v2(opener, &open);
		let mut accept = get_event_msg!(nodes[1], MessageSendEvent::SendAcceptChannelV2, opener);
		accept.funding_satoshis = contribution;
		accept.common_fields.minimum_depth = minimum_depth;
		nodes[0].node.handle_accept_channel_v2(peer, &accept);
		let messages = nodes[0].node.get_and_clear_pending_msg_events();
		assert_eq!(messages.len(), 1);
		assert!(matches!(messages[0], MessageSendEvent::HandleError { .. }));
		assert!(nodes[0].node.list_channels().is_empty());
		let events = nodes[0].node.get_and_clear_pending_events();
		assert_eq!(events.len(), 1);
		assert!(matches!(events[0], Event::ChannelClosed { .. }));
		assert!(nodes[0].tx_broadcaster.txn_broadcast().is_empty());
		check_added_monitors(&nodes[0], 0);
	}
}

#[test]
fn test_external_v2_abandon_before_transaction_construction() {
	use crate::events::bump_transaction::sync::WalletSourceSync;
	let chanmon_cfgs = create_chanmon_cfgs(2);
	let node_cfgs = create_node_cfgs(2, &chanmon_cfgs);
	let mut config = test_default_channel_config();
	config.accept_inbound_channels_v2 = true;
	let node_chanmgrs = create_node_chanmgrs(2, &node_cfgs, &[None, Some(config)]);
	let nodes = create_network(2, &node_cfgs, &node_chanmgrs);
	let peer = nodes[1].node.get_our_node_id();
	let inputs = create_dual_funding_utxos_with_prev_txs(&nodes[0], &[150_000]);
	let change = nodes[0].wallet_source.get_change_script().unwrap();
	let channel =
		nodes[0].node.create_channel_v2(peer, 100_000, inputs, change, 1000, 42, None).unwrap();
	let _open = get_event_msg!(nodes[0], MessageSendEvent::SendOpenChannelV2, peer);
	nodes[0].node.abandon_unfunded_channel(&channel, &peer).unwrap();
	assert!(nodes[0].node.list_channels().is_empty());
	let messages = nodes[0].node.get_and_clear_pending_msg_events();
	assert_eq!(messages.len(), 1);
	assert!(matches!(messages[0], MessageSendEvent::HandleError { .. }));
	let events = nodes[0].node.get_and_clear_pending_events();
	assert_eq!(events.len(), 1);
	assert!(matches!(events[0], Event::ChannelClosed { .. }));
	assert!(nodes[0].tx_broadcaster.txn_broadcast().is_empty());
	check_added_monitors(&nodes[0], 0);
}
