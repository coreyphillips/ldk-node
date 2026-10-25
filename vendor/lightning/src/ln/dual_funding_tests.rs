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
