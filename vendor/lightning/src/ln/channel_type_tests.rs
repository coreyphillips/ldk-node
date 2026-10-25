use crate::chain::chaininterface::{ConfirmationTarget, LowerBoundedFeeEstimator};
use crate::ln::channel::{
	get_initial_channel_type, InboundV1Channel, OutboundV1Channel, PendingV2Channel,
};
use crate::ln::channelmanager;
use crate::ln::msgs;
use crate::prelude::*;
use crate::util::config::UserConfig;
use crate::util::ser::{LengthReadable, Writeable};
use crate::util::test_utils::{TestFeeEstimator, TestKeysInterface, TestLogger};
use bitcoin::constants::ChainHash;
use bitcoin::network::Network;
use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use lightning_types::features::{ChannelTypeFeatures, InitFeatures};

#[test]
fn test_explicit_zero_conf_creation_policy_matrix() {
	let test_est = TestFeeEstimator::new(15000);
	let fee_estimator = LowerBoundedFeeEstimator::new(&test_est);
	let keys_provider = TestKeysInterface::new(&[42; 32], Network::Testnet);
	let logger = TestLogger::new();
	let peer =
		PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[7; 32]).unwrap());
	// Exhaustively cover opt-in, public/private, self-funding trust, and both
	// required peer features. Defaults retain the existing ordinary open path.
	for flags in 0..32 {
		let mut config = UserConfig::default();
		config.channel_handshake_config.require_zero_conf = flags & 1 != 0;
		config.channel_handshake_config.announce_for_forwarding = flags & 2 != 0;
		config.channel_handshake_limits.trust_own_funding_0conf = flags & 4 != 0;
		let mut features = channelmanager::provided_init_features(&config);
		if flags & 8 == 0 {
			features.clear_zero_conf();
		}
		if flags & 16 == 0 {
			features.clear_scid_privacy();
		}
		let result = OutboundV1Channel::<&TestKeysInterface>::new(
			&fee_estimator,
			&&keys_provider,
			&&keys_provider,
			peer,
			&features,
			1_000_000,
			0,
			flags as u128,
			&config,
			0,
			42,
			None,
			&logger,
		);
		let valid = flags & 1 == 0 || flags & 2 == 0 && flags & 28 == 28;
		assert_eq!(result.is_ok(), valid, "configuration {flags}");
		if let Ok(channel) = result {
			let channel_type = channel.funding.get_channel_type();
			assert_eq!(channel_type.requires_zero_conf(), flags & 1 != 0);
			assert_eq!(channel_type.requires_scid_privacy(), flags & 1 != 0);
		}
	}
}

#[test]
fn test_explicit_zero_conf_native_negotiation_and_depth_validation() {
	let test_est = TestFeeEstimator::new(15000);
	let fee_estimator = LowerBoundedFeeEstimator::new(&test_est);
	let keys_provider = TestKeysInterface::new(&[42; 32], Network::Testnet);
	let logger = TestLogger::new();
	let peer =
		PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[7; 32]).unwrap());
	let mut config = UserConfig::default();
	assert!(!config.channel_handshake_config.require_zero_conf);
	config.channel_handshake_config.require_zero_conf = true;
	let features = channelmanager::provided_init_features(&config);
	let mut outbound = OutboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		peer,
		&features,
		1_000_000,
		0,
		42,
		&config,
		0,
		42,
		None,
		&logger,
	)
	.unwrap();
	let open = outbound
		.get_open_channel(ChainHash::using_genesis_block(Network::Testnet), &&logger)
		.unwrap();
	// Exercise the actual wire serializer and reader, without changing the
	// message between ChannelManager's state and its peer-visible encoding.
	let encoded = open.encode();
	let decoded = msgs::OpenChannel::read_from_fixed_length_buffer(&mut &encoded[..]).unwrap();
	assert_eq!(decoded.common_fields.channel_type, open.common_fields.channel_type);
	let channel_type = open.common_fields.channel_type.as_ref().unwrap();
	assert!(channel_type.requires_zero_conf());
	assert!(channel_type.requires_scid_privacy());
	assert_eq!(channel_type, outbound.funding.get_channel_type());
	let mut inbound = InboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		peer,
		&channelmanager::provided_channel_type_features(&config),
		&features,
		&decoded,
		7,
		&config,
		0,
		&&logger,
		true,
	)
	.unwrap();
	let mut accept = inbound.accept_inbound_channel(&&logger).unwrap();
	assert_eq!(accept.common_fields.minimum_depth, 0);
	assert_eq!(accept.common_fields.channel_type, open.common_fields.channel_type);
	accept.common_fields.minimum_depth = 3;
	assert!(outbound.accept_channel(&accept, &config.channel_handshake_limits, &features).is_err());
	accept.common_fields.minimum_depth = 0;
	outbound.accept_channel(&accept, &config.channel_handshake_limits, &features).unwrap();
	assert_eq!(outbound.context.minimum_depth(&outbound.funding), Some(0));
	assert_eq!(outbound.funding.get_channel_type(), inbound.funding.get_channel_type());
}

#[test]
fn test_explicit_zero_conf_never_downgrades_on_peer_error() {
	let test_est = TestFeeEstimator::new(15000);
	let fee_estimator = LowerBoundedFeeEstimator::new(&test_est);
	let keys_provider = TestKeysInterface::new(&[42; 32], Network::Testnet);
	let logger = TestLogger::new();
	let peer =
		PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[7; 32]).unwrap());
	for anchors in [false, true] {
		let mut config = UserConfig::default();
		config.channel_handshake_config.require_zero_conf = true;
		config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = anchors;
		let features = channelmanager::provided_init_features(&config);
		let mut channel = OutboundV1Channel::<&TestKeysInterface>::new(
			&fee_estimator,
			&&keys_provider,
			&&keys_provider,
			peer,
			&features,
			1_000_000,
			0,
			42,
			&config,
			0,
			42,
			None,
			&logger,
		)
		.unwrap();
		let chain_hash = ChainHash::using_genesis_block(Network::Testnet);
		channel.get_open_channel(chain_hash, &&logger).unwrap();
		let original_type = channel.funding.get_channel_type().clone();
		// The default manager policy may differ from a per-channel override.
		assert!(channel
			.maybe_handle_error_without_close(
				chain_hash,
				&fee_estimator,
				&&logger,
				&UserConfig::default(),
				&features,
			)
			.is_err());
		assert_eq!(channel.funding.get_channel_type(), &original_type);
	}
}

#[test]
fn test_explicit_zero_conf_rejects_outbound_v2() {
	let test_est = TestFeeEstimator::new(15000);
	let fee_estimator = LowerBoundedFeeEstimator::new(&test_est);
	let keys_provider = TestKeysInterface::new(&[42; 32], Network::Testnet);
	let logger = TestLogger::new();
	let peer =
		PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[7; 32]).unwrap());
	let mut config = UserConfig::default();
	config.channel_handshake_config.require_zero_conf = true;
	let result = PendingV2Channel::<&TestKeysInterface>::new_outbound(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		peer,
		&channelmanager::provided_init_features(&config),
		1_000_000,
		Vec::new(),
		42,
		&config,
		0,
		42,
		ConfirmationTarget::NonAnchorChannelFee,
		&logger,
	);
	assert!(result.is_err());
}

#[test]
fn test_option_scid_privacy_initial() {
	let mut expected_type = ChannelTypeFeatures::only_static_remote_key();
	expected_type.set_scid_privacy_required();

	do_test_get_initial_channel_type(
		UserConfig::default(),
		InitFeatures::empty(),
		ChannelTypeFeatures::only_static_remote_key(),
		|cfg: &mut UserConfig| {
			// announce_for_forwarding = false is required, but set by UserConfig::default().
			cfg.channel_handshake_config.negotiate_scid_privacy = true;
		},
		|their_features: &mut InitFeatures| {
			their_features.set_scid_privacy_optional();
		},
		expected_type,
	)
}

#[test]
fn test_option_anchors_zero_fee_initial() {
	let mut expected_type = ChannelTypeFeatures::only_static_remote_key();
	expected_type.set_anchors_zero_fee_htlc_tx_required();

	do_test_get_initial_channel_type(
		UserConfig::default(),
		InitFeatures::empty(),
		ChannelTypeFeatures::only_static_remote_key(),
		|cfg: &mut UserConfig| {
			cfg.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
		},
		|their_features: &mut InitFeatures| {
			their_features.set_anchors_zero_fee_htlc_tx_optional();
		},
		expected_type,
	)
}

#[test]
fn test_option_zero_fee_commitments_initial() {
	let mut expected_type = ChannelTypeFeatures::empty();
	expected_type.set_anchor_zero_fee_commitments_required();

	do_test_get_initial_channel_type(
		UserConfig::default(),
		InitFeatures::empty(),
		ChannelTypeFeatures::only_static_remote_key(),
		|cfg: &mut UserConfig| {
			cfg.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;
		},
		|their_features: &mut InitFeatures| {
			their_features.set_anchor_zero_fee_commitments_optional();
		},
		expected_type,
	)
}

#[test]
fn test_option_zero_fee_commitments_from_zero_htlc_anchors_initial() {
	let mut start_cfg = UserConfig::default();
	start_cfg.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;

	let mut start_features = InitFeatures::empty();
	start_features.set_anchors_zero_fee_htlc_tx_optional();

	let mut start_type = ChannelTypeFeatures::anchors_zero_htlc_fee_and_dependencies();

	let mut expected_type = ChannelTypeFeatures::empty();
	expected_type.set_anchor_zero_fee_commitments_required();

	do_test_get_initial_channel_type(
		start_cfg,
		start_features,
		start_type,
		|cfg: &mut UserConfig| {
			cfg.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;
		},
		|their_features: &mut InitFeatures| {
			their_features.set_anchor_zero_fee_commitments_optional();
		},
		expected_type,
	)
}

fn do_test_get_initial_channel_type<F1, F2>(
	start_cfg: UserConfig, start_features: InitFeatures, start_type: ChannelTypeFeatures,
	mut local_cfg_mod: F1, mut remote_features_mod: F2, channel_type: ChannelTypeFeatures,
) where
	F1: FnOnce(&mut UserConfig),
	F2: FnOnce(&mut InitFeatures),
{
	// Local node supports feature, remote does not.
	let mut config = start_cfg.clone();
	local_cfg_mod(&mut config);
	assert_eq!(get_initial_channel_type(&config, &start_features), start_type);

	// Remote node supports feature, local does not.
	let mut their_features = start_features.clone();
	remote_features_mod(&mut their_features);
	assert_eq!(get_initial_channel_type(&start_cfg, &their_features), start_type);

	// Both support feature.
	assert_eq!(get_initial_channel_type(&config, &their_features), channel_type)
}

#[test]
fn test_zero_conf_channel_type_support() {
	let test_est = TestFeeEstimator::new(15000);
	let feeest = LowerBoundedFeeEstimator::new(&test_est);
	let secp_ctx = Secp256k1::new();
	let seed = [42; 32];
	let network = Network::Testnet;
	let keys_provider = TestKeysInterface::new(&seed, network);
	let logger = TestLogger::new();

	let node_b_node_id =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[42; 32]).unwrap());
	let config = UserConfig::default();
	let mut node_a_chan = OutboundV1Channel::<&TestKeysInterface>::new(
		&feeest,
		&&keys_provider,
		&&keys_provider,
		node_b_node_id,
		&channelmanager::provided_init_features(&config),
		10000000,
		100000,
		42,
		&config,
		0,
		42,
		None,
		&logger,
	)
	.unwrap();

	let mut channel_type_features = ChannelTypeFeatures::only_static_remote_key();
	channel_type_features.set_zero_conf_required();

	let mut open_channel_msg =
		node_a_chan.get_open_channel(ChainHash::using_genesis_block(network), &&logger).unwrap();
	open_channel_msg.common_fields.channel_type = Some(channel_type_features);
	let node_b_node_id =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[7; 32]).unwrap());
	let res = InboundV1Channel::<&TestKeysInterface>::new(
		&feeest,
		&&keys_provider,
		&&keys_provider,
		node_b_node_id,
		&channelmanager::provided_channel_type_features(&config),
		&channelmanager::provided_init_features(&config),
		&open_channel_msg,
		7,
		&config,
		0,
		&&logger,
		/*is_0conf=*/ false,
	);
	assert!(res.is_ok());
}

#[test]
fn test_supports_anchors_zero_htlc_tx_fee() {
	// Tests that if both sides support and negotiate `anchors_zero_fee_htlc_tx`, it is the
	// resulting `channel_type`.
	let mut config = UserConfig::default();
	config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;

	let mut expected_channel_type = ChannelTypeFeatures::empty();
	expected_channel_type.set_static_remote_key_required();
	expected_channel_type.set_anchors_zero_fee_htlc_tx_required();

	do_test_supports_channel_type(config, expected_channel_type)
}

#[test]
fn test_supports_zero_fee_commitments() {
	// Tests that if both sides support and negotiate `anchors_zero_fee_commitments`, it is
	// the resulting `channel_type`.
	let mut config = UserConfig::default();
	config.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;

	let mut expected_channel_type = ChannelTypeFeatures::empty();
	expected_channel_type.set_anchor_zero_fee_commitments_required();

	do_test_supports_channel_type(config, expected_channel_type)
}

#[test]
fn test_supports_zero_fee_commitments_and_htlc_tx_fee() {
	// Tests that if both sides support and negotiate `anchors_zero_fee_commitments` and
	// `anchors_zero_fee_htlc_tx`, the resulting `channel_type` is
	// `anchors_zero_fee_commitments`.
	let mut config = UserConfig::default();
	config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	config.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;

	let mut expected_channel_type = ChannelTypeFeatures::empty();
	expected_channel_type.set_anchor_zero_fee_commitments_required();

	do_test_supports_channel_type(config, expected_channel_type)
}

fn do_test_supports_channel_type(config: UserConfig, expected_channel_type: ChannelTypeFeatures) {
	let secp_ctx = Secp256k1::new();
	let test_est = TestFeeEstimator::new(15000);
	let fee_estimator = LowerBoundedFeeEstimator::new(&test_est);
	let network = Network::Testnet;
	let keys_provider = TestKeysInterface::new(&[42; 32], network);
	let logger = TestLogger::new();

	let node_id_a =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[1; 32]).unwrap());
	let node_id_b =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[2; 32]).unwrap());

	// Assert that we get `static_remotekey` when no custom config is negotiated.
	let channel_a = OutboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_b,
		&channelmanager::provided_init_features(&UserConfig::default()),
		10000000,
		100000,
		42,
		&config,
		0,
		42,
		None,
		&logger,
	)
	.unwrap();
	assert_eq!(
		channel_a.funding.get_channel_type(),
		&ChannelTypeFeatures::only_static_remote_key()
	);

	let mut channel_a = OutboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_b,
		&channelmanager::provided_init_features(&config),
		10000000,
		100000,
		42,
		&config,
		0,
		42,
		None,
		&logger,
	)
	.unwrap();

	let open_channel_msg =
		channel_a.get_open_channel(ChainHash::using_genesis_block(network), &&logger).unwrap();
	let channel_b = InboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_a,
		&channelmanager::provided_channel_type_features(&config),
		&channelmanager::provided_init_features(&config),
		&open_channel_msg,
		7,
		&config,
		0,
		&&logger,
		/*is_0conf=*/ false,
	)
	.unwrap();

	assert_eq!(channel_a.funding.get_channel_type(), &expected_channel_type);
	assert_eq!(channel_b.funding.get_channel_type(), &expected_channel_type);

	if expected_channel_type.supports_anchor_zero_fee_commitments() {
		assert_eq!(channel_a.context.feerate_per_kw, 0);
		assert_eq!(channel_b.context.feerate_per_kw, 0);
	} else {
		assert_ne!(channel_a.context.feerate_per_kw, 0);
		assert_ne!(channel_b.context.feerate_per_kw, 0);
	}
}

#[test]
fn test_rejects_if_channel_type_not_set() {
	// Tests that if `channel_type` is not set in `open_channel` and `accept_channel`, it is
	// rejected.
	let secp_ctx = Secp256k1::new();
	let test_est = TestFeeEstimator::new(15000);
	let fee_estimator = LowerBoundedFeeEstimator::new(&test_est);
	let network = Network::Testnet;
	let keys_provider = TestKeysInterface::new(&[42; 32], network);
	let logger = TestLogger::new();

	let node_id_a =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[1; 32]).unwrap());
	let node_id_b =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[2; 32]).unwrap());

	let config = UserConfig::default();

	let mut channel_a = OutboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_b,
		&channelmanager::provided_init_features(&config),
		10000000,
		100000,
		42,
		&config,
		0,
		42,
		None,
		&logger,
	)
	.unwrap();

	// Set `channel_type` to `None` to cause failure.
	let mut open_channel_msg =
		channel_a.get_open_channel(ChainHash::using_genesis_block(network), &&logger).unwrap();
	open_channel_msg.common_fields.channel_type = None;

	let channel_b = InboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_a,
		&channelmanager::provided_channel_type_features(&config),
		&channelmanager::provided_init_features(&config),
		&open_channel_msg,
		7,
		&config,
		0,
		&&logger,
		/*is_0conf=*/ false,
	);
	assert!(channel_b.is_err());

	open_channel_msg.common_fields.channel_type =
		Some(channel_a.funding.get_channel_type().clone());
	let mut channel_b = InboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_a,
		&channelmanager::provided_channel_type_features(&config),
		&channelmanager::provided_init_features(&config),
		&open_channel_msg,
		7,
		&config,
		0,
		&&logger,
		/*is_0conf=*/ false,
	)
	.unwrap();

	// Set `channel_type` to `None` in `accept_channel` to cause failure.
	let mut accept_channel_msg = channel_b.get_accept_channel_message(&&logger).unwrap();
	accept_channel_msg.common_fields.channel_type = None;

	let res = channel_a.accept_channel(
		&accept_channel_msg,
		&config.channel_handshake_limits,
		&channelmanager::provided_init_features(&config),
	);
	assert!(res.is_err());
}

#[test]
fn test_rejects_if_channel_type_differ() {
	// Tests that if the `channel_type` in `accept_channel` does not match the one set in
	// `open_channel` it rejects the channel.
	let secp_ctx = Secp256k1::new();
	let test_est = TestFeeEstimator::new(15000);
	let fee_estimator = LowerBoundedFeeEstimator::new(&test_est);
	let network = Network::Testnet;
	let keys_provider = TestKeysInterface::new(&[42; 32], network);
	let logger = TestLogger::new();

	let node_id_a =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[1; 32]).unwrap());
	let node_id_b =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[2; 32]).unwrap());

	let config = UserConfig::default();

	let mut channel_a = OutboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_b,
		&channelmanager::provided_init_features(&config),
		10000000,
		100000,
		42,
		&config,
		0,
		42,
		None,
		&logger,
	)
	.unwrap();

	let open_channel_msg =
		channel_a.get_open_channel(ChainHash::using_genesis_block(network), &&logger).unwrap();

	let mut channel_b = InboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_a,
		&channelmanager::provided_channel_type_features(&config),
		&channelmanager::provided_init_features(&config),
		&open_channel_msg,
		7,
		&config,
		0,
		&&logger,
		/*is_0conf=*/ false,
	)
	.unwrap();

	// Change the `channel_type` in `accept_channel` msg to make it different from the one set in
	// `open_channel` to cause failure.
	let mut accept_channel_msg = channel_b.get_accept_channel_message(&&logger).unwrap();
	let mut channel_type = channelmanager::provided_channel_type_features(&config);
	channel_type.set_zero_conf_required();
	accept_channel_msg.common_fields.channel_type = Some(channel_type.clone());

	let res = channel_a.accept_channel(
		&accept_channel_msg,
		&config.channel_handshake_limits,
		&channelmanager::provided_init_features(&config),
	);
	assert!(res.is_err());
}

#[test]
fn test_rejects_simple_anchors_channel_type() {
	// Tests that if `option_anchors` is being negotiated through the `channel_type` feature,
	// it is rejected.
	let secp_ctx = Secp256k1::new();
	let test_est = TestFeeEstimator::new(15000);
	let fee_estimator = LowerBoundedFeeEstimator::new(&test_est);
	let network = Network::Testnet;
	let keys_provider = TestKeysInterface::new(&[42; 32], network);
	let logger = TestLogger::new();

	let node_id_a =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[1; 32]).unwrap());
	let node_id_b =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[2; 32]).unwrap());

	let config = UserConfig::default();

	// See feature bit assignments: https://github.com/lightning/bolts/blob/master/09-features.md
	let static_remote_key_required: u64 = 1 << 12;
	let simple_anchors_required: u64 = 1 << 20;
	let simple_anchors_raw_features = static_remote_key_required | simple_anchors_required;
	let simple_anchors_init =
		InitFeatures::from_le_bytes(simple_anchors_raw_features.to_le_bytes().to_vec());
	let simple_anchors_channel_type =
		ChannelTypeFeatures::from_le_bytes(simple_anchors_raw_features.to_le_bytes().to_vec());
	assert!(!simple_anchors_init.requires_unknown_bits());
	assert!(!simple_anchors_channel_type.requires_unknown_bits());

	// First, we'll try to open a channel between A and B where A requests a channel type for
	// the original `option_anchors` feature (non zero fee htlc tx). This should be rejected by
	// B as it's not supported by LDK.
	let mut channel_a = OutboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_b,
		&channelmanager::provided_init_features(&config),
		10000000,
		100000,
		42,
		&config,
		0,
		42,
		None,
		&logger,
	)
	.unwrap();

	let mut open_channel_msg =
		channel_a.get_open_channel(ChainHash::using_genesis_block(network), &&logger).unwrap();
	open_channel_msg.common_fields.channel_type = Some(simple_anchors_channel_type.clone());

	let res = InboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_a,
		&channelmanager::provided_channel_type_features(&config),
		&simple_anchors_init,
		&open_channel_msg,
		7,
		&config,
		0,
		&&logger,
		/*is_0conf=*/ false,
	);
	assert!(res.is_err());

	// Then, we'll try to open another channel where A requests a channel type for
	// `anchors_zero_fee_htlc_tx`. B is malicious and tries to downgrade the channel type to the
	// original `option_anchors` feature, which should be rejected by A as it's not supported by
	// LDK.
	let mut channel_a = OutboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_b,
		&simple_anchors_init,
		10000000,
		100000,
		42,
		&config,
		0,
		42,
		None,
		&logger,
	)
	.unwrap();

	let open_channel_msg =
		channel_a.get_open_channel(ChainHash::using_genesis_block(network), &&logger).unwrap();

	let mut channel_b = InboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_a,
		&channelmanager::provided_channel_type_features(&config),
		&channelmanager::provided_init_features(&config),
		&open_channel_msg,
		7,
		&config,
		0,
		&&logger,
		/*is_0conf=*/ false,
	)
	.unwrap();

	let mut accept_channel_msg = channel_b.get_accept_channel_message(&&logger).unwrap();
	accept_channel_msg.common_fields.channel_type = Some(simple_anchors_channel_type.clone());

	let res = channel_a.accept_channel(
		&accept_channel_msg,
		&config.channel_handshake_limits,
		&simple_anchors_init,
	);
	assert!(res.is_err());
}

#[test]
fn test_rejects_both_anchor_types_channel_type() {
	// Tests that a `channel_type` requiring both `option_anchors_zero_fee_htlc_tx` and
	// `option_zero_fee_commitments` is rejected.
	let secp_ctx = Secp256k1::new();
	let test_est = TestFeeEstimator::new(15000);
	let fee_estimator = LowerBoundedFeeEstimator::new(&test_est);
	let network = Network::Testnet;
	let keys_provider = TestKeysInterface::new(&[42; 32], network);
	let logger = TestLogger::new();

	let node_id_a =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[1; 32]).unwrap());
	let node_id_b =
		PublicKey::from_secret_key(&secp_ctx, &SecretKey::from_slice(&[2; 32]).unwrap());

	let mut config = UserConfig::default();
	config.channel_handshake_config.negotiate_anchors_zero_fee_htlc_tx = true;
	config.channel_handshake_config.negotiate_anchor_zero_fee_commitments = true;

	let mut both_anchor_types = ChannelTypeFeatures::anchors_zero_fee_commitments();
	both_anchor_types.set_anchors_zero_fee_htlc_tx_required();

	let mut channel_a = OutboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_b,
		&channelmanager::provided_init_features(&config),
		10000000,
		100000,
		42,
		&config,
		0,
		42,
		None,
		&logger,
	)
	.unwrap();

	let mut open_channel_msg =
		channel_a.get_open_channel(ChainHash::using_genesis_block(network), &&logger).unwrap();
	open_channel_msg.common_fields.channel_type = Some(both_anchor_types);

	let res = InboundV1Channel::<&TestKeysInterface>::new(
		&fee_estimator,
		&&keys_provider,
		&&keys_provider,
		node_id_a,
		&channelmanager::provided_channel_type_features(&config),
		&channelmanager::provided_init_features(&config),
		&open_channel_msg,
		7,
		&config,
		0,
		&&logger,
		false,
	);
	assert!(res.is_err());
}


#[test]
fn test_funding_key_reuse_creation_policy() {
	use crate::util::test_channel_signer::SignerOp;
	let test_est = TestFeeEstimator::new(15000);
	let fee_estimator = LowerBoundedFeeEstimator::new(&test_est);
	let logger = TestLogger::new();
	let peer = PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[7; 32]).unwrap());
	for flags in 0..8 {
		let keys = TestKeysInterface::new(&[flags + 1; 32], Network::Testnet);
		let mut config = UserConfig::default();
		config.channel_handshake_config.reuse_funding_key_on_splice = flags & 1 != 0;
		config.channel_handshake_config.announce_for_forwarding = flags & 2 != 0;
		if flags & 4 == 0 {
			keys.next_signer_disabled_ops.lock().unwrap().insert(SignerOp::FundingKeyReuse);
		}
		let features = channelmanager::provided_init_features(&config);
		let result = OutboundV1Channel::<&TestKeysInterface>::new(
			&fee_estimator, &&keys, &&keys, peer, &features, 1_000_000, 0,
			42, &config, 0, 42, None, &logger,
		);
		let expected = flags & 1 == 0 || flags & 2 == 0 && flags & 4 != 0;
		assert_eq!(result.is_ok(), expected, "configuration {flags}");
		// Build an ordinary open, then apply the same matrix to inbound creation.
		let sender_keys = TestKeysInterface::new(&[42; 32], Network::Testnet);
		let mut sender_config = config.clone();
		sender_config.channel_handshake_config.reuse_funding_key_on_splice = false;
		let mut sender = OutboundV1Channel::<&TestKeysInterface>::new(
			&fee_estimator, &&sender_keys, &&sender_keys, peer, &features, 1_000_000, 0,
			42, &sender_config, 0, 42, None, &logger,
		).unwrap();
		let open = sender.get_open_channel(ChainHash::using_genesis_block(Network::Testnet), &&logger).unwrap();
		if flags & 4 == 0 {
			keys.next_signer_disabled_ops.lock().unwrap().insert(SignerOp::FundingKeyReuse);
		}
		let inbound = InboundV1Channel::<&TestKeysInterface>::new(
			&fee_estimator, &&keys, &&keys, peer,
			&channelmanager::provided_channel_type_features(&config), &features,
			&open, 7, &config, 0, &&logger, false,
		);
		let inbound_expected = flags & 1 == 0 || flags & 2 != 0 || flags & 4 != 0;
		assert_eq!(inbound.is_ok(), inbound_expected, "inbound configuration {flags}");
		if let Ok(inbound) = inbound {
			assert_eq!(inbound.funding.channel_transaction_parameters.reuse_funding_key_on_splice,
				flags & 1 != 0 && flags & 2 == 0);
		}
	}
}
