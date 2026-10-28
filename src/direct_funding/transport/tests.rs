use super::*;
use bitcoin::secp256k1::{Secp256k1, SecretKey};

fn peer(byte: u8) -> PublicKey {
	PublicKey::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[byte; 32]).unwrap())
}

fn relayed(address: RelayAddress, subtype: u16) -> Envelope {
	Envelope {
		version: PROTOCOL_VERSION,
		subtype: codec::RELAY,
		payload: RelayFrame { address, subtype, payload: vec![7, 8] }.encode().unwrap(),
	}
}

#[test]
fn direct_and_relayed_frames_preserve_authenticated_route_identity() {
	let transport = Transport::new(peer(1));
	let mut inbound = transport.subscribe();
	let message =
		Envelope { version: PROTOCOL_VERSION, subtype: codec::SIGN_REQUEST, payload: vec![3] };
	transport.handle_message(peer(2), &message);
	let frame = inbound.try_recv().unwrap();
	assert_eq!(frame.route, Route { peer: peer(2), relay_target: None });
	assert_eq!(frame.payload, vec![3]);
	transport.handle_message(peer(2), &relayed(RelayAddress::From(peer(3)), codec::WITNESS));
	let frame = inbound.try_recv().unwrap();
	assert_eq!(frame.route, Route { peer: peer(2), relay_target: Some(peer(3)) });
	assert_eq!(frame.subtype, codec::WITNESS);
	assert_eq!(frame.payload, vec![7, 8]);
	assert!(inbound.try_recv().is_err());
}

#[test]
fn endpoints_ignore_relay_to_frames_nested_relays_and_oversized_messages() {
	let transport = Transport::new(peer(1));
	let mut inbound = transport.subscribe();
	for message in [
		relayed(RelayAddress::To(peer(3)), codec::OFFER),
		relayed(RelayAddress::From(peer(3)), codec::RELAY),
		relayed(RelayAddress::From(peer(2)), codec::OFFER),
		Envelope { version: PROTOCOL_VERSION + 1, subtype: codec::OFFER, payload: vec![] },
		Envelope { version: PROTOCOL_VERSION, subtype: 99, payload: vec![] },
		Envelope {
			version: PROTOCOL_VERSION,
			subtype: codec::OFFER,
			payload: vec![0; codec::MAX_MESSAGE_BYTES + 1],
		},
		Envelope { version: PROTOCOL_VERSION, subtype: codec::RELAY, payload: vec![0] },
	] {
		transport.handle_message(peer(2), &message);
	}
	assert!(inbound.try_recv().is_err());
}

#[test]
fn inbound_rate_limit_and_outbound_queue_are_bounded_and_recoverable() {
	let transport = Transport::new(peer(1));
	let mut inbound = transport.subscribe();
	let message = Envelope { version: PROTOCOL_VERSION, subtype: codec::OFFER, payload: vec![1] };
	for _ in 0..40 {
		transport.handle_message(peer(2), &message);
	}
	let mut accepted = 0;
	while inbound.try_recv().is_ok() {
		accepted += 1;
	}
	assert_eq!(accepted, 32);
	let route = Route { peer: peer(2), relay_target: Some(peer(3)) };
	for _ in 0..MAX_QUEUE {
		transport.send(route, codec::OFFER, vec![4]).unwrap();
	}
	assert_eq!(transport.send(route, codec::OFFER, vec![4]), Err(DirectFundingError::Busy));
	let messages = transport.take_messages();
	assert_eq!(messages.len(), MAX_QUEUE);
	let frame = RelayFrame::decode(&messages[0].1.payload).unwrap();
	assert!(matches!(frame.address, RelayAddress::To(target) if target == peer(3)));
	assert_eq!(frame.subtype, codec::OFFER);
	transport.send(route, codec::WITNESS, vec![5]).unwrap();
	assert_eq!(transport.take_messages().len(), 1);
}

#[test]
fn sender_lane_ignores_frames_from_another_relay_or_target() {
	let transport = Arc::new(Transport::new(peer(1)));
	let route = Route { peer: peer(2), relay_target: Some(peer(3)) };
	let mut lane = Lane { transport: transport.clone(), route, incoming: transport.subscribe() };
	transport.handle_message(peer(4), &relayed(RelayAddress::From(peer(3)), codec::SIGN_REQUEST));
	transport.handle_message(peer(2), &relayed(RelayAddress::From(peer(4)), codec::SIGN_REQUEST));
	transport.handle_message(peer(2), &relayed(RelayAddress::From(peer(3)), codec::SIGN_REQUEST));
	let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
	let received = runtime.block_on(async {
		tokio::time::timeout(Duration::from_secs(1), lane.receive()).await.unwrap()
	});
	assert_eq!(received, Some((codec::SIGN_REQUEST, vec![7, 8])));
}
