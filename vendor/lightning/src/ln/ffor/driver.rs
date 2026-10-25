// Copyright (c) 2023 Synonym. MIT license, see LICENSE-BEIGNET.
// Adapted from Beignet channel/channel.ts and ffor/amounts.ts at the revision
// recorded in the parent module. Native custody barriers are additional.

use super::*;
use crate::ln::ffor_monitor::{CommitmentSnapshot, FforJournal};
use crate::sign::{EntropySource, NodeSigner, Recipient};

/// These are instructions to the native monitor completion handler, never
/// permission to emit from a candidate that has merely been prepared in memory.
/// A claim deliberately carries no preimage: custody is looked up from the
/// durable journal only after checking its exact slot and upstream identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Action {
	Send(SignedMessage),
	OfferVouchers,
	ClaimUpstream { slot: u16, upstream: Upstream },
	ExitQuiescence,
	CancelSetupVouchers,
}

pub(crate) struct PreparedTransition {
	pub(crate) journal: FforJournal,
	pub(crate) after_persistence: Vec<Action>,
}

/// Local admission limits. These are independent of a peer's signed request.
#[derive(Clone, Debug)]
pub(crate) struct Policy {
	pub(crate) max_slots: u16,
	pub(crate) max_budget_msat: u64,
	pub(crate) max_epoch_blocks: u32,
	pub(crate) min_fee_base_msat: u32,
	pub(crate) min_fee_ppm: u32,
}

/// Facts obtained under the native channel lock. The balance excludes native
/// reserves, both anchors, and the full voucher commitment fee at twice the
/// frozen feerate. The native caller must calculate this, not a wire caller.
pub(crate) struct SetupContext {
	pub(crate) channel_id: [u8; 32],
	pub(crate) remote_node: PublicKey,
	pub(crate) usable_anchor_channel: bool,
	pub(crate) concurrent_features_negotiated: bool,
	pub(crate) idle_without_splice: bool,
	pub(crate) current_height: u32,
	pub(crate) next_local_htlc_id: u64,
	pub(crate) local_commitment_number: u64,
	pub(crate) max_accepted_htlcs: u16,
	pub(crate) max_in_flight_msat: u64,
	pub(crate) minimum_htlc_msat: u64,
	pub(crate) minimum_untrimmed_msat: u64,
	pub(crate) available_after_reserves_and_fee_msat: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct FeePolicy {
	pub(crate) base_msat: u32,
	pub(crate) ppm: u32,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum ForwardAmount {
	Plaintext(u64),
	Blinded,
}

/// Constructed only after the upstream add is committed in both native views.
/// Advertised fee policy is allowed only after validating channel announcement
/// signatures and that its node and funding keys name a local channel to R.
pub(crate) struct DelegationContext {
	pub(crate) upstream: Upstream,
	pub(crate) payment_hash: [u8; 32],
	pub(crate) irrevocably_committed: bool,
	pub(crate) current_height: u32,
	pub(crate) incoming_cltv: u32,
	pub(crate) forwarding_delta: u32,
	pub(crate) incoming_msat: u64,
	pub(crate) forward: ForwardAmount,
	pub(crate) verified_advertised_fee: Option<FeePolicy>,
}

fn next(
	previous: &FforJournal, epoch: SettlerEpoch, actions: Vec<Action>,
) -> Result<PreparedTransition, Error> {
	Ok(PreparedTransition {
		journal: FforJournal::prepare(
			Some(previous),
			previous.revision.checked_add(1).ok_or(Error::Limit)?,
			epoch,
			previous.activation_snapshot.clone(),
		)?,
		after_persistence: actions,
	})
}

fn prefix(epoch: &SettlerEpoch) -> Vec<u8> {
	let mut bytes = epoch.channel_id.to_vec();
	bytes.extend_from_slice(&epoch.epoch_id);
	bytes
}

fn append_bigsize(out: &mut Vec<u8>, n: u64) {
	match n {
		0..=0xfc => out.push(n as u8),
		0xfd..=0xffff => {
			out.push(0xfd);
			out.extend_from_slice(&(n as u16).to_be_bytes());
		},
		0x10000..=0xffffffff => {
			out.push(0xfe);
			out.extend_from_slice(&(n as u32).to_be_bytes());
		},
		_ => {
			out.push(0xff);
			out.extend_from_slice(&n.to_be_bytes());
		},
	}
}
fn append_tlv(out: &mut Vec<u8>, typ: u64, value: &[u8]) {
	append_bigsize(out, typ);
	append_bigsize(out, value.len() as u64);
	out.extend_from_slice(value);
}
fn sign<S: NodeSigner + ?Sized>(
	signer: &S, kind: Kind, unsigned: &[u8],
) -> Result<SignedMessage, Error> {
	if !signer.supports_ffor_settler() {
		return Err(Error::Unsupported);
	}
	let signature =
		signer.sign_ffor_message(kind as u16, unsigned).map_err(|_| Error::Signature)?;
	let message = SignedMessage::from_parts(kind, unsigned, signature.serialize_compact())?;
	message.verify(
		&Secp256k1::verification_only(),
		&signer.get_node_id(Recipient::Node).map_err(|_| Error::Signature)?,
	)?;
	Ok(message)
}
fn message(epoch: &SettlerEpoch, kind: Kind) -> Result<&SignedMessage, Error> {
	epoch.messages.iter().find(|m| m.kind == kind).ok_or(Error::Invalid)
}
fn peer_message(epoch: &SettlerEpoch, msg: &SignedMessage, kind: Kind) -> Result<(), Error> {
	if msg.kind != kind || msg.channel_id != epoch.channel_id || msg.epoch_id != epoch.epoch_id {
		return Err(Error::Invalid);
	}
	msg.verify(&Secp256k1::verification_only(), &epoch.remote_node)
}
fn h_act(epoch: &SettlerEpoch) -> Result<[u8; 32], Error> {
	message(epoch, Kind::ActivateAck)?.unsigned()[64..96].try_into().map_err(|_| Error::Invalid)
}

/// Prepare all secret custody before any accept frame or voucher add can leave.
pub(crate) fn prepare_setup<S: NodeSigner + ?Sized, E: EntropySource + ?Sized>(
	previous: Option<&FforJournal>, init: SignedMessage, context: &SetupContext, policy: &Policy,
	signer: &S, entropy: &E,
) -> Result<PreparedTransition, Error> {
	if !context.usable_anchor_channel
		|| !context.concurrent_features_negotiated
		|| !context.idle_without_splice
		|| context.current_height == 0
		|| init.channel_id != context.channel_id
		|| !signer.supports_ffor_settler()
	{
		return Err(Error::Unsupported);
	}
	init.verify(&Secp256k1::verification_only(), &context.remote_node)?;
	let terms = init.settler_terms()?;
	let count = terms.amounts_msat.len();
	if count > policy.max_slots as usize
		|| count > context.max_accepted_htlcs as usize
		|| terms.budget_msat > policy.max_budget_msat
		|| terms.budget_msat > context.max_in_flight_msat
		|| terms.budget_msat > context.available_after_reserves_and_fee_msat
		|| terms.deadline <= context.current_height
		|| terms
			.expiry
			.checked_sub(context.current_height)
			.map_or(true, |n| n > policy.max_epoch_blocks || n > 5040)
		|| terms.fee_base_msat < policy.min_fee_base_msat
		|| terms.fee_ppm < policy.min_fee_ppm
		|| context.local_commitment_number >= (1u64 << 48)
		|| terms
			.amounts_msat
			.iter()
			.any(|n| *n < context.minimum_htlc_msat || *n < context.minimum_untrimmed_msat)
	{
		return Err(Error::Invalid);
	}
	let mut slots = Vec::with_capacity(count);
	for (i, amount) in terms.amounts_msat.iter().enumerate() {
		let fee = fee(*amount, FeePolicy { base_msat: terms.fee_base_msat, ppm: terms.fee_ppm })?;
		amount.checked_add(fee).ok_or(Error::Limit)?;
		let preimage = entropy.get_secure_random_bytes();
		slots.push(Slot {
			entry: BookEntry {
				slot: (i + 1) as u16,
				payment_hash: digest(&[&preimage]),
				amount_msat: *amount,
				expiry: terms.expiry,
				deadline: terms.deadline,
				htlc_id: context.next_local_htlc_id.checked_add(i as u64).ok_or(Error::Limit)?,
			},
			preimage,
			state: SlotState::Unused,
			upstream: None,
			redeemed: false,
			removal: None,
			chain_removal: None,
		});
	}
	let mut epoch = SettlerEpoch {
		channel_id: init.channel_id,
		epoch_id: init.epoch_id,
		local_node: signer.get_node_id(Recipient::Node).map_err(|_| Error::Signature)?,
		remote_node: context.remote_node,
		phase: Phase::Negotiating,
		capability_hold: false,
		activation_mismatch: false,
		activation_ack_pending: false,
		abort_reason: None,
		abort: None,
		messages: vec![init],
		slots,
	};
	let mut bytes = prefix(&epoch);
	bytes.extend_from_slice(&context.local_commitment_number.to_be_bytes());
	append_tlv(
		&mut bytes,
		1,
		&epoch.slots.iter().flat_map(|s| s.entry.payment_hash).collect::<Vec<_>>(),
	);
	append_tlv(&mut bytes, 7, &context.next_local_htlc_id.to_be_bytes());
	append_tlv(&mut bytes, 9, message(&epoch, Kind::Init)?.tlv(9).ok_or(Error::Invalid)?);
	append_tlv(&mut bytes, 11, &init_hash(&epoch.messages[0].encode()));
	append_tlv(&mut bytes, 17, &2u16.to_be_bytes());
	let accept = sign(signer, Kind::Accept, &bytes)?;
	epoch.messages.push(accept.clone());
	let revision = previous.map_or(Ok(1), |p| p.revision.checked_add(1).ok_or(Error::Limit))?;
	Ok(PreparedTransition {
		journal: FforJournal::prepare(previous, revision, epoch, None)?,
		after_persistence: vec![Action::Send(accept), Action::OfferVouchers],
	})
}

/// The caller must obtain this snapshot under the native quiescence barrier,
/// after the final voucher revoke in both directions, and persist it natively.
pub(crate) fn vouchers_committed(
	previous: &FforJournal, snapshot: CommitmentSnapshot,
) -> Result<PreparedTransition, Error> {
	if previous.epoch.phase != Phase::Negotiating
		|| previous.epoch.slots.iter().any(|slot| slot.chain_removal.is_some())
	{
		return Err(Error::Invalid);
	}
	snapshot.validate(&previous.epoch)?;
	let mut epoch = previous.epoch.clone();
	epoch.phase = Phase::VouchersCommitted;
	Ok(PreparedTransition {
		journal: FforJournal::prepare(
			Some(previous),
			previous.revision.checked_add(1).ok_or(Error::Limit)?,
			epoch,
			Some(snapshot),
		)?,
		after_persistence: Vec::new(),
	})
}

pub(crate) fn prepare_activate<S: NodeSigner + ?Sized>(
	previous: &FforJournal, activate: SignedMessage, snapshot: &CommitmentSnapshot, height: u32,
	signer: &S,
) -> Result<PreparedTransition, Error> {
	let old = &previous.epoch;
	peer_message(old, &activate, Kind::Activate)?;
	if old.phase != Phase::VouchersCommitted
		|| previous.activation_snapshot.as_ref() != Some(snapshot)
		|| old.slots.iter().any(|slot| slot.chain_removal.is_some())
	{
		return Err(Error::Invalid);
	}
	snapshot.validate(old)?;
	let setup = setup_hash(
		&init_hash(&message(old, Kind::Init)?.encode()),
		&message(old, Kind::Accept)?.encode(),
	);
	let book = book_hash(&encode_book(
		&old.epoch_id,
		&old.slots.iter().map(|s| s.entry.clone()).collect::<Vec<_>>(),
	)?);
	let commit = commitment_hash(
		snapshot.receiver_number,
		&snapshot.receiver_txid.to_byte_array(),
		snapshot.settler_number,
		&snapshot.settler_txid.to_byte_array(),
	);
	let bytes = activate.unsigned();
	let start = u32::from_be_bytes(bytes[160..164].try_into().map_err(|_| Error::Invalid)?);
	if bytes[64..96] != setup
		|| bytes[96..128] != book
		|| bytes[128..160] != commit
		|| height.abs_diff(start) > 6
	{
		return Err(Error::Invalid);
	}
	let terms = message(old, Kind::Init)?.settler_terms()?;
	if height >= terms.deadline {
		return Err(Error::Invalid);
	}
	let mut ack = prefix(old);
	ack.extend_from_slice(&activation_hash(&setup, &book, &commit, start));
	let ack = sign(signer, Kind::ActivateAck, &ack)?;
	let mut epoch = old.clone();
	epoch.phase = Phase::Active;
	epoch.activation_ack_pending = true;
	epoch.messages.extend([activate, ack.clone()]);
	next(previous, epoch, vec![Action::Send(ack), Action::ExitQuiescence])
}

pub(crate) fn activation_ack_sent(previous: &FforJournal) -> Result<PreparedTransition, Error> {
	if previous.epoch.phase != Phase::Active || !previous.epoch.activation_ack_pending {
		return Err(Error::Invalid);
	}
	let mut epoch = previous.epoch.clone();
	epoch.activation_ack_pending = false;
	next(previous, epoch, Vec::new())
}

fn fee(amount: u64, policy: FeePolicy) -> Result<u64, Error> {
	let product = amount.checked_mul(policy.ppm as u64).ok_or(Error::Limit)?;
	(product / 1_000_000).checked_add(policy.base_msat as u64).ok_or(Error::Limit)
}
fn check_amount(amount: u64, terms: &InitTerms, ctx: &DelegationContext) -> Result<(), Error> {
	let policy = FeePolicy { base_msat: terms.fee_base_msat, ppm: terms.fee_ppm };
	let forward = match ctx.forward {
		ForwardAmount::Plaintext(forward) => {
			if forward != amount {
				return Err(Error::Invalid);
			}
			forward
		},
		ForwardAmount::Blinded => {
			let net =
				ctx.incoming_msat.checked_sub(policy.base_msat as u64).ok_or(Error::Invalid)?
					as u128;
			let divisor = 1_000_000u128 + policy.ppm as u128;
			let forward = (net * 1_000_000 + divisor - 1) / divisor;
			let slack = 17 + (8 * amount as u128 + 999_999) / 1_000_000;
			if forward < amount as u128
				|| forward > amount as u128 + slack
				|| forward > u64::MAX as u128
			{
				return Err(Error::Invalid);
			}
			forward as u64
		},
	};
	let paid = ctx.incoming_msat.checked_sub(forward).ok_or(Error::Invalid)?;
	if paid >= fee(amount, policy)? {
		return Ok(());
	}
	if matches!(ctx.forward, ForwardAmount::Plaintext(_)) {
		if let Some(policy) = ctx.verified_advertised_fee {
			if paid >= fee(amount, policy)? {
				return Ok(());
			}
		}
	}
	Err(Error::Invalid)
}

pub(crate) fn prepare_settlement(
	previous: &FforJournal, slot: u16, ctx: &DelegationContext,
) -> Result<PreparedTransition, Error> {
	let old = &previous.epoch;
	let index = (slot as usize).checked_sub(1).ok_or(Error::Invalid)?;
	let item = old.slots.get(index).ok_or(Error::Invalid)?;
	if item.entry.payment_hash != ctx.payment_hash
		|| item.state != SlotState::Unused
		|| item.redeemed
		|| item.chain_removal.is_some()
	{
		return Err(Error::Invalid);
	}
	let terms = message(old, Kind::Init)?.settler_terms()?;
	if old.phase != Phase::Active
		|| old.capability_hold
		|| old.activation_mismatch
		|| !ctx.irrevocably_committed
		|| ctx.current_height == 0
		|| ctx.current_height >= terms.deadline
		|| ctx
			.current_height
			.checked_add(ctx.forwarding_delta)
			.map_or(true, |n| ctx.incoming_cltv <= n)
		|| (!terms.witness_peers.is_empty()
			&& !terms.witness_peers.contains(&ctx.upstream.counterparty_node_id))
	{
		return Err(Error::Invalid);
	}
	check_amount(item.entry.amount_msat, &terms, ctx)?;
	let mut epoch = old.clone();
	epoch.slots[index].state = SlotState::Settling;
	epoch.slots[index].upstream = Some(ctx.upstream.clone());
	next(previous, epoch, vec![Action::ClaimUpstream { slot, upstream: ctx.upstream.clone() }])
}

/// Called only after the corresponding upstream claim's monitor barrier.
pub(crate) fn settlement_completed(
	previous: &FforJournal, slot: u16, upstream: &Upstream,
) -> Result<PreparedTransition, Error> {
	let mut epoch = previous.epoch.clone();
	let item = epoch
		.slots
		.get_mut((slot as usize).checked_sub(1).ok_or(Error::Invalid)?)
		.ok_or(Error::Invalid)?;
	if item.state != SlotState::Settling || item.upstream.as_ref() != Some(upstream) {
		return Err(Error::Invalid);
	}
	item.state = SlotState::Settled;
	maybe_closed(&mut epoch);
	next(previous, epoch, Vec::new())
}

fn maybe_closed(epoch: &mut SettlerEpoch) {
	if epoch.phase == Phase::Draining
		&& epoch.slots.iter().all(|s| {
			(s.removal.is_some() || s.chain_removal.is_some()) && s.state != SlotState::Settling
		}) {
		epoch.phase = Phase::Closed;
	}
}

/// Record native proof of voucher fulfillment and, separately, irreversible
/// removal from both commitment views. A received fulfill alone is not removal.
/// Chain resolution is retained by the monitor until it can supply its own
/// durable proof; this function never invents commitment counters for it.
pub(crate) fn prepare_voucher_result(
	previous: &FforJournal, slot: u16, preimage: Option<[u8; 32]>, removal: Option<Removal>,
) -> Result<PreparedTransition, Error> {
	let mut epoch = previous.epoch.clone();
	let active = matches!(epoch.phase, Phase::Active | Phase::Draining | Phase::Closed);
	let aborted = epoch.phase == Phase::Aborted;
	let item = epoch
		.slots
		.get_mut((slot as usize).checked_sub(1).ok_or(Error::Invalid)?)
		.ok_or(Error::Invalid)?;
	if let Some(preimage) = preimage {
		if !active || preimage != item.preimage {
			return Err(Error::Invalid);
		}
		item.redeemed = true;
	}
	if let Some(removal) = removal {
		if removal.local_commitment >= (1u64 << 48)
			|| removal.remote_commitment >= (1u64 << 48)
			|| removal.fulfilled && !item.redeemed
			|| !removal.fulfilled && !aborted
			|| item.removal.as_ref().is_some_and(|old| old != &removal)
		{
			return Err(Error::Invalid);
		}
		item.removal = Some(removal);
	}
	maybe_closed(&mut epoch);
	next(previous, epoch, Vec::new())
}

/// Record a resolution authenticated by the native monitor after its anti-reorg
/// delay. This preserves every bound upstream obligation, even if the home output
/// timed out. Exact replay retains the same proof; a conflicting proof is refused.
/// The caller must persist this transition before releasing monitor claim custody.
pub(crate) fn prepare_chain_resolution(
	previous: &FforJournal, slot: u16, evidence: ChainRemoval,
) -> Result<PreparedTransition, Error> {
	let mut epoch = previous.epoch.clone();
	let activated = matches!(epoch.phase, Phase::Active | Phase::Draining | Phase::Closed);
	let item = epoch
		.slots
		.get_mut((slot as usize).checked_sub(1).ok_or(Error::Invalid)?)
		.ok_or(Error::Invalid)?;
	if item.chain_removal.as_ref().is_some_and(|old| old != &evidence) {
		return Err(Error::Invalid);
	}
	if activated && evidence.fulfilled {
		item.redeemed = true;
	}
	item.chain_removal = Some(evidence);
	maybe_closed(&mut epoch);
	next(previous, epoch, Vec::new())
}

/// A durable obligation survives deadlines, disconnect, draining and restart.
/// This never manufactures a binding and does not admit a second payment.
pub(crate) fn replay_settling(journal: &FforJournal) -> Vec<Action> {
	journal
		.epoch
		.slots
		.iter()
		.filter_map(|slot| {
			if slot.state == SlotState::Settling {
				slot.upstream.as_ref().map(|upstream| Action::ClaimUpstream {
					slot: slot.entry.slot,
					upstream: upstream.clone(),
				})
			} else {
				None
			}
		})
		.collect()
}

pub(crate) fn replay_claim(
	journal: &FforJournal, slot: u16, upstream: &Upstream,
) -> Result<Action, Error> {
	let item = journal
		.epoch
		.slots
		.get((slot as usize).checked_sub(1).ok_or(Error::Invalid)?)
		.ok_or(Error::Invalid)?;
	if item.state == SlotState::Unused || item.upstream.as_ref() != Some(upstream) {
		return Err(Error::Invalid);
	}
	Ok(Action::ClaimUpstream { slot, upstream: upstream.clone() })
}

/// Recognized hashes never fall through the ordinary forwarding path when
/// policy refuses them. The caller separately checks admission or exact replay.
pub(crate) fn identify_slot(journal: &FforJournal, payment_hash: &[u8; 32]) -> Option<u16> {
	journal.epoch.slots.iter().find(|s| &s.entry.payment_hash == payment_hash).map(|s| s.entry.slot)
}

fn receipt_content(epoch: &SettlerEpoch, include_settling: bool) -> (Vec<u8>, Vec<u8>) {
	let mut bitmap = vec![0; (epoch.slots.len() + 7) / 8];
	let mut receipts = Vec::new();
	for (i, slot) in epoch.slots.iter().enumerate() {
		if slot.state == SlotState::Settled
			|| slot.removal.as_ref().is_some_and(|removal| removal.fulfilled)
			|| slot.chain_removal.as_ref().is_some_and(|removal| removal.fulfilled)
			|| include_settling && (slot.redeemed || slot.state == SlotState::Settling)
		{
			bitmap[i / 8] |= 1 << (i % 8);
			receipts.extend_from_slice(&slot.entry.slot.to_be_bytes());
			receipts.extend_from_slice(&slot.preimage);
		}
	}
	(bitmap, receipts)
}

pub(crate) fn prepare_sync<S: NodeSigner + ?Sized>(
	previous: &FforJournal, request: &SignedMessage, signer: &S,
) -> Result<PreparedTransition, Error> {
	let old = &previous.epoch;
	peer_message(old, request, Kind::Sync)?;
	if request.unsigned()[64..96] != h_act(old)? {
		return Err(Error::Invalid);
	}
	if matches!(old.phase, Phase::Draining | Phase::Closed) {
		return next(
			previous,
			old.clone(),
			vec![Action::Send(message(old, Kind::CloseAck)?.clone())],
		);
	}
	if old.phase != Phase::Active
		|| old.activation_mismatch
		|| old.activation_ack_pending
		|| request.unsigned()[64..96] != h_act(old)?
	{
		return Err(Error::Invalid);
	}
	let (bitmap, receipts) = receipt_content(old, false);
	let mut content = (old.slots.len() as u16).to_be_bytes().to_vec();
	content.extend_from_slice(&bitmap);
	content.extend_from_slice(&((receipts.len() / 34) as u16).to_be_bytes());
	content.extend_from_slice(&receipts);
	let previous_reply = old.messages.iter().find(|m| m.kind == Kind::SyncReply);
	let seq = if let Some(reply) = previous_reply {
		let old_seq =
			u64::from_be_bytes(reply.unsigned()[128..136].try_into().map_err(|_| Error::Invalid)?);
		old_seq.checked_add((reply.unsigned()[136..] != content) as u64).ok_or(Error::Limit)?
	} else {
		(!receipts.is_empty()) as u64
	};
	let mut bytes = prefix(old);
	bytes.extend_from_slice(&h_act(old)?);
	bytes.extend_from_slice(&request.unsigned()[96..128]);
	bytes.extend_from_slice(&seq.to_be_bytes());
	bytes.extend_from_slice(&content);
	let reply = sign(signer, Kind::SyncReply, &bytes)?;
	let mut epoch = old.clone();
	epoch.messages.retain(|m| m.kind != Kind::SyncReply);
	epoch.messages.push(reply.clone());
	next(previous, epoch, vec![Action::Send(reply)])
}

pub(crate) fn prepare_close<S: NodeSigner + ?Sized>(
	previous: &FforJournal, close: SignedMessage, signer: &S,
) -> Result<PreparedTransition, Error> {
	let old = &previous.epoch;
	peer_message(old, &close, Kind::Close)?;
	if old.phase != Phase::Active || close.unsigned()[64..96] != h_act(old)? {
		return Err(Error::Invalid);
	}
	// A SETTLING slot is already a durable obligation. Its close receipt cannot
	// be withdrawn even if the upstream completion action has not run yet.
	let (bitmap, receipts) = receipt_content(old, true);
	let mut bytes = prefix(old);
	bytes.extend_from_slice(&h_act(old)?);
	bytes.extend_from_slice(&(old.slots.len() as u16).to_be_bytes());
	bytes.extend_from_slice(&bitmap);
	append_tlv(&mut bytes, 1, &receipts);
	let ack = sign(signer, Kind::CloseAck, &bytes)?;
	let mut epoch = old.clone();
	epoch.phase = Phase::Draining;
	epoch.messages.extend([close, ack.clone()]);
	// Preserve SETTLING until the upstream monitor confirms the claim. This is
	// stronger custody accounting than treating the close receipt as completion.
	next(previous, epoch, vec![Action::Send(ack)])
}

pub(crate) fn prepare_abort<S: NodeSigner + ?Sized>(
	previous: &FforJournal, reason: u16, signer: &S,
) -> Result<PreparedTransition, Error> {
	let old = &previous.epoch;
	if !matches!(old.phase, Phase::Negotiating | Phase::VouchersCommitted) {
		return Err(Error::Invalid);
	}
	let init = init_hash(&message(old, Kind::Init)?.encode());
	let transcript = if let Ok(accept) = message(old, Kind::Accept) {
		setup_hash(&init, &accept.encode())
	} else {
		init
	};
	let mut bytes = prefix(old);
	bytes.extend_from_slice(&transcript);
	bytes.extend_from_slice(&reason.to_be_bytes());
	bytes.extend_from_slice(&0u16.to_be_bytes());
	let abort = sign(signer, Kind::Abort, &bytes)?;
	let mut epoch = old.clone();
	epoch.phase = Phase::Aborted;
	epoch.activation_ack_pending = false;
	epoch.abort_reason = Some(reason);
	epoch.abort = Some(AbortRecord { local: true, message: abort.clone() });
	next(previous, epoch, vec![Action::Send(abort), Action::CancelSetupVouchers])
}

pub(crate) fn prepare_peer_abort(
	previous: &FforJournal, abort: SignedMessage,
) -> Result<PreparedTransition, Error> {
	let old = &previous.epoch;
	peer_message(old, &abort, Kind::Abort)?;
	if !matches!(old.phase, Phase::Negotiating | Phase::VouchersCommitted) {
		return Err(Error::Invalid);
	}
	let reason =
		u16::from_be_bytes(abort.unsigned()[96..98].try_into().map_err(|_| Error::Invalid)?);
	let mut epoch = old.clone();
	epoch.phase = Phase::Aborted;
	epoch.activation_ack_pending = false;
	epoch.abort_reason = Some(reason);
	epoch.abort = Some(AbortRecord { local: false, message: abort });
	// The epoch validator checks the exact setup or init transcript binding.
	next(previous, epoch, vec![Action::CancelSetupVouchers])
}

/// Exact duplicate requests may only replay already durable signed responses.
pub(crate) fn replay_response(
	journal: &FforJournal, request: &SignedMessage,
) -> Result<Action, Error> {
	let response = match request.kind {
		Kind::Init => Kind::Accept,
		Kind::Activate => Kind::ActivateAck,
		Kind::Close => Kind::CloseAck,
		_ => return Err(Error::Unsupported),
	};
	if message(&journal.epoch, request.kind)? != request {
		return Err(Error::Invalid);
	}
	Ok(Action::Send(message(&journal.epoch, response)?.clone()))
}

/// Ordinary disconnection preserves an activated offline service. Setup cannot
/// survive it because neither side has an enforceable activated transcript yet.
pub(crate) fn prepare_disconnect<S: NodeSigner + ?Sized>(
	previous: &FforJournal, signer: &S,
) -> Result<Option<PreparedTransition>, Error> {
	if matches!(previous.epoch.phase, Phase::Negotiating | Phase::VouchersCommitted) {
		Ok(Some(prepare_abort(previous, 6, signer)?))
	} else {
		Ok(None)
	}
}

/// Native channel_reestablish must call this after checking its ordinary BOLT
/// counters and before releasing new home-channel traffic. `negotiated` means
/// both base and concurrent feature pairs in this connection's authenticated
/// init exchange, never merely a saved channel setting.
pub(crate) fn prepare_reestablish<S: NodeSigner + ?Sized>(
	previous: &FforJournal, peer: Option<&Reestablish>, negotiated: bool, signer: &S,
) -> Result<PreparedTransition, Error> {
	let old = &previous.epoch;
	if let Some(peer) = peer {
		peer.encode()?;
	}
	if matches!(old.phase, Phase::Negotiating | Phase::VouchersCommitted) {
		return prepare_abort(previous, 6, signer);
	}
	let mut epoch = old.clone();
	epoch.capability_hold = matches!(old.phase, Phase::Active | Phase::Draining) && !negotiated;
	let peer = peer.filter(|p| p.epoch_id == old.epoch_id);
	let mut actions = Vec::new();
	if matches!(old.phase, Phase::Active | Phase::Draining | Phase::Closed) {
		let activation = h_act(old)?;
		match peer {
			None => epoch.activation_mismatch = true,
			Some(peer) if peer.state == Phase::Aborted as u8 => epoch.activation_mismatch = true,
			Some(peer)
				if peer.state >= Phase::Active as u8 && peer.activation_hash != activation =>
			{
				epoch.activation_mismatch = true
			},
			Some(peer) if old.phase == Phase::Active && peer.state < Phase::Active as u8 => {
				actions.push(Action::Send(message(old, Kind::ActivateAck)?.clone()));
			},
			Some(peer)
				if matches!(old.phase, Phase::Draining | Phase::Closed)
					&& peer.state == Phase::Active as u8 =>
			{
				actions.push(Action::Send(message(old, Kind::CloseAck)?.clone()));
			},
			_ => {},
		}
		epoch.activation_ack_pending =
			actions.iter().any(|a| matches!(a, Action::Send(m) if m.kind == Kind::ActivateAck));
	} else if old.phase == Phase::Aborted {
		if let Some(abort) = &old.abort {
			if abort.local {
				actions.push(Action::Send(abort.message.clone()));
			}
		}
		actions.push(Action::CancelSetupVouchers);
	}
	next(previous, epoch, actions)
}

pub(crate) fn reestablish(journal: &FforJournal) -> Result<Reestablish, Error> {
	Ok(Reestablish {
		epoch_id: journal.epoch.epoch_id,
		state: journal.epoch.phase as u8,
		last_seq: 0,
		activation_hash: if matches!(
			journal.epoch.phase,
			Phase::Active | Phase::Draining | Phase::Closed
		) {
			h_act(&journal.epoch)?
		} else {
			[0; 32]
		},
	})
}
