// Copyright (c) 2023 Synonym. MIT license, see LICENSE-BEIGNET.
// Internal serialization groundwork. No transition here authorizes a wire emit.

use super::*;

const MAX_RECORD: usize = 512 * 1024;
const MAX_ARCHIVE: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum Phase {
	Negotiating = 0,
	VouchersCommitted = 1,
	Active = 3,
	Draining = 4,
	Closed = 5,
	Aborted = 6,
}
impl Phase {
	fn read(n: u8) -> Result<Self, Error> {
		Ok(match n {
			0 => Self::Negotiating,
			1 => Self::VouchersCommitted,
			3 => Self::Active,
			4 => Self::Draining,
			5 => Self::Closed,
			6 => Self::Aborted,
			_ => return Err(Error::Invalid),
		})
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SlotState {
	Unused,
	Settling,
	Settled,
}

/// The exact upstream identity bound before a preimage may be released.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Upstream {
	pub(crate) counterparty_node_id: PublicKey,
	pub(crate) funding_txo: crate::chain::transaction::OutPoint,
	pub(crate) channel_id: [u8; 32],
	pub(crate) htlc_id: u64,
}

/// Evidence that both commitment views removed a voucher. Learning a preimage is
/// not removal evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Removal {
	pub(crate) fulfilled: bool,
	pub(crate) local_commitment: u64,
	pub(crate) remote_commitment: u64,
}

/// Native monitor evidence after the chain's anti-reorg delay. A missing output
/// index means the commitment itself proves the voucher absent. The driver does
/// not authenticate transactions; only the native monitor may supply this value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ChainRemoval {
	pub(crate) commitment_txid: [u8; 32],
	pub(crate) output_index: Option<u32>,
	pub(crate) resolving_txid: [u8; 32],
	pub(crate) fulfilled: bool,
}

// Deliberately no Debug: the settler owns preimages even for unpaid slots.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct Slot {
	pub(crate) entry: BookEntry,
	pub(crate) preimage: [u8; 32],
	pub(crate) state: SlotState,
	pub(crate) upstream: Option<Upstream>,
	pub(crate) redeemed: bool,
	pub(crate) removal: Option<Removal>,
	pub(crate) chain_removal: Option<ChainRemoval>,
}

impl Slot {
	fn validate(&self) -> Result<(), Error> {
		if digest(&[&self.preimage]) != self.entry.payment_hash {
			return Err(Error::Invalid);
		}
		if (self.state == SlotState::Unused) != self.upstream.is_none() {
			return Err(Error::Invalid);
		}
		if self.removal.as_ref().map_or(false, |r| r.fulfilled) && !self.redeemed {
			return Err(Error::Invalid);
		}
		if self.chain_removal.as_ref().is_some_and(|proof| {
			proof.output_index.is_none()
				&& (proof.fulfilled || proof.resolving_txid != proof.commitment_txid)
		}) {
			return Err(Error::Invalid);
		}
		Ok(())
	}
	fn write(&self, out: &mut Vec<u8>) {
		self.entry.write(out);
		out.extend_from_slice(&self.preimage);
		out.push(match self.state {
			SlotState::Unused => 0,
			SlotState::Settling => 1,
			SlotState::Settled => 2,
		});
		if let Some(u) = &self.upstream {
			out.extend_from_slice(&u.counterparty_node_id.serialize());
			out.extend_from_slice(&u.funding_txo.txid.to_byte_array());
			out.extend_from_slice(&u.funding_txo.index.to_be_bytes());
			out.extend_from_slice(&u.channel_id);
			out.extend_from_slice(&u.htlc_id.to_be_bytes());
		}
		out.push(self.redeemed as u8);
		out.push(self.removal.is_some() as u8);
		if let Some(r) = &self.removal {
			out.push(r.fulfilled as u8);
			out.extend_from_slice(&r.local_commitment.to_be_bytes());
			out.extend_from_slice(&r.remote_commitment.to_be_bytes());
		}
		out.push(self.chain_removal.is_some() as u8);
		if let Some(r) = &self.chain_removal {
			out.extend_from_slice(&r.commitment_txid);
			out.push(r.output_index.is_some() as u8);
			if let Some(index) = r.output_index {
				out.extend_from_slice(&index.to_be_bytes());
			}
			out.extend_from_slice(&r.resolving_txid);
			out.push(r.fulfilled as u8);
		}
	}
	fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
		let entry = BookEntry::read(r)?;
		let preimage = r.array()?;
		let state = match r.u8()? {
			0 => SlotState::Unused,
			1 => SlotState::Settling,
			2 => SlotState::Settled,
			_ => return Err(Error::Invalid),
		};
		let upstream = if state == SlotState::Unused {
			None
		} else {
			Some(Upstream {
				counterparty_node_id: PublicKey::from_slice(r.take(33)?)
					.map_err(|_| Error::Invalid)?,
				funding_txo: crate::chain::transaction::OutPoint {
					txid: bitcoin::Txid::from_byte_array(r.array()?),
					index: r.u16()?,
				},
				channel_id: r.array()?,
				htlc_id: r.u64()?,
			})
		};
		let redeemed = boolean(r)?;
		let removal = if boolean(r)? {
			Some(Removal {
				fulfilled: boolean(r)?,
				local_commitment: r.u64()?,
				remote_commitment: r.u64()?,
			})
		} else {
			None
		};
		let chain_removal = if boolean(r)? {
			Some(ChainRemoval {
				commitment_txid: r.array()?,
				output_index: if boolean(r)? { Some(r.u32()?) } else { None },
				resolving_txid: r.array()?,
				fulfilled: boolean(r)?,
			})
		} else {
			None
		};
		let slot = Self { entry, preimage, state, upstream, redeemed, removal, chain_removal };
		slot.validate()?;
		Ok(slot)
	}
}

fn boolean(r: &mut Reader<'_>) -> Result<bool, Error> {
	match r.u8()? {
		0 => Ok(false),
		1 => Ok(true),
		_ => Err(Error::Invalid),
	}
}
fn bytes_write(out: &mut Vec<u8>, bytes: &[u8]) {
	out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
	out.extend_from_slice(bytes);
}
fn bytes_read(r: &mut Reader<'_>) -> Result<Vec<u8>, Error> {
	let n = r.u32()? as usize;
	if n > MAX_BODY + 2 {
		return Err(Error::Limit);
	}
	Ok(r.take(n)?.to_vec())
}

/// S-only concurrent-v2 journal value. This is a candidate storage schema, not a
/// channel state-machine implementation. Its owner must bind both node ids to the
/// actual channel, enforce transition ordering and atomically persist monitor changes.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SettlerEpoch {
	pub(crate) channel_id: [u8; 32],
	pub(crate) epoch_id: [u8; 32],
	pub(crate) local_node: PublicKey,
	pub(crate) remote_node: PublicKey,
	pub(crate) phase: Phase,
	pub(crate) capability_hold: bool,
	/// A missing or conflicting activated epoch at reestablish is durable
	/// evidence of data loss. A later capability advertisement cannot clear it.
	pub(crate) activation_mismatch: bool,
	pub(crate) activation_ack_pending: bool,
	/// A disconnect can abort setup without a valid signed peer message. Such an
	/// abort retains its local reason but never invents signed peer evidence.
	pub(crate) abort_reason: Option<u16>,
	pub(crate) abort: Option<AbortRecord>,
	/// Exact init, accept, activation, activation ACK, close, close ACK, and last
	/// sync reply bytes. Never reconstruct replay transcripts from decoded fields.
	pub(crate) messages: Vec<SignedMessage>,
	pub(crate) slots: Vec<Slot>,
}

/// Exact signed abort evidence and its origin. Replay local messages verbatim;
/// received messages are evidence only, never relabeled as locally signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AbortRecord {
	pub(crate) local: bool,
	pub(crate) message: SignedMessage,
}

impl SettlerEpoch {
	pub(crate) fn validate(&self) -> Result<(), Error> {
		slots(self.slots.len())?;
		if self.messages.len() > 7 || self.local_node == self.remote_node {
			return Err(Error::Invalid);
		}
		let activated = matches!(self.phase, Phase::Active | Phase::Draining | Phase::Closed);
		if !activated
			&& (self.activation_mismatch
				|| self.activation_ack_pending
				|| self.slots.iter().any(|s| s.redeemed))
		{
			return Err(Error::Invalid);
		}
		let has_close = self.messages.iter().any(|m| m.kind == Kind::Close);
		let has_close_ack = self.messages.iter().any(|m| m.kind == Kind::CloseAck);
		if has_close != has_close_ack
			|| matches!(self.phase, Phase::Draining | Phase::Closed) != has_close
		{
			return Err(Error::Invalid);
		}
		let secp = Secp256k1::verification_only();
		for (i, msg) in self.messages.iter().enumerate() {
			if msg.channel_id != self.channel_id
				|| msg.epoch_id != self.epoch_id
				|| self.messages[..i].iter().any(|m| m.kind == msg.kind)
			{
				return Err(Error::Invalid);
			}
			let signer = match msg.kind {
				Kind::Init | Kind::Activate | Kind::Close => &self.remote_node,
				Kind::Accept | Kind::ActivateAck | Kind::CloseAck | Kind::SyncReply => {
					&self.local_node
				},
				_ => return Err(Error::Unsupported),
			};
			msg.verify(&secp, signer)?;
		}
		let init = self.messages.iter().find(|m| m.kind == Kind::Init).ok_or(Error::Invalid)?;
		init.settler_terms()?;
		if (self.phase == Phase::Aborted) != self.abort_reason.is_some() {
			return Err(Error::Invalid);
		}
		if self.phase == Phase::Aborted
			&& (self.activation_ack_pending
				|| self.messages.iter().any(|m| {
					matches!(
						m.kind,
						Kind::ActivateAck | Kind::Close | Kind::CloseAck | Kind::SyncReply
					)
				})) {
			return Err(Error::Invalid);
		}
		if let Some(abort) = &self.abort {
			let msg = &abort.message;
			if self.phase != Phase::Aborted
				|| msg.kind != Kind::Abort
				|| msg.channel_id != self.channel_id
				|| msg.epoch_id != self.epoch_id
			{
				return Err(Error::Invalid);
			}
			msg.verify(&secp, if abort.local { &self.local_node } else { &self.remote_node })?;
			let expected = match self.messages.iter().find(|m| m.kind == Kind::Accept) {
				Some(accept) => setup_hash(&init_hash(&init.encode()), &accept.encode()),
				None => init_hash(&init.encode()),
			};
			let reason =
				u16::from_be_bytes(msg.unsigned()[96..98].try_into().map_err(|_| Error::Invalid)?);
			if msg.unsigned()[64..96] != expected || Some(reason) != self.abort_reason {
				return Err(Error::Invalid);
			}
		}
		if init.concurrent_version() != Some(2) {
			return Err(Error::Unsupported);
		}
		let amounts = init.tlv(9).ok_or(Error::Invalid)?;
		if amounts.len() != self.slots.len() * 8 {
			return Err(Error::Invalid);
		}
		let mut terms = Reader::new(&init.unsigned()[65..]);
		let budget = terms.u64()?;
		let count = terms.u16()? as usize;
		let minimum = terms.u64()?;
		let deadline = terms.u32()?;
		let expiry = terms.u32()?;
		if count != self.slots.len() || expiry.checked_sub(deadline).map_or(true, |d| d < 1008) {
			return Err(Error::Invalid);
		}
		let mut sum = 0u64;
		for (i, slot) in self.slots.iter().enumerate() {
			slot.validate()?;
			if activated
				&& slot.chain_removal.as_ref().is_some_and(|proof| proof.fulfilled)
				&& !slot.redeemed
			{
				return Err(Error::Invalid);
			}
			if slot.state != SlotState::Unused
				&& !matches!(self.phase, Phase::Active | Phase::Draining | Phase::Closed)
			{
				return Err(Error::Invalid);
			}
			// Only an aborted pre-activation setup can cancel a v2 voucher.
			if slot.removal.as_ref().map_or(false, |r| !r.fulfilled) && self.phase != Phase::Aborted
			{
				return Err(Error::Invalid);
			}
			let amount = u64::from_be_bytes(
				amounts[i * 8..(i + 1) * 8].try_into().map_err(|_| Error::Invalid)?,
			);
			if slot.entry.amount_msat != amount
				|| amount < minimum
				|| slot.entry.deadline != deadline
				|| slot.entry.expiry != expiry
			{
				return Err(Error::Invalid);
			}
			sum = sum.checked_add(amount).ok_or(Error::Limit)?;
		}
		if sum != budget {
			return Err(Error::Invalid);
		}
		let book = encode_book(
			&self.epoch_id,
			&self.slots.iter().map(|s| s.entry.clone()).collect::<Vec<_>>(),
		)?;
		let accept = self.messages.iter().find(|m| m.kind == Kind::Accept);
		if let Some(a) = accept {
			if a.concurrent_version() != Some(2)
				|| a.tlv(11) != Some(init_hash(&init.encode()).as_slice())
				|| a.tlv(9) != Some(amounts)
			{
				return Err(Error::Invalid);
			}
			let hashes = a.tlv(1).ok_or(Error::Invalid)?;
			let mut base = Reader::new(a.tlv(7).ok_or(Error::Invalid)?);
			let first = base.u64()?;
			if hashes.len() != self.slots.len() * 32 {
				return Err(Error::Invalid);
			}
			for (i, s) in self.slots.iter().enumerate() {
				if hashes[i * 32..(i + 1) * 32] != s.entry.payment_hash
					|| first.checked_add(i as u64) != Some(s.entry.htlc_id)
				{
					return Err(Error::Invalid);
				}
			}
		} else if !matches!(self.phase, Phase::Negotiating | Phase::Aborted) {
			return Err(Error::Invalid);
		}
		if let Some(act) = self.messages.iter().find(|m| m.kind == Kind::Activate) {
			if !activated {
				return Err(Error::Invalid);
			}
			let a = accept.ok_or(Error::Invalid)?;
			let setup = setup_hash(&init_hash(&init.encode()), &a.encode());
			if act.unsigned()[64..96] != setup || act.unsigned()[96..128] != book_hash(&book) {
				return Err(Error::Invalid);
			}
			let commit: [u8; 32] =
				act.unsigned()[128..160].try_into().map_err(|_| Error::Invalid)?;
			let height = u32::from_be_bytes(
				act.unsigned()[160..164].try_into().map_err(|_| Error::Invalid)?,
			);
			let h_act = activation_hash(&setup, &book_hash(&book), &commit, height);
			for m in &self.messages {
				if matches!(
					m.kind,
					Kind::ActivateAck | Kind::Close | Kind::CloseAck | Kind::SyncReply
				) && m.unsigned()[64..96] != h_act
				{
					return Err(Error::Invalid);
				}
				if matches!(m.kind, Kind::CloseAck | Kind::SyncReply) {
					let (n, bitmap, receipt_bytes) = if m.kind == Kind::CloseAck {
						let mut r = Reader::new(&m.unsigned()[96..]);
						let n = r.u16()? as usize;
						(n, r.take((n + 7) / 8)?, m.tlv(1).unwrap_or(&[]))
					} else {
						let mut r = Reader::new(&m.unsigned()[136..]);
						let n = r.u16()? as usize;
						let bitmap = r.take((n + 7) / 8)?;
						let count = r.u16()? as usize;
						(n, bitmap, r.take(count * 34)?)
					};
					if n != self.slots.len() {
						return Err(Error::Invalid);
					}
					let mut receipts = Reader::new(receipt_bytes);
					for k in 1..=n {
						if bitmap[(k - 1) / 8] & (1 << ((k - 1) % 8)) == 0 {
							continue;
						}
						let slot = &self.slots[k - 1];
						let reportable = if m.kind == Kind::SyncReply {
							slot.state == SlotState::Settled
								|| slot.removal.as_ref().is_some_and(|removal| removal.fulfilled)
								|| slot
									.chain_removal
									.as_ref()
									.is_some_and(|removal| removal.fulfilled)
						} else {
							slot.redeemed || slot.state != SlotState::Unused
						};
						if receipts.u16()? as usize != k
							|| receipts.take(32)? != slot.preimage
							|| !reportable
						{
							return Err(Error::Invalid);
						}
					}
				}
			}
			if matches!(self.phase, Phase::Active | Phase::Draining | Phase::Closed)
				&& !self.messages.iter().any(|m| m.kind == Kind::ActivateAck)
			{
				return Err(Error::Invalid);
			}
		} else if matches!(self.phase, Phase::Active | Phase::Draining | Phase::Closed) {
			return Err(Error::Invalid);
		} else if self.messages.iter().any(|m| {
			matches!(m.kind, Kind::ActivateAck | Kind::Close | Kind::CloseAck | Kind::SyncReply)
		}) {
			return Err(Error::Invalid);
		}
		if self.phase == Phase::Closed
			&& self.slots.iter().any(|s| {
				(s.removal.is_none() && s.chain_removal.is_none()) || s.state == SlotState::Settling
			}) {
			return Err(Error::Invalid);
		}
		Ok(())
	}

	pub(crate) fn encode(&self) -> Result<Vec<u8>, Error> {
		self.validate()?;
		let mut out = b"FFS2\x04".to_vec();
		out.extend_from_slice(&self.channel_id);
		out.extend_from_slice(&self.epoch_id);
		out.extend_from_slice(&self.local_node.serialize());
		out.extend_from_slice(&self.remote_node.serialize());
		out.push(self.phase as u8);
		out.push(self.capability_hold as u8);
		out.push(self.activation_mismatch as u8);
		out.push(self.activation_ack_pending as u8);
		out.push(self.abort_reason.is_some() as u8);
		if let Some(reason) = self.abort_reason {
			out.extend_from_slice(&reason.to_be_bytes());
		}
		out.push(self.abort.is_some() as u8);
		if let Some(abort) = &self.abort {
			out.push(abort.local as u8);
			bytes_write(&mut out, &abort.message.encode());
		}
		out.push(self.messages.len() as u8);
		for msg in &self.messages {
			bytes_write(&mut out, &msg.encode());
		}
		out.extend_from_slice(&(self.slots.len() as u16).to_be_bytes());
		for slot in &self.slots {
			slot.write(&mut out);
		}
		if out.len() > MAX_RECORD {
			return Err(Error::Limit);
		}
		Ok(out)
	}
	pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
		if bytes.len() > MAX_RECORD {
			return Err(Error::Limit);
		}
		let mut r = Reader::new(bytes);
		if r.take(5)? != b"FFS2\x04" {
			return Err(Error::Unsupported);
		}
		let channel_id = r.array()?;
		let epoch_id = r.array()?;
		let local_node = PublicKey::from_slice(r.take(33)?).map_err(|_| Error::Invalid)?;
		let remote_node = PublicKey::from_slice(r.take(33)?).map_err(|_| Error::Invalid)?;
		let phase = Phase::read(r.u8()?)?;
		let capability_hold = boolean(&mut r)?;
		let activation_mismatch = boolean(&mut r)?;
		let activation_ack_pending = boolean(&mut r)?;
		let abort_reason = if boolean(&mut r)? { Some(r.u16()?) } else { None };
		let abort = if boolean(&mut r)? {
			Some(AbortRecord {
				local: boolean(&mut r)?,
				message: SignedMessage::decode(&bytes_read(&mut r)?)?,
			})
		} else {
			None
		};
		let n = r.u8()? as usize;
		if n > 7 {
			return Err(Error::Limit);
		}
		let mut messages = Vec::with_capacity(n);
		for _ in 0..n {
			messages.push(SignedMessage::decode(&bytes_read(&mut r)?)?);
		}
		let n = r.u16()? as usize;
		slots(n)?;
		let mut slots = Vec::with_capacity(n);
		for _ in 0..n {
			slots.push(Slot::read(&mut r)?);
		}
		if !r.done() {
			return Err(Error::Invalid);
		}
		let value = Self {
			channel_id,
			epoch_id,
			local_node,
			remote_node,
			phase,
			capability_hold,
			activation_mismatch,
			activation_ack_pending,
			abort_reason,
			abort,
			messages,
			slots,
		};
		value.validate()?;
		Ok(value)
	}
}

/// Persistent rejection index. It never evicts used identities on age, channel
/// closure or epoch retirement. Reaching the bound refuses new reservations.
/// It deliberately contains no preimages and is not a claim-resolution archive.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct UsedArchive {
	entries: Vec<([u8; 32], [u8; 32], [u8; 32])>,
	burned: Vec<([u8; 32], [u8; 32])>,
}
impl UsedArchive {
	pub(crate) fn contains_hash(&self, hash: &[u8; 32]) -> bool {
		self.entries.iter().any(|(_, _, previous)| previous == hash)
	}
	pub(crate) fn contains(&self, channel: [u8; 32], epoch: [u8; 32], hash: [u8; 32]) -> bool {
		self.entries.contains(&(channel, epoch, hash))
	}

	/// Refused setup ids remain used even if no voucher hashes were generated.
	pub(crate) fn burn_epoch(&mut self, channel: [u8; 32], epoch: [u8; 32]) -> Result<(), Error> {
		if self.entries.len() + self.burned.len() >= MAX_ARCHIVE {
			return Err(Error::Limit);
		}
		if self.burned.contains(&(channel, epoch))
			|| self.entries.iter().any(|(c, e, _)| *c == channel && *e == epoch)
		{
			return Err(Error::Invalid);
		}
		self.burned.push((channel, epoch));
		Ok(())
	}
	pub(crate) fn reserve(
		&mut self, channel: [u8; 32], epoch: [u8; 32], hashes: &[[u8; 32]],
	) -> Result<(), Error> {
		slots(hashes.len())?;
		if self
			.entries
			.len()
			.checked_add(hashes.len() + self.burned.len())
			.map_or(true, |n| n > MAX_ARCHIVE)
		{
			return Err(Error::Limit);
		}
		if self.burned.contains(&(channel, epoch)) {
			return Err(Error::Invalid);
		}
		for (i, hash) in hashes.iter().enumerate() {
			if hashes[..i].contains(hash)
				|| self.entries.iter().any(|(c, e, h)| (*c == channel && *e == epoch) || h == hash)
			{
				return Err(Error::Invalid);
			}
		}
		self.entries.extend(hashes.iter().map(|h| (channel, epoch, *h)));
		Ok(())
	}
	pub(crate) fn encode(&self) -> Vec<u8> {
		let mut out = b"FFA2\x01".to_vec();
		out.extend_from_slice(&(self.entries.len() as u16).to_be_bytes());
		for (c, e, h) in &self.entries {
			out.extend_from_slice(c);
			out.extend_from_slice(e);
			out.extend_from_slice(h);
		}
		out.extend_from_slice(&(self.burned.len() as u16).to_be_bytes());
		for (c, e) in &self.burned {
			out.extend_from_slice(c);
			out.extend_from_slice(e);
		}
		out
	}
	pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
		if bytes.len() > 9 + MAX_ARCHIVE * 96 {
			return Err(Error::Limit);
		}
		let mut r = Reader::new(bytes);
		if r.take(5)? != b"FFA2\x01" {
			return Err(Error::Unsupported);
		}
		let n = r.u16()? as usize;
		if n > MAX_ARCHIVE {
			return Err(Error::Limit);
		}
		let mut entries = Vec::with_capacity(n);
		for _ in 0..n {
			let c = r.array()?;
			let e = r.array()?;
			let h = r.array()?;
			if entries.iter().any(|(_, _, previous)| previous == &h) {
				return Err(Error::Invalid);
			}
			entries.push((c, e, h));
		}
		let count = r.u16()? as usize;
		if n + count > MAX_ARCHIVE {
			return Err(Error::Limit);
		}
		let mut burned = Vec::with_capacity(count);
		for _ in 0..count {
			let c = r.array()?;
			let e = r.array()?;
			if burned.contains(&(c, e))
				|| entries.iter().any(|(old_c, old_e, _)| c == *old_c && e == *old_e)
			{
				return Err(Error::Invalid);
			}
			burned.push((c, e));
		}
		if !r.done() {
			return Err(Error::Invalid);
		}
		Ok(Self { entries, burned })
	}
}
