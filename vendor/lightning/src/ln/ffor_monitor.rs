//! Durable native FFOR custody. This module does not enable the wire protocol.

use crate::io::{self, Read};
use crate::ln::ffor::{BookEntry, Error, Kind, Phase, SettlerEpoch, SlotState, UsedArchive, MAX_SLOTS};
use crate::prelude::*;
use crate::util::ser::{Readable, Writeable, Writer};
use crate::ln::msgs::DecodeError;
use bitcoin::Txid;
use bitcoin::hashes::Hash;
use core::fmt;

const MAX_JOURNAL_PART: usize = 512 * 1024;
const INITIAL_COMMITMENT_NUMBER: u64 = (1 << 48) - 1;

/// Monitor-authenticated resolutions retained until the manager durably releases
/// the exact native voucher source. This cannot be supplied in a monitor update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FforChainResolutions {
	pub(crate) epoch_id: [u8; 32],
	pub(crate) entries: Vec<(u16, crate::ln::ffor::ChainRemoval)>,
}
impl Writeable for FforChainResolutions {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.epoch_id.write(writer)?;
		(self.entries.len() as u16).write(writer)?;
		for (slot, proof) in &self.entries {
			slot.write(writer)?;
			proof.commitment_txid.write(writer)?;
			proof.output_index.write(writer)?;
			proof.resolving_txid.write(writer)?;
			proof.fulfilled.write(writer)?;
		}
		Ok(())
	}
}
impl Readable for FforChainResolutions {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let epoch_id = Readable::read(reader)?;
		let count = u16::read(reader)? as usize;
		if count == 0 || count > MAX_SLOTS { return Err(DecodeError::InvalidValue); }
		let mut entries = Vec::with_capacity(count);
		for _ in 0..count {
			let slot = u16::read(reader)?;
			if slot == 0 || entries.iter().any(|(id, _)| *id == slot) { return Err(DecodeError::InvalidValue); }
			let proof = crate::ln::ffor::ChainRemoval { commitment_txid: Readable::read(reader)?,
				output_index: Readable::read(reader)?, resolving_txid: Readable::read(reader)?, fulfilled: Readable::read(reader)? };
			if proof.output_index.is_none() && (proof.fulfilled || proof.resolving_txid != proof.commitment_txid) {
				return Err(DecodeError::InvalidValue);
			}
			entries.push((slot, proof));
		}
		Ok(Self { epoch_id, entries })
	}
}

/// Exact, untrimmed voucher mapping in both native commitment transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VoucherOutput {
	pub(crate) entry: BookEntry,
	pub(crate) receiver_output_index: u32,
	pub(crate) settler_output_index: u32,
}

/// R/S-oriented, ascending commitment numbers and internal-order transaction ids.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CommitmentSnapshot {
	pub(crate) funding_txo: crate::chain::transaction::OutPoint,
	pub(crate) receiver_number: u64,
	pub(crate) receiver_txid: Txid,
	pub(crate) settler_number: u64,
	pub(crate) settler_txid: Txid,
	pub(crate) outputs: Vec<VoucherOutput>,
}
impl CommitmentSnapshot {
	pub(crate) fn validate(&self, epoch: &SettlerEpoch) -> Result<(), Error> {
		if self.receiver_number > INITIAL_COMMITMENT_NUMBER
			|| self.settler_number > INITIAL_COMMITMENT_NUMBER
			|| self.outputs.len() != epoch.slots.len() || self.outputs.len() > MAX_SLOTS {
			return Err(Error::Invalid);
		}
		for (i, output) in self.outputs.iter().enumerate() {
			if output.entry != epoch.slots[i].entry || self.outputs[..i].iter().any(|previous| {
				previous.receiver_output_index == output.receiver_output_index
					|| previous.settler_output_index == output.settler_output_index
			}) { return Err(Error::Invalid); }
		}
		Ok(())
	}
}

/// Custody state retained independently of a possibly stale ChannelManager.
/// Secret material deliberately has a redacted Debug implementation.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct FforJournal {
	pub(crate) revision: u64,
	pub(crate) epoch: SettlerEpoch,
	pub(crate) activation_snapshot: Option<CommitmentSnapshot>,
	used: UsedArchive,
}
impl fmt::Debug for FforJournal {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("FforJournal").field("revision", &self.revision)
			.field("phase", &self.epoch.phase).field("slots", &self.epoch.slots.len()).finish()
	}
}
impl FforJournal {
	pub(crate) fn prepare(previous: Option<&Self>, revision: u64, epoch: SettlerEpoch,
		activation_snapshot: Option<CommitmentSnapshot>) -> Result<Self, Error> {
		let mut used = previous.map(|old| old.used.clone()).unwrap_or_default();
		if previous.map_or(true, |old| old.epoch.epoch_id != epoch.epoch_id) {
			used.reserve(epoch.channel_id, epoch.epoch_id,
				&epoch.slots.iter().map(|slot| slot.entry.payment_hash).collect::<Vec<_>>())?;
		}
		let next = Self { revision, epoch, activation_snapshot, used };
		next.validate_transition(previous)?;
		Ok(next)
	}

	pub(crate) fn validate(&self) -> Result<(), Error> {
		self.epoch.validate()?;
		if self.epoch.slots.iter().any(|slot| !self.used.contains(self.epoch.channel_id, self.epoch.epoch_id, slot.entry.payment_hash)) { return Err(Error::Invalid); }
		if self.revision == 0 { return Err(Error::Invalid); }
		if let Some(snapshot) = &self.activation_snapshot {
			snapshot.validate(&self.epoch)?;
			if let Some(activate) = self.epoch.messages.iter().find(|m| m.kind == Kind::Activate) {
				let hash = crate::ln::ffor::commitment_hash(snapshot.receiver_number,
					&snapshot.receiver_txid.to_byte_array(), snapshot.settler_number, &snapshot.settler_txid.to_byte_array());
				if activate.unsigned()[128..160] != hash { return Err(Error::Invalid); }
			}
		}
		if matches!(self.epoch.phase, Phase::VouchersCommitted | Phase::Active | Phase::Draining | Phase::Closed)
			&& self.activation_snapshot.is_none() { return Err(Error::Invalid); }
		Ok(())
	}

	/// Validate every replay-sensitive field again at the monitor boundary.
	pub(crate) fn validate_transition(&self, previous: Option<&Self>) -> Result<(), Error> {
		self.validate()?;
		let Some(old) = previous else {
			if self.revision != 1 || self.epoch.phase != Phase::Negotiating
				|| self.activation_snapshot.is_some() || self.epoch.slots.iter().any(|slot|
					slot.chain_removal.is_some() || slot.removal.is_some() || slot.redeemed || slot.state != SlotState::Unused) { return Err(Error::Invalid); }
			return Ok(());
		};
		if old.revision.checked_add(1) != Some(self.revision)
			|| old.epoch.channel_id != self.epoch.channel_id
			|| old.epoch.local_node != self.epoch.local_node || old.epoch.remote_node != self.epoch.remote_node {
			return Err(Error::Invalid);
		}
		if old.epoch.epoch_id != self.epoch.epoch_id {
			// Retire only when every native voucher is removed and no claim can be
			// reassigned. The non-evicting identity archive still rejects replay.
			if !matches!(old.epoch.phase, Phase::Closed | Phase::Aborted)
				|| old.epoch.slots.iter().any(|s| (s.removal.is_none() && s.chain_removal.is_none()) || s.state == SlotState::Settling)
				|| self.epoch.phase != Phase::Negotiating || self.activation_snapshot.is_some()
				|| self.epoch.slots.iter().any(|slot| slot.chain_removal.is_some() || slot.removal.is_some()
					|| slot.redeemed || slot.state != SlotState::Unused) {
				return Err(Error::Invalid);
			}
			let mut expected = old.used.clone();
			expected.reserve(self.epoch.channel_id, self.epoch.epoch_id,
				&self.epoch.slots.iter().map(|s| s.entry.payment_hash).collect::<Vec<_>>())?;
			return if self.used == expected { Ok(()) } else { Err(Error::Invalid) };
		}
		if old.used != self.used || old.epoch.slots.len() != self.epoch.slots.len() { return Err(Error::Invalid); }
		let phase_valid = old.epoch.phase == self.epoch.phase || matches!((old.epoch.phase, self.epoch.phase),
			(Phase::Negotiating, Phase::VouchersCommitted | Phase::Aborted)
			| (Phase::VouchersCommitted, Phase::Active | Phase::Aborted)
			| (Phase::Active, Phase::Draining) | (Phase::Draining, Phase::Closed));
		if !phase_valid || old.epoch.activation_mismatch && !self.epoch.activation_mismatch
			|| old.activation_snapshot.as_ref().is_some_and(|s| Some(s) != self.activation_snapshot.as_ref()) {
			return Err(Error::Invalid);
		}
		for (old, next) in old.epoch.slots.iter().zip(&self.epoch.slots) {
			let allowed = old.state == next.state || matches!((old.state, next.state),
				(SlotState::Unused, SlotState::Settling) | (SlotState::Settling, SlotState::Settled));
			if !allowed || old.entry != next.entry || old.preimage != next.preimage
				|| old.upstream.as_ref().is_some_and(|u| Some(u) != next.upstream.as_ref())
				|| old.redeemed && !next.redeemed
				|| old.removal.as_ref().is_some_and(|r| Some(r) != next.removal.as_ref())
				|| old.chain_removal.as_ref().is_some_and(|r| Some(r) != next.chain_removal.as_ref()) {
				return Err(Error::Invalid);
			}
		}
		for message in &old.epoch.messages {
			if message.kind != Kind::SyncReply && !self.epoch.messages.iter().any(|next| next == message) {
				return Err(Error::Invalid);
			}
		}
		if let Some(old_sync) = old.epoch.messages.iter().find(|m| m.kind == Kind::SyncReply) {
			let new_sync = self.epoch.messages.iter().find(|m| m.kind == Kind::SyncReply).ok_or(Error::Invalid)?;
			let old_bytes = old_sync.unsigned(); let new_bytes = new_sync.unsigned();
			let old_seq = u64::from_be_bytes(old_bytes[128..136].try_into().map_err(|_| Error::Invalid)?);
			let new_seq = u64::from_be_bytes(new_bytes[128..136].try_into().map_err(|_| Error::Invalid)?);
			if new_seq < old_seq || new_seq == old_seq && old_bytes[136..] != new_bytes[136..] { return Err(Error::Invalid); }
			let bitmap_len = (self.epoch.slots.len() + 7) / 8;
			if old_bytes[138..138 + bitmap_len].iter().zip(&new_bytes[138..138 + bitmap_len])
				.any(|(old, new)| old & new != *old) { return Err(Error::Invalid); }
		}
		Ok(())
	}
}

fn write_bytes<W: Writer>(bytes: &[u8], writer: &mut W) -> Result<(), io::Error> {
	(bytes.len() as u32).write(writer)?;
	writer.write_all(bytes)
}
fn read_bytes<R: Read>(reader: &mut R) -> Result<Vec<u8>, DecodeError> {
	let len = u32::read(reader)? as usize;
	if len > MAX_JOURNAL_PART { return Err(DecodeError::InvalidValue); }
	let mut bytes = vec![0; len];
	reader.read_exact(&mut bytes)?;
	Ok(bytes)
}
impl Writeable for FforJournal {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.revision.write(writer)?;
		write_bytes(&self.epoch.encode().map_err(|_| io::ErrorKind::InvalidData)?, writer)?;
		self.activation_snapshot.write(writer)?;
		write_bytes(&self.used.encode(), writer)
	}
}
impl Readable for FforJournal {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let revision = u64::read(reader)?;
		let epoch = SettlerEpoch::decode(&read_bytes(reader)?).map_err(|_| DecodeError::InvalidValue)?;
		let activation_snapshot = Option::<CommitmentSnapshot>::read(reader)?;
		let used = UsedArchive::decode(&read_bytes(reader)?).map_err(|_| DecodeError::InvalidValue)?;
		let journal = Self { revision, epoch, activation_snapshot, used };
		journal.validate().map_err(|_| DecodeError::InvalidValue)?;
		Ok(journal)
	}
}
impl Writeable for CommitmentSnapshot {
	fn write<W: Writer>(&self, writer: &mut W) -> Result<(), io::Error> {
		self.funding_txo.write(writer)?;
		self.receiver_number.write(writer)?; self.receiver_txid.write(writer)?;
		self.settler_number.write(writer)?; self.settler_txid.write(writer)?;
		(self.outputs.len() as u16).write(writer)?;
		for output in &self.outputs {
			output.entry.slot.write(writer)?; output.entry.htlc_id.write(writer)?;
			output.entry.payment_hash.write(writer)?; output.entry.amount_msat.write(writer)?;
			output.entry.expiry.write(writer)?; output.entry.deadline.write(writer)?;
			output.receiver_output_index.write(writer)?; output.settler_output_index.write(writer)?;
		}
		Ok(())
	}
}
impl Readable for CommitmentSnapshot {
	fn read<R: Read>(reader: &mut R) -> Result<Self, DecodeError> {
		let funding_txo = Readable::read(reader)?;
		let receiver_number = u64::read(reader)?; let receiver_txid = Txid::read(reader)?;
		let settler_number = u64::read(reader)?; let settler_txid = Txid::read(reader)?;
		let count = u16::read(reader)? as usize;
		if count == 0 || count > MAX_SLOTS { return Err(DecodeError::InvalidValue); }
		let mut outputs = Vec::with_capacity(count);
		for _ in 0..count {
			outputs.push(VoucherOutput { entry: BookEntry {
				slot: u16::read(reader)?, htlc_id: u64::read(reader)?, payment_hash: Readable::read(reader)?,
				amount_msat: u64::read(reader)?, expiry: u32::read(reader)?, deadline: u32::read(reader)?,
			}, receiver_output_index: u32::read(reader)?, settler_output_index: u32::read(reader)? });
		}
		Ok(Self { funding_txo, receiver_number, receiver_txid, settler_number, settler_txid, outputs })
	}
}

/// A monitor completion must prove this exact native update became durable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FforPersistenceToken {
	pub(crate) channel_id: crate::ln::types::ChannelId,
	pub(crate) epoch_id: [u8; 32],
	pub(crate) revision: u64,
	pub(crate) update_id: u64,
}
impl_writeable_tlv_based!(FforPersistenceToken, {
	(0, channel_id, required),
	(2, epoch_id, required),
	(4, revision, required),
	(6, update_id, required),
});
impl FforJournal {
	pub(crate) fn contains_payment_hash(&self, hash: &[u8; 32]) -> bool { self.used.contains_hash(hash) }

	pub(crate) fn proves_settling_token(&self, token: &FforPersistenceToken,
		slot: u16, upstream: &crate::ln::ffor::Upstream) -> bool {
		self.epoch.channel_id == token.channel_id.0 && self.epoch.epoch_id == token.epoch_id
			&& self.revision >= token.revision && token.revision != 0
			&& self.epoch.slots.iter().any(|entry| entry.entry.slot == slot
				&& matches!(entry.state, SlotState::Settling | SlotState::Settled)
				&& entry.upstream.as_ref() == Some(upstream))
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::ln::ffor::{tests::active_epoch, Upstream};
	use crate::chain::transaction::OutPoint;
	use bitcoin::hex::FromHex;
	fn snapshot(epoch: &SettlerEpoch) -> CommitmentSnapshot {
		let txid = |hex: &str| Txid::from_byte_array(Vec::<u8>::from_hex(hex).unwrap().try_into().unwrap());
		CommitmentSnapshot {
			funding_txo: OutPoint { txid: Txid::from_byte_array([1; 32]), index: 0 },
			receiver_number: 43,
			receiver_txid: txid("c56247558caf290d78e2fe7d948d9605320c012b20fa181db87fc847ce69159b"),
			settler_number: 43,
			settler_txid: txid("d23aaf74371cdda6cbaf75b7390fdd75b3247dfe90c98d2e19e9802783c349b9"),
			outputs: epoch.slots.iter().enumerate().map(|(i, slot)| VoucherOutput {
				entry: slot.entry.clone(), receiver_output_index: i as u32, settler_output_index: i as u32,
			}).collect(),
		}
	}
	fn active_journal() -> FforJournal {
		let active = active_epoch();
		let mut setup = active.clone();
		setup.phase = Phase::Negotiating;
		setup.messages.retain(|m| matches!(m.kind, Kind::Init | Kind::Accept));
		let first = FforJournal::prepare(None, 1, setup.clone(), None).unwrap();
		setup.phase = Phase::VouchersCommitted;
		let committed = FforJournal::prepare(Some(&first), 2, setup, Some(snapshot(&active))).unwrap();
		FforJournal::prepare(Some(&committed), 3, active.clone(), Some(snapshot(&active))).unwrap()
	}
	#[test]
	fn journal_requires_old_reader_rejection() -> Result<(), io::Error> {
		fn legacy<R: io::Read>(reader: &mut R) -> Result<(), DecodeError> {
			read_tlv_fields!(reader, {});
			Ok(())
		}
		let journal = Some(active_journal());
		let mut bytes = crate::util::ser::VecWriter(Vec::new());
		write_tlv_fields!(&mut bytes, { (38, journal, option) });
		assert_eq!(legacy(&mut io::Cursor::new(bytes.0)), Err(DecodeError::UnknownRequiredFeature));
		Ok(())
	}
	#[test]
	fn journal_roundtrip_and_activation_binding() {
		let active = active_journal();
		let bytes = active.encode();
		let read = FforJournal::read(&mut io::Cursor::new(&bytes)).unwrap();
		assert_eq!(read, active);
		let mut bad = active.clone();
		bad.activation_snapshot.as_mut().unwrap().receiver_txid = Txid::from_byte_array([7; 32]);
		assert!(bad.validate().is_err());
		assert!(FforJournal::read(&mut io::Cursor::new(&bytes[..bytes.len()-1])).is_err());
		let mut oversize = 1u64.encode();
		oversize.extend_from_slice(&((MAX_JOURNAL_PART + 1) as u32).to_be_bytes());
		assert!(FforJournal::read(&mut io::Cursor::new(oversize)).is_err());
		let mut unarchived = active.clone();
		unarchived.used = UsedArchive::default();
		assert!(unarchived.validate().is_err());
		let debug = format!("{active:?}");
		assert!(!debug.contains("preimage"));
	}
	#[test]
	fn journal_rejects_claim_rollback_and_preserves_descendant_tokens() {
		let active = active_journal();
		let mut epoch = active.epoch.clone();
		let upstream = Upstream { counterparty_node_id: epoch.remote_node,
			funding_txo: OutPoint { txid: Txid::from_byte_array([2; 32]), index: 1 },
			channel_id: [9; 32], htlc_id: 42 };
		epoch.slots[0].state = SlotState::Settling;
		epoch.slots[0].upstream = Some(upstream.clone());
		let settling = FforJournal::prepare(Some(&active), 4, epoch.clone(), active.activation_snapshot.clone()).unwrap();
		let token = FforPersistenceToken { channel_id: crate::ln::types::ChannelId(epoch.channel_id),
			epoch_id: epoch.epoch_id, revision: 4, update_id: 17 };
		assert!(settling.proves_settling_token(&token, 1, &upstream));
		epoch.capability_hold = true;
		let descendant = FforJournal::prepare(Some(&settling), 5, epoch.clone(), active.activation_snapshot.clone()).unwrap();
		assert!(descendant.proves_settling_token(&token, 1, &upstream));
		let mut other = upstream.clone(); other.htlc_id += 1;
		assert!(!descendant.proves_settling_token(&token, 1, &other));
		let mut bad = epoch.clone(); bad.slots[0].upstream = Some(other);
		assert!(FforJournal::prepare(Some(&descendant), 6, bad, active.activation_snapshot.clone()).is_err());
		let mut bad = epoch.clone(); bad.slots[0].state = SlotState::Unused; bad.slots[0].upstream = None;
		assert!(FforJournal::prepare(Some(&descendant), 6, bad, active.activation_snapshot.clone()).is_err());
		assert!(FforJournal::prepare(Some(&descendant), 5, epoch.clone(), active.activation_snapshot.clone()).is_err());
		epoch.slots[0].state = SlotState::Settled;
		let settled = FforJournal::prepare(Some(&descendant), 6, epoch, active.activation_snapshot.clone()).unwrap();
		assert!(settled.proves_settling_token(&token, 1, &upstream));
	}
}
