// FFOR protocol adaptation from Beignet, Copyright (c) 2023 Synonym.
// Licensed under the MIT license in ffor/LICENSE-BEIGNET.
// Reference: coreyphillips/beignet at fc4b253fde5d3add31c4f0e208e16794bb32e324,
// src/lightning/ffor/{messages,transcript,types}.ts.
// Appendix D vectors originate in coreyphillips/ffor at
// ec77c7f44453b2d7b0124dccbeee946f5ae37fda, as attributed by Beignet's tests.

//! Internal Variant D codec, custody state and pure transition preparation.
//!
//! Nothing here advertises support, sends messages, offers native HTLCs or signs
//! commitments. Prepared actions require the native monitor persistence barrier.
//! Native channel hooks must enforce commitment invariants and bind every action
//! to durable state. Decoding is not authorization. Only concurrent version 2 is
//! admissible for a settler.

use crate::prelude::*;
use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, Verification};

mod state;
pub(crate) use state::*;
mod driver;
pub(crate) use driver::*;

pub(crate) const MAX_SLOTS: usize = 483;
pub(crate) const MAX_BODY: usize = 65_533;
pub(crate) const MAX_TLVS: usize = 64;

/// Experimental option_ff_receive pair, synchronized with Beignet's 440/441 assignment.
pub(crate) const RECEIVE_FEATURE_BIT: usize = 440;
/// Experimental option_ff_concurrent pair. The former 560-563 range belongs to Eclair.
pub(crate) const CONCURRENT_FEATURE_BIT: usize = 442;

/// Pure parser exercise for a separate fuzz target. No node, signer, network or
/// secret output is constructed. `cfg(fuzzing)` does not bypass this module's
/// signature verification; do not enable the separate `secp256k1_fuzz` cfg when
/// using this target to exercise real signature checks.
#[cfg(any(test, fuzzing))]
pub(super) fn fuzz_parsers(data: &[u8]) {
	if data.len() > 512 * 1024 {
		return;
	}
	if let Ok(message) = SignedMessage::decode(data) {
		let encoded = message.encode();
		assert_eq!(encoded, data);
		assert_eq!(SignedMessage::decode(&encoded).unwrap(), message);
		let generator = PublicKey::from_slice(&[
			2, 121, 190, 102, 126, 249, 220, 187, 172, 85, 160, 98, 149, 206, 135, 11, 7, 2, 155,
			252, 219, 45, 206, 40, 217, 89, 242, 129, 91, 22, 248, 23, 152,
		])
		.unwrap();
		let _ = message.verify(&Secp256k1::verification_only(), &generator);
	}
	if let Ok(epoch) = SettlerEpoch::decode(data) {
		let encoded = epoch.encode().unwrap();
		assert_eq!(encoded, data);
		assert!(SettlerEpoch::decode(&encoded).unwrap() == epoch);
	}
	if let Ok(archive) = UsedArchive::decode(data) {
		let encoded = archive.encode();
		assert_eq!(encoded, data);
		assert_eq!(UsedArchive::decode(&encoded).unwrap().encode(), encoded);
	}
	if let Ok(reestablish) = Reestablish::decode(data) {
		let encoded = reestablish.encode().unwrap();
		assert_eq!(encoded.as_slice(), data);
		assert_eq!(Reestablish::decode(&encoded).unwrap(), reestablish);
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
	Truncated,
	NonCanonical,
	Unsupported,
	Limit,
	Invalid,
	Signature,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u16)]
pub(crate) enum Kind {
	Init = 55001,
	Accept = 55003,
	Activate = 55045,
	ActivateAck = 55047,
	Abort = 55049,
	Close = 55051,
	CloseAck = 55053,
	Sync = 55075,
	SyncReply = 55077,
}

impl Kind {
	fn decode(n: u16) -> Result<Self, Error> {
		Ok(match n {
			55001 => Self::Init,
			55003 => Self::Accept,
			55045 => Self::Activate,
			55047 => Self::ActivateAck,
			55049 => Self::Abort,
			55051 => Self::Close,
			55053 => Self::CloseAck,
			55075 => Self::Sync,
			55077 => Self::SyncReply,
			_ => return Err(Error::Unsupported),
		})
	}
}

/// The signer accepts only canonical, bounded outbound settler frames. Computing
/// the protocol domain here prevents use as an arbitrary node-key digest oracle.
pub(crate) fn settler_signing_digest(typ: u16, unsigned: &[u8]) -> Result<[u8; 32], Error> {
	let kind = Kind::decode(typ)?;
	if !matches!(
		kind,
		Kind::Accept | Kind::ActivateAck | Kind::Abort | Kind::CloseAck | Kind::SyncReply
	) {
		return Err(Error::Unsupported);
	}
	SignedMessage::from_parts(kind, unsigned, [0; 64])?;
	Ok(message_digest(kind, unsigned))
}

pub(crate) struct Reader<'a> {
	bytes: &'a [u8],
	pos: usize,
}
impl<'a> Reader<'a> {
	pub(crate) fn new(bytes: &'a [u8]) -> Self {
		Self { bytes, pos: 0 }
	}
	pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], Error> {
		let end = self.pos.checked_add(n).ok_or(Error::Limit)?;
		let value = self.bytes.get(self.pos..end).ok_or(Error::Truncated)?;
		self.pos = end;
		Ok(value)
	}
	pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], Error> {
		self.take(N)?.try_into().map_err(|_| Error::Truncated)
	}
	pub(crate) fn u8(&mut self) -> Result<u8, Error> {
		Ok(self.array::<1>()?[0])
	}
	pub(crate) fn u16(&mut self) -> Result<u16, Error> {
		Ok(u16::from_be_bytes(self.array()?))
	}
	pub(crate) fn u32(&mut self) -> Result<u32, Error> {
		Ok(u32::from_be_bytes(self.array()?))
	}
	pub(crate) fn u64(&mut self) -> Result<u64, Error> {
		Ok(u64::from_be_bytes(self.array()?))
	}
	pub(crate) fn done(&self) -> bool {
		self.pos == self.bytes.len()
	}
	fn bigsize(&mut self) -> Result<u64, Error> {
		let prefix = self.u8()?;
		let (n, min) = match prefix {
			0xfd => (self.u16()? as u64, 0xfd),
			0xfe => (self.u32()? as u64, 0x10000),
			0xff => (self.u64()?, 0x100000000),
			_ => return Ok(prefix as u64),
		};
		if n < min {
			return Err(Error::NonCanonical);
		}
		Ok(n)
	}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Tlv {
	pub(crate) typ: u64,
	pub(crate) value: Vec<u8>,
}

fn parse_tlvs(bytes: &[u8]) -> Result<Vec<Tlv>, Error> {
	let mut r = Reader::new(bytes);
	let mut out = Vec::new();
	let mut previous = None;
	while !r.done() {
		if out.len() == MAX_TLVS {
			return Err(Error::Limit);
		}
		let typ = r.bigsize()?;
		if previous.map_or(false, |last| typ <= last) {
			return Err(Error::NonCanonical);
		}
		// All currently assigned extension fields are odd. Never ignore an even field.
		if typ % 2 == 0 {
			return Err(Error::Unsupported);
		}
		let n = r.bigsize()?;
		if n > MAX_BODY as u64 {
			return Err(Error::Limit);
		}
		out.push(Tlv { typ, value: r.take(n as usize)?.to_vec() });
		previous = Some(typ);
	}
	Ok(out)
}

fn slots(n: usize) -> Result<(), Error> {
	if n == 0 || n > MAX_SLOTS {
		Err(Error::Limit)
	} else {
		Ok(())
	}
}

fn list(value: &[u8], size: usize) -> Result<(), Error> {
	if value.len() % size != 0 {
		return Err(Error::Invalid);
	}
	if value.len() / size > MAX_SLOTS {
		return Err(Error::Limit);
	}
	Ok(())
}

/// Exact signed body is retained, including unknown odd extensions, for replay and hashing.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct SignedMessage {
	pub(crate) kind: Kind,
	pub(crate) channel_id: [u8; 32],
	pub(crate) epoch_id: [u8; 32],
	unsigned: Vec<u8>,
	signature: [u8; 64],
	tlvs: Vec<Tlv>,
}

impl core::fmt::Debug for SignedMessage {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		// Receipt messages contain preimages. Never expose payloads in diagnostics.
		f.debug_struct("SignedMessage")
			.field("kind", &self.kind)
			.field("body_bytes", &(self.unsigned.len() + 64))
			.finish()
	}
}

impl SignedMessage {
	pub(crate) fn decode(wire: &[u8]) -> Result<Self, Error> {
		if wire.len() > MAX_BODY + 2 {
			return Err(Error::Limit);
		}
		let mut r = Reader::new(wire);
		let kind = Kind::decode(r.u16()?)?;
		let body = r.take(wire.len() - 2)?;
		if body.len() < 128 {
			return Err(Error::Truncated);
		}
		let unsigned = &body[..body.len() - 64];
		let signature = body[body.len() - 64..].try_into().map_err(|_| Error::Truncated)?;
		let mut r = Reader::new(unsigned);
		let channel_id = r.array()?;
		let epoch_id = r.array()?;
		match kind {
			Kind::Init => {
				// Other variants have different safety requirements and are not ported.
				if r.u8()? != 4 {
					return Err(Error::Unsupported);
				}
				r.u64()?;
				slots(r.u16()? as usize)?;
				r.take(8 + 4 + 4 + 4 + 4)?;
				if r.u64()? != 0 || r.u16()? != 0 {
					return Err(Error::Unsupported);
				}
			},
			Kind::Accept => {
				r.u64()?;
			},
			Kind::Activate => {
				r.take(32 * 3 + 4)?;
			},
			Kind::ActivateAck | Kind::Close => {
				r.take(32)?;
			},
			Kind::Abort => {
				r.take(32)?;
				r.u16()?;
				let n = r.u16()? as usize;
				r.take(n)?;
			},
			Kind::CloseAck => {
				r.take(32)?;
				let n = r.u16()? as usize;
				slots(n)?;
				check_bitmap(n, r.take((n + 7) / 8)?)?;
			},
			Kind::Sync => {
				r.take(64)?;
			},
			Kind::SyncReply => {
				r.take(64)?;
				let seq = r.u64()?;
				let n = r.u16()? as usize;
				slots(n)?;
				let bitmap = r.take((n + 7) / 8)?;
				check_bitmap(n, bitmap)?;
				let count = r.u16()? as usize;
				if count > n || (seq == 0 && count != 0) {
					return Err(Error::Invalid);
				}
				check_receipts(n, bitmap, r.take(count * 34)?)?;
			},
		}
		let fixed_end = r.pos;
		let tlvs = parse_tlvs(&unsigned[fixed_end..])?;
		let msg = Self { kind, channel_id, epoch_id, unsigned: unsigned.to_vec(), signature, tlvs };
		msg.check_fields()?;
		Ok(msg)
	}

	fn check_fields(&self) -> Result<(), Error> {
		if matches!(self.kind, Kind::Init | Kind::Accept) {
			if let Some(v) = self.tlv(17) {
				if v.len() != 2 {
					return Err(Error::Invalid);
				}
			}
			if let Some(v) = self.tlv(9) {
				list(v, 8)?;
			}
			if let Some(v) = self.tlv(1) {
				list(v, 32)?;
			}
		}
		if self.kind == Kind::Init {
			// No historical tower, hash-chain or issuer extensions in this port.
			if [1, 3, 5, 15].iter().any(|t| self.tlv(*t).is_some()) {
				return Err(Error::Unsupported);
			}
			if let Some(v) = self.tlv(13) {
				let mut r = Reader::new(v);
				let count = r.u16()? as usize;
				slots(count)?;
				for _ in 0..count {
					PublicKey::from_slice(r.take(33)?).map_err(|_| Error::Invalid)?;
				}
				if !r.done() {
					return Err(Error::Invalid);
				}
			}
		}
		if self.kind == Kind::Accept {
			self.tlv(1).ok_or(Error::Invalid)?;
			if self.tlv(7).map_or(true, |v| v.len() != 8)
				|| self.tlv(11).map_or(true, |v| v.len() != 32)
			{
				return Err(Error::Invalid);
			}
		}
		if self.kind == Kind::CloseAck {
			let n =
				u16::from_be_bytes(self.unsigned[96..98].try_into().map_err(|_| Error::Invalid)?)
					as usize;
			let bitmap = &self.unsigned[98..98 + (n + 7) / 8];
			check_receipts(n, bitmap, self.tlv(1).unwrap_or(&[]))?;
		}
		Ok(())
	}

	pub(crate) fn tlv(&self, typ: u64) -> Option<&[u8]> {
		self.tlvs.iter().find(|v| v.typ == typ).map(|v| v.value.as_slice())
	}
	pub(crate) fn concurrent_version(&self) -> Option<u16> {
		self.tlv(17).and_then(|v| v.try_into().ok()).map(u16::from_be_bytes)
	}
	pub(crate) fn unsigned(&self) -> &[u8] {
		&self.unsigned
	}
	pub(crate) fn encode(&self) -> Vec<u8> {
		let mut out = (self.kind as u16).to_be_bytes().to_vec();
		out.extend_from_slice(&self.unsigned);
		out.extend_from_slice(&self.signature);
		out
	}
	pub(crate) fn verify<C: Verification>(
		&self, secp: &Secp256k1<C>, peer: &PublicKey,
	) -> Result<(), Error> {
		let sig = Signature::from_compact(&self.signature).map_err(|_| Error::Signature)?;
		let mut low = sig;
		low.normalize_s();
		if low != sig {
			return Err(Error::Signature);
		}
		let digest = message_digest(self.kind, &self.unsigned);
		secp.verify_ecdsa(&Message::from_digest(digest), &sig, peer).map_err(|_| Error::Signature)
	}
	/// Append a caller-provided node signature, then revalidate the complete frame.
	/// The caller controls signer custody; no node secret is accepted here.
	pub(crate) fn from_parts(
		kind: Kind, unsigned: &[u8], signature: [u8; 64],
	) -> Result<Self, Error> {
		if unsigned.len() > MAX_BODY - 64 {
			return Err(Error::Limit);
		}
		let mut wire = (kind as u16).to_be_bytes().to_vec();
		wire.extend_from_slice(unsigned);
		wire.extend_from_slice(&signature);
		Self::decode(&wire)
	}
}

fn check_bitmap(n: usize, bitmap: &[u8]) -> Result<(), Error> {
	if bitmap.len() != (n + 7) / 8
		|| (n % 8 != 0 && bitmap.last().map_or(true, |b| b >> (n % 8) != 0))
	{
		return Err(Error::Invalid);
	}
	Ok(())
}

fn check_receipts(n: usize, bitmap: &[u8], bytes: &[u8]) -> Result<(), Error> {
	list(bytes, 34)?;
	let mut r = Reader::new(bytes);
	for k in 1..=n {
		if bitmap[(k - 1) / 8] & (1 << ((k - 1) % 8)) != 0 {
			if r.u16()? as usize != k {
				return Err(Error::Invalid);
			}
			r.take(32)?;
		}
	}
	if !r.done() {
		return Err(Error::Invalid);
	}
	Ok(())
}

pub(crate) fn digest(parts: &[&[u8]]) -> [u8; 32] {
	let mut engine = sha256::Hash::engine();
	for part in parts {
		engine.input(part);
	}
	sha256::Hash::from_engine(engine).to_byte_array()
}
pub(crate) fn message_digest(kind: Kind, unsigned: &[u8]) -> [u8; 32] {
	digest(&[b"ffor/msg", &(kind as u16).to_be_bytes(), unsigned])
}
pub(crate) fn init_hash(wire: &[u8]) -> [u8; 32] {
	digest(&[b"ffor/tr/init", wire])
}
pub(crate) fn setup_hash(init: &[u8; 32], accept: &[u8]) -> [u8; 32] {
	digest(&[b"ffor/tr/setup", init, accept])
}
pub(crate) fn book_hash(book: &[u8]) -> [u8; 32] {
	digest(&[b"ffor/book", book])
}
pub(crate) fn commitment_hash(n_r: u64, tx_r: &[u8; 32], n_s: u64, tx_s: &[u8; 32]) -> [u8; 32] {
	digest(&[b"ffor/commit", &n_r.to_be_bytes(), tx_r, &n_s.to_be_bytes(), tx_s])
}
pub(crate) fn activation_hash(
	setup: &[u8; 32], book: &[u8; 32], commit: &[u8; 32], height: u32,
) -> [u8; 32] {
	digest(&[b"ffor/activate", setup, book, commit, &height.to_be_bytes()])
}
pub(crate) fn voucher_secret(epoch: &[u8; 32], slot: u16) -> Result<[u8; 32], Error> {
	slots(slot as usize)?;
	Ok(digest(&[b"ffor/voucher-secret", epoch, &slot.to_be_bytes()]))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BookEntry {
	pub(crate) slot: u16,
	pub(crate) payment_hash: [u8; 32],
	pub(crate) amount_msat: u64,
	pub(crate) expiry: u32,
	pub(crate) deadline: u32,
	pub(crate) htlc_id: u64,
}
impl BookEntry {
	pub(crate) fn write(&self, out: &mut Vec<u8>) {
		out.extend_from_slice(&self.slot.to_be_bytes());
		out.extend_from_slice(&self.payment_hash);
		out.extend_from_slice(&self.amount_msat.to_be_bytes());
		out.extend_from_slice(&self.expiry.to_be_bytes());
		out.extend_from_slice(&self.deadline.to_be_bytes());
		out.extend_from_slice(&self.htlc_id.to_be_bytes());
	}
	pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self, Error> {
		Ok(Self {
			slot: r.u16()?,
			payment_hash: r.array()?,
			amount_msat: r.u64()?,
			expiry: r.u32()?,
			deadline: r.u32()?,
			htlc_id: r.u64()?,
		})
	}
}
pub(crate) fn encode_book(epoch: &[u8; 32], entries: &[BookEntry]) -> Result<Vec<u8>, Error> {
	slots(entries.len())?;
	let mut out = epoch.to_vec();
	out.extend_from_slice(&[4, 1]);
	out.extend_from_slice(&(entries.len() as u16).to_be_bytes());
	for (i, entry) in entries.iter().enumerate() {
		if entry.slot as usize != i + 1 || entry.amount_msat == 0 || entry.expiry <= entry.deadline
		{
			return Err(Error::Invalid);
		}
		if entries[..i]
			.iter()
			.any(|e| e.payment_hash == entry.payment_hash || e.htlc_id == entry.htlc_id)
		{
			return Err(Error::Invalid);
		}
		entry.write(&mut out);
	}
	Ok(out)
}
pub(crate) fn decode_book(bytes: &[u8]) -> Result<([u8; 32], Vec<BookEntry>), Error> {
	if bytes.len() > 36 + MAX_SLOTS * 58 {
		return Err(Error::Limit);
	}
	let mut r = Reader::new(bytes);
	let epoch = r.array()?;
	if r.u8()? != 4 || r.u8()? != 1 {
		return Err(Error::Unsupported);
	}
	let n = r.u16()? as usize;
	slots(n)?;
	let mut entries = Vec::with_capacity(n);
	for _ in 0..n {
		entries.push(BookEntry::read(&mut r)?);
	}
	if !r.done() || encode_book(&epoch, &entries)? != bytes {
		return Err(Error::Invalid);
	}
	Ok((epoch, entries))
}

/// Parsed terms only. Channel capacity, reserves, fee policy, signatures and
/// negotiated features must all be checked by the eventual channel driver.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InitTerms {
	pub(crate) budget_msat: u64,
	pub(crate) minimum_msat: u64,
	pub(crate) deadline: u32,
	pub(crate) expiry: u32,
	pub(crate) fee_base_msat: u32,
	pub(crate) fee_ppm: u32,
	pub(crate) amounts_msat: Vec<u64>,
	pub(crate) witness_peers: Vec<PublicKey>,
}

impl SignedMessage {
	pub(crate) fn settler_terms(&self) -> Result<InitTerms, Error> {
		if self.kind != Kind::Init || self.concurrent_version() != Some(2) {
			return Err(Error::Unsupported);
		}
		let mut r = Reader::new(&self.unsigned[65..]);
		let budget_msat = r.u64()?;
		let count = r.u16()? as usize;
		let minimum_msat = r.u64()?;
		let deadline = r.u32()?;
		let expiry = r.u32()?;
		let fee_base_msat = r.u32()?;
		let fee_ppm = r.u32()?;
		if minimum_msat == 0 || expiry.checked_sub(deadline).map_or(true, |d| d < 1008) {
			return Err(Error::Invalid);
		}
		let values = self.tlv(9).ok_or(Error::Invalid)?;
		if values.len() != count * 8 {
			return Err(Error::Invalid);
		}
		let mut amounts_msat = Vec::with_capacity(count);
		let mut sum = 0u64;
		let mut amounts = Reader::new(values);
		for _ in 0..count {
			let amount = amounts.u64()?;
			if amount < minimum_msat {
				return Err(Error::Invalid);
			}
			sum = sum.checked_add(amount).ok_or(Error::Limit)?;
			amounts_msat.push(amount);
		}
		if sum != budget_msat {
			return Err(Error::Invalid);
		}
		let mut witness_peers = Vec::new();
		if let Some(value) = self.tlv(13) {
			let mut r = Reader::new(value);
			for _ in 0..r.u16()? {
				witness_peers.push(PublicKey::from_slice(r.take(33)?).map_err(|_| Error::Invalid)?);
			}
		}
		Ok(InitTerms {
			budget_msat,
			minimum_msat,
			deadline,
			expiry,
			fee_base_msat,
			fee_ppm,
			amounts_msat,
			witness_peers,
		})
	}
}

/// Exact value of channel_reestablish TLV 55001. State 2 is the receiver's
/// activating state and can be decoded even though an S record never enters it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Reestablish {
	pub(crate) epoch_id: [u8; 32],
	pub(crate) state: u8,
	pub(crate) last_seq: u16,
	pub(crate) activation_hash: [u8; 32],
}
impl Reestablish {
	pub(crate) fn encode(&self) -> Result<[u8; 67], Error> {
		if self.state > 6 {
			return Err(Error::Invalid);
		}
		let mut bytes = [0; 67];
		bytes[..32].copy_from_slice(&self.epoch_id);
		bytes[32] = self.state;
		bytes[33..35].copy_from_slice(&self.last_seq.to_be_bytes());
		bytes[35..].copy_from_slice(&self.activation_hash);
		Ok(bytes)
	}
	pub(crate) fn decode(bytes: &[u8]) -> Result<Self, Error> {
		if bytes.len() != 67 {
			return Err(Error::Invalid);
		}
		let mut r = Reader::new(bytes);
		let value = Self {
			epoch_id: r.array()?,
			state: r.u8()?,
			last_seq: r.u16()?,
			activation_hash: r.array()?,
		};
		value.encode()?;
		Ok(value)
	}
}

#[cfg(test)]
pub(crate) mod tests;
