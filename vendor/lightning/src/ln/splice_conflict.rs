//! Native, durable evidence for an explicitly retired splice candidate.

use crate::chain::BestBlock;
use crate::ln::types::ChannelId;
use bitcoin::secp256k1::PublicKey;
use bitcoin::{BlockHash, Transaction, Txid};

pub(crate) const MAX_RETIRED_SPLICES: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SpliceConflictRecord {
	pub(crate) channel_id: ChannelId,
	pub(crate) counterparty_node_id: PublicKey,
	pub(crate) splice_txid: Txid,
	pub(crate) conflict_txid: Txid,
	pub(crate) input_index: u16,
	pub(crate) confirmation_height: u32,
	pub(crate) confirmation_hash: BlockHash,
	pub(crate) verified_tip: BestBlock,
	pub(crate) update_id: u64,
}
impl_writeable_tlv_based!(SpliceConflictRecord, {
	(0, channel_id, required),
	(2, counterparty_node_id, required),
	(4, splice_txid, required),
	(6, conflict_txid, required),
	(8, input_index, required),
	(10, confirmation_height, required),
	(12, confirmation_hash, required),
	(14, verified_tip, required),
	(16, update_id, required),
});
impl SpliceConflictRecord {
	pub(crate) fn validate(
		&self, candidate: &Transaction, conflict: &Transaction, shared: bitcoin::OutPoint,
	) -> Result<(), ()> {
		if candidate.compute_txid() != self.splice_txid
			|| conflict.compute_txid() != self.conflict_txid
			|| self.splice_txid == self.conflict_txid
			|| self.confirmation_height == 0
			|| self
				.confirmation_height
				.checked_add(5)
				.map_or(true, |height| height > self.verified_tip.height)
		{
			return Err(());
		}
		let input = candidate.input.get(self.input_index as usize).ok_or(())?.previous_output;
		if input == shared
			|| conflict.input.iter().any(|input| input.previous_output == shared)
			|| !candidate.input.iter().any(|input| input.previous_output == shared)
			|| !conflict.input.iter().any(|conflict_input| conflict_input.previous_output == input)
		{
			return Err(());
		}
		Ok(())
	}
}
