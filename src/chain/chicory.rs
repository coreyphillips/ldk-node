//! Chain evidence for the native splice-conflict protocol. A peer's transaction
//! identifiers only select what to inspect; they never establish confirmation.

use bitcoin::{BlockHash, Transaction, Txid};
use lightning::chain::BestBlock;
use std::sync::Arc;

use super::{ChainSource, ChainSourceKind};
use crate::Error;

#[cfg(test)]
mod backend_tests;

/// A transaction proved present in the configured backend's active chain at an
/// exact native tip. The native rollback method must recheck that tip and the
/// complete candidate identity after this asynchronous lookup.
pub(crate) struct ConfirmedTransaction {
	pub transaction: Transaction,
	pub block_hash: BlockHash,
	pub height: u32,
	pub tip: BestBlock,
}

pub(super) fn sufficiently_confirmed(height: u32, tip: BestBlock) -> bool {
	height > 0 && tip.height.checked_sub(height).is_some_and(|age| age >= 5)
}

impl ChainSource {
	/// Serialize a conflict commit with every native manager/monitor apply batch.
	/// False means a prior batch was incomplete or cancelled. Proof lookups must
	/// not hold this gate. A complete subsequent native sync clears the hold.
	pub(crate) fn chain_apply_gate(&self) -> Arc<tokio::sync::Mutex<bool>> {
		match &self.kind {
			ChainSourceKind::Bitcoind(source) => Arc::clone(&source.chain_apply_gate),
			ChainSourceKind::Electrum(source) => Arc::clone(&source.chain_apply_gate),
			ChainSourceKind::Esplora(source) => Arc::clone(&source.chain_apply_gate),
		}
	}
	/// Fetch bounded conflict evidence without advancing native chain state. A
	/// concurrent reorg or missing/index-unavailable transaction refuses proof.
	pub(crate) async fn confirmed_transaction(
		&self, txid: Txid, tip: BestBlock,
	) -> Result<ConfirmedTransaction, Error> {
		let proof = tokio::time::timeout(std::time::Duration::from_secs(15), async {
			match &self.kind {
				ChainSourceKind::Bitcoind(source) => source.confirmed_transaction(txid, tip).await,
				ChainSourceKind::Electrum(source) => source.confirmed_transaction(txid, tip).await,
				ChainSourceKind::Esplora(source) => source.confirmed_transaction(txid, tip).await,
			}
		})
		.await
		.map_err(|_| Error::TxSyncFailed)??;
		if proof.transaction.compute_txid() != txid
			|| proof.tip != tip
			|| !sufficiently_confirmed(proof.height, tip)
		{
			return Err(Error::TxSyncFailed);
		}
		Ok(proof)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use bitcoin::hashes::Hash;

	#[test]
	fn conflict_requires_six_confirmations_on_a_known_tip() {
		let tip = BestBlock::new(BlockHash::all_zeros(), 100);
		assert!(!sufficiently_confirmed(0, tip));
		assert!(!sufficiently_confirmed(101, tip));
		assert!(!sufficiently_confirmed(100, tip));
		assert!(!sufficiently_confirmed(96, tip));
		assert!(sufficiently_confirmed(95, tip));
		assert!(sufficiently_confirmed(1, tip));
		assert!(!sufficiently_confirmed(1, BestBlock::new(BlockHash::all_zeros(), 0)));
	}
}
