extern crate alloc;

use alloc::vec::Vec;
use bitcoin::{
    consensus,
    hashes::{sha256d::Hash as DHash, Hash, HashEngine},
    Transaction,
};
use tracing::error;

/// Computes the Merkle root from coinbase transaction components and a path of transaction hashes.
///
/// Validates and deserializes a coinbase transaction before building the 32-byte Merkle root.
/// The assembled bytes must not only deserialize as a transaction, but also satisfy the coinbase
/// invariant (exactly one input spending the null outpoint, see [`Transaction::is_coinbase`]).
/// Returns [`None`] if the arguments are invalid.
///
/// ## Components
/// * `coinbase_tx_prefix`: First part of the coinbase transaction (the part before the extranonce).
///   Should be converted from [`binary_sv2::B064K`].
/// * `coinbase_tx_suffix`: Coinbase transaction suffix (the part after the extranonce). Should be
///   converted from [`binary_sv2::B064K`].
/// * `extranonce`: Extra nonce space. Should be converted from [`binary_sv2::B032`] and padded with
///   zeros if not `32` bytes long.
/// * `path`: List of transaction hashes. Should be converted from [`binary_sv2::U256`].
pub fn merkle_root_from_path<T: AsRef<[u8]>>(
    coinbase_tx_prefix: &[u8],
    coinbase_tx_suffix: &[u8],
    extranonce: &[u8],
    path: &[T],
) -> Option<[u8; 32]> {
    let mut coinbase =
        Vec::with_capacity(coinbase_tx_prefix.len() + coinbase_tx_suffix.len() + extranonce.len());
    coinbase.extend_from_slice(coinbase_tx_prefix);
    coinbase.extend_from_slice(extranonce);
    coinbase.extend_from_slice(coinbase_tx_suffix);
    let coinbase: Transaction = match consensus::deserialize(&coinbase[..]) {
        Ok(trans) => trans,
        Err(e) => {
            error!("ERROR: {}", e);
            return None;
        }
    };

    if !coinbase.is_coinbase() {
        error!("ERROR: not a coinbase transaction");
        return None;
    }

    let coinbase_id: [u8; 32] = *coinbase.compute_txid().as_ref();

    Some(merkle_root_from_path_(coinbase_id, path))
}

/// Computes the Merkle root from a validated coinbase transaction and a path of transaction
/// hashes.
///
/// If the `path` is empty, the coinbase transaction hash (`coinbase_id`) is returned as the root.
///
/// ## Components
/// * `coinbase_id`: Coinbase transaction hash.
/// * `path`: List of transaction hashes. Should be converted from [`binary_sv2::U256`].
pub fn merkle_root_from_path_<T: AsRef<[u8]>>(coinbase_id: [u8; 32], path: &[T]) -> [u8; 32] {
    let mut root = coinbase_id;
    for node in path {
        let mut engine = DHash::engine();
        engine.input(&root);
        engine.input(node.as_ref());
        root = *DHash::from_engine(engine).as_ref();
    }
    root
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{
        absolute::LockTime,
        blockdata::witness::Witness,
        transaction::{OutPoint, TxIn, TxOut, Version},
        Amount, ScriptBuf, Sequence, Txid,
    };

    fn tx_with_previous_output(previous_output: OutPoint) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(0),
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xffffffff),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(5_000_000_000),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    #[test]
    fn test_rejects_semantically_non_coinbase_transaction() {
        // a validly encoded transaction whose sole input spends a non-null outpoint is not a
        // coinbase, and must be rejected rather than yield a merkle root
        let non_coinbase =
            tx_with_previous_output(OutPoint::new(Txid::from_byte_array([0xab; 32]), 0));
        let serialized = consensus::serialize(&non_coinbase);
        assert!(merkle_root_from_path::<&[u8]>(&serialized, &[], &[], &[]).is_none());

        // the same transaction with a null outpoint is a coinbase and must be accepted
        let coinbase = tx_with_previous_output(OutPoint::null());
        let serialized = consensus::serialize(&coinbase);
        assert!(merkle_root_from_path::<&[u8]>(&serialized, &[], &[], &[]).is_some());
    }
}
