//! Recovering deployed bytecode from blake2s-keyed preimage blobs.

use super::*;

/// Recover the raw EVM code whose `keccak256` equals `keccak_key` from a
/// blake2s preimage blob (`code || padding || jumpdest-artifacts`) and push it
/// into the guest's keccak-keyed bytecode map.
///
/// `unpadded_code_len` is the fast path — it holds for virtually every account
/// — but it is not reliable for all (observed off for some upgrade
/// force-deploy targets, leaving alignment padding in the slice). Since the
/// observable hash IS `keccak256(unpadded code)`, the code is the unique blob
/// prefix that hashes to it, so on a fast-path miss we scan prefix lengths to
/// recover exactly that code. A wrong-keyed entry would poison the map the
/// guest verifies with `keccak256(code) == key`, so nothing is pushed unless
/// it matches. Returns whether an entry was accepted.
pub(super) fn push_code_from_blob(
    keccak_key: B256,
    blob: &[u8],
    unpadded_code_len: usize,
    bytecodes_map: &mut HashMap<B256, Bytecode>,
    bytecodes_out: &mut Vec<(B256, Vec<u8>)>,
) -> bool {
    let Some(code) = recover_code_matching(keccak_key, blob, unpadded_code_len) else {
        tracing::debug!(
            key = %keccak_key, blob_len = blob.len(),
            "no blob prefix reproduces the keccak key; not preloading"
        );
        return false;
    };
    if let std::collections::hash_map::Entry::Vacant(entry) = bytecodes_map.entry(keccak_key) {
        bytecodes_out.push((keccak_key, code.to_vec()));
        entry.insert(Bytecode::new_raw(Bytes::copy_from_slice(code.as_slice())));
    }
    true
}

/// Recover the raw EVM code whose `keccak256` equals `keccak_key` from a
/// blake2s preimage blob (`code || padding || jumpdest-artifacts`).
/// `unpadded_code_len` is the fast path; on a miss the unique matching blob
/// prefix is found by scan (see `push_code_from_blob`). `None` if no prefix
/// matches.
pub(crate) fn recover_code_matching(
    keccak_key: B256,
    blob: &[u8],
    unpadded_code_len: usize,
) -> Option<Vec<u8>> {
    if unpadded_code_len > 0
        && unpadded_code_len <= blob.len()
        && alloy::primitives::keccak256(&blob[..unpadded_code_len]) == keccak_key
    {
        return Some(blob[..unpadded_code_len].to_vec());
    }
    (1..=blob.len())
        .find(|&n| alloy::primitives::keccak256(&blob[..n]) == keccak_key)
        .map(|n| blob[..n].to_vec())
}
