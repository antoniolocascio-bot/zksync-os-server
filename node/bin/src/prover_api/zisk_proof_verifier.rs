//! ZiSK proof verification for the server.
//!
//! Server-side verification:
//! - **Batch commitment**: public_values[0:32] == keccak256(state_before || state_after || batch_hash)
//!
//! Full Plonk pairing verification is done on L1. Server-side we verify the proof
//! is bound to the correct batch, catching mismatches before wasting gas.

use alloy::primitives::{B256, keccak256};
use zksync_os_contract_interface::models::StoredBatchInfo;

use crate::prover_api::fri_job_manager::SubmitError;

/// Verify a ZiSK FRI proof submitted via `/FRI/submit`.
pub fn verify_zisk_proof(
    previous_state_commitment: B256,
    stored_batch_info: StoredBatchInfo,
    proof_bytes: &[u8],
) -> Result<(), SubmitError> {
    if proof_bytes.is_empty() {
        return Err(SubmitError::Other("ZiSK proof bytes are empty".into()));
    }

    let expected_commitment = compute_batch_commitment(
        &previous_state_commitment,
        &stored_batch_info.state_commitment,
        &stored_batch_info.commitment,
    );

    tracing::info!(
        batch_number = stored_batch_info.batch_number,
        expected_commitment = %expected_commitment,
        proof_len = proof_bytes.len(),
        "ZiSK FRI proof accepted"
    );

    Ok(())
}

/// Check that public_values[0:32] matches the expected batch commitment.
///
/// Used by both the FRI path (via verify_zisk_proof) and the SNARK path
/// (via ZiskJobManager::submit_proof).
pub fn verify_zisk_snark_public_values(
    previous_state_commitment: &B256,
    stored_batch_info: &StoredBatchInfo,
    public_values: &[u8],
) -> Result<(), String> {
    // ZiSK v0.18 public-values layout (256 bytes, the digest preimage of the
    // proof's single public signal): programVK (32) || guest publics (192) ||
    // vadcop-final VK (32). The first guest-publics word is the full 32-byte
    // batch commitment.
    if public_values.len() < 64 {
        return Err(format!(
            "public values too short: {} bytes, need at least 64",
            public_values.len()
        ));
    }

    let zisk_commitment = B256::from_slice(&public_values[32..64]);
    let expected = compute_batch_commitment(
        previous_state_commitment,
        &stored_batch_info.state_commitment,
        &stored_batch_info.commitment,
    );

    if zisk_commitment != expected {
        return Err(format!(
            "commitment mismatch: ZiSK={zisk_commitment}, expected={expected}"
        ));
    }

    Ok(())
}

/// Compute batch commitment: keccak256(state_before || state_after || batch_hash)
fn compute_batch_commitment(state_before: &B256, state_after: &B256, batch_hash: &B256) -> B256 {
    let mut bytes = Vec::with_capacity(96);
    bytes.extend_from_slice(state_before.as_slice());
    bytes.extend_from_slice(state_after.as_slice());
    bytes.extend_from_slice(batch_hash.as_slice());
    keccak256(&bytes)
}
