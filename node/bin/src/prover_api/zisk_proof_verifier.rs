//! ZiSK proof verification for the server.
//!
//! Server-side verification:
//! - **Batch public input**: the guest's committed value is
//!   `keccak256(state_before ‖ state_after ‖ chain_config_hash ‖ batch_output_hash)`
//!   (`zksync_os_zisk_lib::commitment::batch_public_input_hash`), carried in
//!   `public_values[32..64]` of the ZiSK v0.18 layout
//!   (`programVK (32) ‖ guest publics (192) ‖ vadcop-final VK (32)`).
//!
//! Full Plonk pairing verification is done on L1. Server-side we verify the proof
//! is bound to the correct batch, catching mismatches before wasting gas. The
//! expected value is computed with the guest lib's own commitment functions, so
//! the two sides cannot drift silently.

use alloy::primitives::B256;
use zksync_os_contract_interface::models::StoredBatchInfo;
use zksync_os_zisk_lib::commitment as zisk_commitment;

use crate::batcher::batch_builder::ZiskChainConfig;
use crate::prover_api::fri_job_manager::SubmitError;

/// The batch public input the ZiSK guest commits to, computed from server-side
/// batch metadata with the guest lib's own hash functions.
pub fn expected_zisk_public_input(
    previous_state_commitment: &B256,
    stored_batch_info: &StoredBatchInfo,
    chain_id: u64,
    chain_config: ZiskChainConfig,
) -> B256 {
    let chain_config_hash = zisk_commitment::chain_config_hash(
        chain_id,
        chain_config.fri_proof_verification_enabled,
        chain_config.max_tx_gas_limit,
    );
    zisk_commitment::batch_public_input_hash(
        previous_state_commitment,
        &stored_batch_info.state_commitment,
        &chain_config_hash,
        &stored_batch_info.commitment,
    )
}

/// Verify a ZiSK FRI proof submitted via `/FRI/submit`.
pub fn verify_zisk_proof(
    _previous_state_commitment: B256,
    stored_batch_info: StoredBatchInfo,
    proof_bytes: &[u8],
) -> Result<(), SubmitError> {
    if proof_bytes.is_empty() {
        return Err(SubmitError::Other("ZiSK proof bytes are empty".into()));
    }

    // The binding check against the batch public input happens at SNARK
    // submission (`ZiskJobManager::submit_proof`), where the chain config
    // needed for the expected value is available.
    tracing::info!(
        batch_number = stored_batch_info.batch_number,
        proof_len = proof_bytes.len(),
        "ZiSK FRI proof accepted"
    );

    Ok(())
}

/// Check that `public_values[32..64]` matches the expected batch public input.
///
/// Used by the SNARK path (`ZiskJobManager::submit_proof`) and by the shadow
/// execution self-check in the batcher.
pub fn verify_zisk_snark_public_values(
    previous_state_commitment: &B256,
    stored_batch_info: &StoredBatchInfo,
    chain_id: u64,
    chain_config: ZiskChainConfig,
    public_values: &[u8],
) -> Result<(), String> {
    // ZiSK v0.18 public-values layout (256 bytes, the digest preimage of the
    // proof's single public signal): programVK (32) || guest publics (192) ||
    // vadcop-final VK (32). The first guest-publics word is the full 32-byte
    // batch public input.
    if public_values.len() < 64 {
        return Err(format!(
            "public values too short: {} bytes, need at least 64",
            public_values.len()
        ));
    }

    let zisk_commitment = B256::from_slice(&public_values[32..64]);
    let expected = expected_zisk_public_input(
        previous_state_commitment,
        stored_batch_info,
        chain_id,
        chain_config,
    );

    if zisk_commitment != expected {
        return Err(format!(
            "commitment mismatch: ZiSK={zisk_commitment}, expected={expected}"
        ));
    }

    Ok(())
}
