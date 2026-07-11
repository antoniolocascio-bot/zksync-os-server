use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct BatchDataPayload {
    pub batch_number: u64,
    pub vk_hash: String,
    pub prover_input: String, // base64‑encoded little‑endian u32 array
}

#[derive(Debug, Deserialize)]
pub(super) struct ProverQuery {
    pub id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct FriProofPayload {
    pub batch_number: u64,
    pub vk_hash: String,
    pub proof: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct NextSnarkProverJobPayload {
    pub from_batch_number: u64,
    pub to_batch_number: u64,
    pub vk_hash: String,
    pub fri_proofs: Vec<String>, // base64‑encoded FRI proofs (little‑endian u32 array)
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct SnarkProofPayload {
    pub from_batch_number: u64,
    pub to_batch_number: u64,
    pub vk_hash: String,
    pub proof: String,
}

/// Response for ZiSK batch data pick endpoint.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct ZiskBatchDataPayload {
    pub batch_number: u64,
    pub vk_hash: String,
    /// Base64-encoded bincode-serialized BatchInput for ZiSK prover.
    pub zisk_data: String,
}

/// Payload for submitting a ZiSK SNARK proof.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct ZiskProofPayload {
    pub batch_number: u64,
    /// Base64-encoded ZiSK SNARK proof (768 bytes).
    pub proof: String,
    /// Base64-encoded ZiSK public values (256 bytes).
    pub public_values: String,
}

/// One per-batch entry inside a ZiSK aggregation job payload.
///
/// SCAFFOLDING NOTE: today this carries the per-batch PLONK-wrapped proof
/// the server holds; the aggregator guest consumes the pre-wrap
/// `vadcop_final` streams, which the daemon will retain/submit when the
/// aggregation lane goes live (plan 2.7).
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct ZiskAggregationBatchProof {
    pub batch_number: u64,
    /// Base64-encoded per-batch ZiSK SNARK proof (768 bytes).
    pub proof: String,
    /// Base64-encoded per-batch ZiSK public values (320 bytes).
    pub public_values: String,
}

/// Response for the ZiSK aggregation pick endpoint: a contiguous range of
/// completed per-batch proofs, in batch order.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct ZiskAggregationJobPayload {
    pub from_batch_number: u64,
    pub to_batch_number: u64,
    pub proofs: Vec<ZiskAggregationBatchProof>,
}

/// Payload for submitting an aggregated ZiSK range proof.
#[derive(Debug, Serialize, Deserialize)]
pub(super) struct ZiskAggregationProofPayload {
    pub from_batch_number: u64,
    pub to_batch_number: u64,
    /// Base64-encoded aggregated ZiSK SNARK proof (768 bytes).
    pub proof: String,
    /// Base64-encoded aggregated public values (320 bytes; the aggregator
    /// guest's binding digest sits at bytes [32..64]).
    pub public_values: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct FailedProofResponse {
    pub batch_number: u64,
    pub last_batch_timestamp: u64,
    pub expected_hash_u32s: [u32; 8],
    pub proof_final_register_values: [u32; 16],
    pub vk_hash: String,
    pub proof: String, // base64‑encoded FRI proof (little‑endian u32 array)
}
