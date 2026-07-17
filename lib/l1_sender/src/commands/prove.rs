use crate::commands::SendToL1;
use alloy::primitives::{Address, B256, Bytes, U256, keccak256};
use alloy::sol_types::SolCall;
use std::collections::HashMap;
use std::fmt::Display;
use zksync_os_batch_types::batcher_model::{FriProof, SignedBatchEnvelope, SnarkProof};
use zksync_os_batcher_metrics::BatchExecutionStage;
use zksync_os_contract_interface::IExecutor;
use zksync_os_contract_interface::IExecutor::{proofPayloadCall, proveBatchesSharedBridgeCall};
use zksync_os_contract_interface::models::StoredBatchInfo;

const OHBENDER_PROOF_TYPE: u32 = 2;
const FAKE_PROOF_TYPE: u32 = 3;
const FAKE_PROOF_MAGIC_VALUE: u32 = 13;
const MULTI_PROOF_TYPE: u32 = 5;

/// ZiSK Plonk proof: 24 BN254 field elements = 768 bytes.
const ZISK_SNARK_PROOF_BYTES: usize = 768;
/// ZiSK public values: 320 bytes.
// 320 = programVK(32) + guest publics(256: ziskos's full 64-word output
// region, the guest's 8 commitment words first, zeros after) + vadcopVK(32).
// Settled against a real cargo-zisk v0.18 proof file (plan 2.1): the
// draft-era 256/192 assumption undercounted the publics region. The
// commitment stays at [32..64]. NOTE: the on-chain ZiskVerifier's digest
// reconstruction must use the same 320-byte preimage (task 7.x/8).
const ZISK_PUBLIC_VALUES_BYTES: usize = 320;

#[derive(Debug)]
pub struct ProofCommand {
    batches: Vec<SignedBatchEnvelope<FriProof>>,
    proof: SnarkProof,
}

/// Errors from proof calldata encoding.
#[derive(Debug, thiserror::Error)]
pub enum ProofEncodingError {
    #[error("batch commitment mismatch: ZiSK={zisk}, Airbender={era}")]
    BatchCommitmentMismatch { zisk: B256, era: B256 },
    #[error("invalid ZiSK proof size: {got} bytes, expected {expected}")]
    InvalidZiskProofSize { got: usize, expected: usize },
    #[error("invalid ZiSK public values size: {got} bytes, expected {expected}")]
    InvalidZiskPublicValuesSize { got: usize, expected: usize },
    #[error("Airbender proof length ({len}) is not a multiple of 32")]
    AirbenderProofNotAligned { len: usize },
    #[error("unsupported execution version: {version}")]
    UnsupportedExecutionVersion { version: u32 },
}

impl ProofCommand {
    pub fn new(batches: Vec<SignedBatchEnvelope<FriProof>>, proof: SnarkProof) -> Self {
        assert!(
            !batches.is_empty(),
            "ProofCommand must contain at least one batch"
        );
        Self { batches, proof }
    }

    /// Decompose into parts. Used for error recovery when downstream send fails.
    pub fn into_parts(self) -> (Vec<SignedBatchEnvelope<FriProof>>, SnarkProof) {
        (self.batches, self.proof)
    }
}

impl SendToL1 for ProofCommand {
    const COMPONENT_ID: zksync_os_pipeline::ComponentId =
        zksync_os_pipeline::ComponentId::L1SenderProve;
    const SENT_STAGE: BatchExecutionStage = BatchExecutionStage::ProveL1TxSent;
    const MINED_STAGE: BatchExecutionStage = BatchExecutionStage::ProveL1TxMined;
    const PASSTHROUGH_STAGE: BatchExecutionStage = BatchExecutionStage::ProveL1Passthrough;

    fn solidity_call(&self, _operator: &Address) -> Bytes {
        proveBatchesSharedBridgeCall::new((
            self.batches.first().unwrap().batch.chain_address,
            U256::from(self.batches.first().unwrap().batch_number()),
            U256::from(self.batches.last().unwrap().batch_number()),
            self.to_calldata_suffix().into(),
        ))
        .abi_encode()
        .into()
    }
}

impl AsRef<[SignedBatchEnvelope<FriProof>]> for ProofCommand {
    fn as_ref(&self) -> &[SignedBatchEnvelope<FriProof>] {
        self.batches.as_slice()
    }
}

impl AsMut<[SignedBatchEnvelope<FriProof>]> for ProofCommand {
    fn as_mut(&mut self) -> &mut [SignedBatchEnvelope<FriProof>] {
        self.batches.as_mut_slice()
    }
}

impl From<ProofCommand> for Vec<SignedBatchEnvelope<FriProof>> {
    fn from(value: ProofCommand) -> Self {
        value.batches
    }
}

impl Display for ProofCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "prove batches {}-{}",
            self.batches.first().unwrap().batch_number(),
            self.batches.last().unwrap().batch_number()
        )?;
        Ok(())
    }
}

impl ProofCommand {
    fn shift_b256_right(input: &B256) -> B256 {
        let mut bytes = [0_u8; 32];
        bytes[4..32].copy_from_slice(&input.as_slice()[0..28]);
        B256::from_slice(&bytes)
    }

    fn get_batch_public_input(prev_batch: &StoredBatchInfo, batch: &StoredBatchInfo) -> B256 {
        let mut bytes = Vec::with_capacity(32 * 3);
        bytes.extend_from_slice(prev_batch.state_commitment.as_slice());
        bytes.extend_from_slice(batch.state_commitment.as_slice());
        bytes.extend_from_slice(batch.commitment.as_slice());
        keccak256(&bytes)
    }
    fn snark_public_input(previous_batch: &StoredBatchInfo, batches: &[StoredBatchInfo]) -> B256 {
        let mut hash_map: HashMap<usize, &StoredBatchInfo> = HashMap::new();
        hash_map.insert(previous_batch.batch_number as usize, previous_batch);
        for batch in batches {
            hash_map.insert(batch.batch_number as usize, batch);
        }
        let start = batches.first().unwrap().batch_number as usize;
        let end = batches.last().unwrap().batch_number as usize;

        // taken from https://github.com/mm-zk/zksync_tools/blob/cf2c47d61fa8399a030d0b31d4396832f802489b/prove_execute/src/main.rs
        let mut result: Option<B256> = None;
        for i in start..=end {
            let batch = hash_map.get(&i).expect("Batch not found");
            let prev_batch = hash_map.get(&(i - 1)).expect("Previous batch not found");
            let public_input = Self::get_batch_public_input(prev_batch, batch);
            // Snark public input is public_input >> 32.
            let snark_input = Self::shift_b256_right(&public_input);

            match result {
                Some(ref mut res) => {
                    // Combine with previous result.
                    let mut combined = [0_u8; 64];
                    combined[..32].copy_from_slice(&res.0);
                    combined[32..].copy_from_slice(&snark_input.0);
                    *res = Self::shift_b256_right(&keccak256(combined));
                }
                None => {
                    result = Some(snark_input);
                }
            }
        }
        result.unwrap()
    }
    fn to_calldata_suffix(&self) -> Vec<u8> {
        self.try_to_calldata_suffix()
            .expect("proof calldata encoding failed: this is a critical pipeline bug")
    }

    fn try_to_calldata_suffix(&self) -> Result<Vec<u8>, ProofEncodingError> {
        let previous_batch_info = &self
            .batches
            .first()
            .expect("ProofCommand must have at least one batch")
            .batch
            .previous_stored_batch_info;
        let stored_batch_infos: Vec<StoredBatchInfo> = self
            .batches
            .iter()
            .map(|batch| batch.batch.batch_info.clone().into_stored())
            .collect();
        let verifier_version = match self.proof.proving_execution_version() {
            None => 0,
            Some(4) => 4,
            Some(5) => 5,
            Some(6) => 6,
            // MultiProof routes its execution version straight through: the
            // MultiProofVerifier resolves sub-verifiers by version on-chain.
            Some(v) if matches!(self.proof, SnarkProof::MultiProof(_)) => v,
            Some(7) => 0,
            Some(version) => {
                return Err(ProofEncodingError::UnsupportedExecutionVersion { version });
            }
        };

        let public_input = Self::snark_public_input(previous_batch_info, &stored_batch_infos);
        tracing::info!(public_input = %public_input, "computed SNARK public input");

        let proof: Vec<U256> = match &self.proof {
            SnarkProof::Fake => {
                vec![
                    U256::from(FAKE_PROOF_TYPE),
                    // OhBender 'previous hash': for a fake proof we can always
                    // assume that it matches the range perfectly.
                    U256::from(0),
                    U256::from(FAKE_PROOF_MAGIC_VALUE),
                    // Public input: the fake proof still verifies this against
                    // the batch data stored in the contract.
                    U256::from_be_bytes(public_input.0),
                ]
            }
            SnarkProof::Real(real) => {
                let proof: Vec<U256> = real
                    .proof()
                    .chunks(32)
                    .map(|chunk| {
                        let arr: [u8; 32] = chunk
                            .try_into()
                            .expect("proof bytes must be a multiple of 32");
                        U256::from_be_bytes(arr)
                    })
                    .collect();
                vec![
                    U256::from(OHBENDER_PROOF_TYPE | (verifier_version << 8)),
                    // We generate SNARK proofs to always match the range perfectly.
                    U256::from(0),
                ]
                .into_iter()
                .chain(proof)
                .collect()
            }
            SnarkProof::MultiProof(multi_proof) => {
                // Validate proof sizes; these are invariants of the ZiSK Plonk verifier.
                if multi_proof.zisk_proof.len() != ZISK_SNARK_PROOF_BYTES {
                    return Err(ProofEncodingError::InvalidZiskProofSize {
                        got: multi_proof.zisk_proof.len(),
                        expected: ZISK_SNARK_PROOF_BYTES,
                    });
                }
                if multi_proof.zisk_public_values.len() != ZISK_PUBLIC_VALUES_BYTES {
                    return Err(ProofEncodingError::InvalidZiskPublicValuesSize {
                        got: multi_proof.zisk_public_values.len(),
                        expected: ZISK_PUBLIC_VALUES_BYTES,
                    });
                }
                if multi_proof.era_proof.len() % 32 != 0 {
                    return Err(ProofEncodingError::AirbenderProofNotAligned {
                        len: multi_proof.era_proof.len(),
                    });
                }

                // Cross-proof validation: both proof systems must commit to the
                // same batch. ZiSK v0.18 public values are
                // programVK(32) || guest publics(256) || vadcop VK(32), with the
                // full batch commitment as the first guest-publics word.
                let zisk_commitment = B256::from_slice(&multi_proof.zisk_public_values[32..64]);
                let era_commitment =
                    Self::get_batch_public_input(previous_batch_info, &stored_batch_infos[0]);
                if zisk_commitment != era_commitment {
                    tracing::error!(
                        zisk = %zisk_commitment,
                        era = %era_commitment,
                        prev_state = %previous_batch_info.state_commitment,
                        batch_state = %stored_batch_infos[0].state_commitment,
                        batch_hash = %stored_batch_infos[0].commitment,
                        "batch commitment mismatch between ZiSK and Airbender"
                    );
                    return Err(ProofEncodingError::BatchCommitmentMismatch {
                        zisk: zisk_commitment,
                        era: era_commitment,
                    });
                }
                tracing::info!("cross-proof validation passed: commitments match");

                let to_u256_chunks = |bytes: &[u8]| -> Vec<U256> {
                    bytes
                        .chunks_exact(32)
                        .map(|c| {
                            let arr: [u8; 32] = c.try_into().unwrap();
                            U256::from_be_bytes(arr)
                        })
                        .collect()
                };

                let era_chunks = to_u256_chunks(&multi_proof.era_proof);
                let zisk_proof_chunks = to_u256_chunks(&multi_proof.zisk_proof);
                let zisk_pv_chunks = to_u256_chunks(&multi_proof.zisk_public_values);

                let mut proof_vec = vec![
                    U256::from(MULTI_PROOF_TYPE | (verifier_version << 8)),
                    U256::from(0),                // previous hash
                    U256::from(era_chunks.len()), // N
                ];
                proof_vec.extend(era_chunks);
                proof_vec.extend(zisk_proof_chunks);
                proof_vec.extend(zisk_pv_chunks);
                proof_vec
            }
        };

        let proof_payload = proofPayloadCall {
            old: IExecutor::StoredBatchInfo::from(previous_batch_info),
            newInfo: stored_batch_infos
                .iter()
                .map(Into::into) // into `IExecutor::StoredBatchInfo`
                .collect(),
            proof,
        };

        /// Current commitment encoding version as per protocol.
        const SUPPORTED_ENCODING_VERSION: u8 = 1;

        let mut proof_data = vec![SUPPORTED_ENCODING_VERSION];
        proof_payload.abi_encode_raw(&mut proof_data);
        Ok(proof_data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zksync_os_batch_types::batcher_model::MultiProofSnarkProof;

    #[test]
    fn test_multi_proof_serde_roundtrip() {
        let multi_proof = MultiProofSnarkProof {
            era_proof: vec![0xAB; 64],
            zisk_proof: vec![0xCD; 768],
            zisk_public_values: vec![0xEF; 256],
            proving_execution_version: 6,
        };
        let snark = SnarkProof::MultiProof(multi_proof);
        let json = serde_json::to_string(&snark).unwrap();
        let decoded: SnarkProof = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.proving_execution_version(), Some(6));
        assert_eq!(decoded.proof().unwrap().len(), 64);
    }

    #[test]
    fn test_multi_proof_proving_version() {
        let snark = SnarkProof::MultiProof(MultiProofSnarkProof {
            era_proof: vec![],
            zisk_proof: vec![],
            zisk_public_values: vec![],
            proving_execution_version: 6,
        });
        assert_eq!(snark.proving_execution_version(), Some(6));

        // era_proof is returned from proof()
        let snark2 = SnarkProof::MultiProof(MultiProofSnarkProof {
            era_proof: vec![1, 2, 3],
            zisk_proof: vec![4, 5, 6],
            zisk_public_values: vec![7, 8, 9],
            proving_execution_version: 5,
        });
        assert_eq!(snark2.proof(), Some(&[1u8, 2, 3][..]));
        assert_eq!(snark2.proving_execution_version(), Some(5));
    }

    #[test]
    fn test_backward_compat_existing_variants() {
        // Fake proof still works
        let fake = SnarkProof::Fake;
        assert_eq!(fake.proving_execution_version(), None);
        assert!(fake.proof().is_none());

        // Real proof still works
        let real = SnarkProof::Real(zksync_os_batch_types::batcher_model::RealSnarkProof::V2 {
            proof: vec![0xAA; 32],
            proving_execution_version: 6,
        });
        assert_eq!(real.proving_execution_version(), Some(6));
        assert_eq!(real.proof().unwrap().len(), 32);
    }

    #[test]
    fn test_multi_proof_type_constant() {
        // MULTI_PROOF_TYPE must be distinct from existing types
        assert_ne!(MULTI_PROOF_TYPE, OHBENDER_PROOF_TYPE);
        assert_ne!(MULTI_PROOF_TYPE, FAKE_PROOF_TYPE);
        assert_eq!(MULTI_PROOF_TYPE, 5);
    }

    #[test]
    fn test_multi_proof_encoding_type_field() {
        // Verify the proof type encoding formula
        let verifier_version: u32 = 6;
        let encoded = MULTI_PROOF_TYPE | (verifier_version << 8);
        // Type is in low byte
        assert_eq!(encoded & 0xFF, MULTI_PROOF_TYPE);
        // Version is in higher bytes
        assert_eq!(encoded >> 8, verifier_version);
    }
}
