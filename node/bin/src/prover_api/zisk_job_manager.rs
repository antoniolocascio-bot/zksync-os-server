//! Job manager for ZiSK SNARK proof generation.
//!
//! Mirrors `FriJobManager` in architecture:
//! - Batches enter via `add_job` **when the batch is sealed** (the FRI job
//!   manager creates the ZiSK job alongside caching the prover input), so
//!   ZiSK proving runs concurrently with the Airbender FRI + SNARK lane
//!   instead of serialized behind it.
//! - External provers pick jobs via `pick_next_job` (with timeout-based
//!   reassignment) and submit proofs via `submit_proof`.
//! - An accepted proof is validated (sizes, program-VK tripwire, batch
//!   commitment) and parked in the `completed` map. The Airbender SNARK
//!   submission path (`SnarkJobManager`) is the rendezvous point: it takes
//!   the completed ZiSK proof via `take_completed` and composes the
//!   MultiProof — whichever proof arrives last triggers the downstream send.
//!
//! This manager never sends downstream itself; composition and the send
//! permit live in `SnarkJobManager`.

use crate::batcher::batch_builder::ZiskChainConfig;
use crate::prover_api::metrics::ZISK_LANE_METRICS;
use alloy::primitives::B256;
use crate::prover_api::zisk_proof_constants::{ZISK_PUBLIC_VALUES_BYTES, ZISK_SNARK_PROOF_BYTES};
use std::collections::HashMap;
use std::time::Duration;
use tokio::sync::Mutex;
use zksync_os_batch_types::batcher_model::BatchMetadata;

/// Maximum number of pending + assigned + completed-awaiting-SNARK ZiSK jobs.
/// Prevents unbounded memory growth if ZiSK provers are slow or offline, and
/// bounds completed proofs parked while the Airbender lane lags: when full,
/// seal-time job creation is skipped (the SNARK-arrival fallback in
/// `SnarkJobManager` re-creates the job from the data cache later).
const MAX_TOTAL_JOBS: usize = 50;

/// Data stored per ZiSK job, captured at batch seal.
pub struct ZiskJobData {
    /// Bincode-serialized BatchInput for cargo-zisk.
    pub zisk_data: Vec<u8>,
    /// Batch metadata captured at job creation: VK hash for pick, commitment
    /// preimages (previous state commitment + batch info) for submit-time
    /// proof validation.
    pub batch_metadata: BatchMetadata,
    /// When the job was created (batch seal, or the SNARK-arrival fallback).
    /// Preserved across requeues so `zisk_lane_time_to_submit` measures total
    /// wall-clock from job creation to accepted proof.
    pub added_at: std::time::Instant,
}

/// A validated ZiSK proof parked until its Airbender SNARK arrives.
pub struct CompletedZiskProof {
    pub proof: Vec<u8>,
    pub public_values: Vec<u8>,
}

/// Where a batch currently is in the ZiSK lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ZiskBatchStatus {
    /// A validated proof is parked, ready for MultiProof composition.
    Completed,
    /// A job is pending or assigned — a proof is on its way.
    InFlight,
    /// No job and no proof for this batch.
    Unknown,
}

/// Job metadata returned to the prover on pick.
pub struct ZiskJob {
    pub batch_number: u64,
    pub vk_hash: String,
    pub zisk_data: Vec<u8>,
}

/// Errors from ZiSK proof submission.
#[derive(Debug, thiserror::Error)]
pub enum ZiskSubmitError {
    #[error("unknown batch {0}")]
    UnknownJob(u64),
    #[error("invalid proof size: {got} bytes, expected {expected}")]
    InvalidProofSize { got: usize, expected: usize },
    #[error("invalid public values size: {got} bytes, expected {expected}")]
    InvalidPublicValuesSize { got: usize, expected: usize },
    #[error("batch commitment mismatch: ZiSK public values first 32 bytes do not match batch commitment")]
    CommitmentMismatch,
    #[error("program VK mismatch: prover reported {reported}, server expects {expected}")]
    VkDrift { reported: B256, expected: B256 },
}

/// Inner state protected by a single mutex to avoid lock ordering issues.
struct ZiskJobState {
    pending: HashMap<u64, ZiskJobData>,
    assigned: HashMap<u64, (String, std::time::Instant, ZiskJobData)>,
    /// Validated proofs awaiting their Airbender SNARK (the rendezvous).
    completed: HashMap<u64, CompletedZiskProof>,
}

impl ZiskJobState {
    fn total(&self) -> usize {
        self.pending.len() + self.assigned.len() + self.completed.len()
    }

    fn knows(&self, batch_number: u64) -> bool {
        self.pending.contains_key(&batch_number)
            || self.assigned.contains_key(&batch_number)
            || self.completed.contains_key(&batch_number)
    }
}

/// Manages ZiSK SNARK proof jobs with pick/submit assignment model.
pub struct ZiskJobManager {
    state: Mutex<ZiskJobState>,
    /// Assignment timeout — if a prover doesn't submit within this, the job is reassigned.
    assignment_timeout: Duration,
    /// When set, a commitment mismatch halts the node through the critical
    /// task listening on this channel (a mismatch means one proof system is
    /// wrong — a security event). Unset: log + count + retry.
    halt_on_mismatch: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<String>>>,
    /// Expected ZiSK program VK (first 32 bytes of the proof's public
    /// values). When set, a submission with a different VK is rejected and
    /// counted (`zisk_lane_vk_drift`) — the prover runs a different guest
    /// build. Unset: the reported VK is only logged.
    expected_program_vk: Option<B256>,
    /// When set (aggregation stage enabled), every accepted per-batch
    /// proof is COPIED into the aggregation job manager's input buffer,
    /// and discards are forwarded so broken ranges are dropped. The
    /// per-batch `completed` map and its MultiProof rendezvous are
    /// unaffected. See `zisk_aggregation_job_manager.rs` (plan 2.7).
    aggregation_sink:
        std::sync::Mutex<Option<std::sync::Arc<super::zisk_aggregation_job_manager::ZiskAggregationJobManager>>>,
    /// Chain id + chain config: preimage of the `chain_config_hash` word in
    /// the guest's batch public input, needed to compute the expected value.
    chain_id: u64,
    chain_config: ZiskChainConfig,
}

impl ZiskJobManager {
    pub fn new(
        assignment_timeout: Duration,
        expected_program_vk: Option<B256>,
        chain_id: u64,
        chain_config: ZiskChainConfig,
    ) -> Self {
        Self {
            state: Mutex::new(ZiskJobState {
                pending: HashMap::new(),
                assigned: HashMap::new(),
                completed: HashMap::new(),
            }),
            assignment_timeout,
            halt_on_mismatch: std::sync::Mutex::new(None),
            expected_program_vk,
            aggregation_sink: std::sync::Mutex::new(None),
            chain_id,
            chain_config,
        }
    }

    /// Enable the aggregation stage: accepted per-batch proofs are copied
    /// into `sink`'s input buffer, and discards are forwarded to it.
    pub fn set_aggregation_sink(
        &self,
        sink: std::sync::Arc<super::zisk_aggregation_job_manager::ZiskAggregationJobManager>,
    ) {
        *self.aggregation_sink.lock().expect("aggregation sink lock") = Some(sink);
    }

    fn aggregation_sink(
        &self,
    ) -> Option<std::sync::Arc<super::zisk_aggregation_job_manager::ZiskAggregationJobManager>>
    {
        self.aggregation_sink.lock().expect("aggregation sink lock").clone()
    }

    /// Refresh the queue-depth/age gauges. Called under the state lock after
    /// every mutation, and periodically so ages advance while idle.
    fn record_queue_gauges(state: &ZiskJobState) {
        ZISK_LANE_METRICS.jobs_pending.set(state.pending.len() as u64);
        ZISK_LANE_METRICS.jobs_assigned.set(state.assigned.len() as u64);
        ZISK_LANE_METRICS
            .proofs_awaiting_snark
            .set(state.completed.len() as u64);
        let oldest_age = state
            .pending
            .values()
            .map(|d| d.added_at)
            .chain(state.assigned.values().map(|(_, _, d)| d.added_at))
            .min()
            .map(|t| t.elapsed().as_secs())
            .unwrap_or(0);
        ZISK_LANE_METRICS.oldest_job_age_seconds.set(oldest_age);
    }

    /// Refresh the gauges without mutating the queue (periodic liveness).
    pub async fn refresh_gauges(&self) {
        Self::record_queue_gauges(&*self.state.lock().await);
    }

    /// Arm halt-on-mismatch: a commitment mismatch will fire this sender,
    /// bringing the node down via the critical task that awaits it.
    pub fn set_halt_on_mismatch(&self, sender: tokio::sync::oneshot::Sender<String>) {
        *self.halt_on_mismatch.lock().expect("halt sender lock") = Some(sender);
    }

    /// Whether another job can be added without hitting `MAX_TOTAL_JOBS`.
    /// Callers use this to avoid consuming upstream jobs they could not hold.
    pub async fn has_capacity(&self) -> bool {
        self.state.lock().await.total() < MAX_TOTAL_JOBS
    }

    /// Where a batch currently is in the ZiSK lane.
    pub async fn batch_status(&self, batch_number: u64) -> ZiskBatchStatus {
        let state = self.state.lock().await;
        if state.completed.contains_key(&batch_number) {
            ZiskBatchStatus::Completed
        } else if state.pending.contains_key(&batch_number)
            || state.assigned.contains_key(&batch_number)
        {
            ZiskBatchStatus::InFlight
        } else {
            ZiskBatchStatus::Unknown
        }
    }

    /// Add a batch ready for ZiSK proving. Idempotent: a batch already
    /// pending, assigned, or completed is left untouched (`Ok`). A full
    /// queue returns the data to the caller — at batch seal this is plain
    /// backpressure (the SNARK-arrival fallback re-creates the job later).
    pub async fn add_job(&self, batch_number: u64, job_data: ZiskJobData) -> Result<(), ZiskJobData> {
        let mut state = self.state.lock().await;
        if state.knows(batch_number) {
            tracing::debug!(batch = batch_number, "ZiSK job already known, skipping add");
            return Ok(());
        }
        if state.total() >= MAX_TOTAL_JOBS {
            tracing::warn!(
                batch = batch_number,
                pending = state.pending.len(),
                assigned = state.assigned.len(),
                completed = state.completed.len(),
                max = MAX_TOTAL_JOBS,
                "ZiSK job queue full — not adding job (provers offline or Airbender lane behind)"
            );
            return Err(job_data);
        }

        tracing::info!(
            batch = batch_number,
            zisk_data_bytes = job_data.zisk_data.len(),
            "ZiSK job added"
        );
        state.pending.insert(batch_number, job_data);
        Self::record_queue_gauges(&state);
        Ok(())
    }

    /// Pick the next available ZiSK job for a prover.
    pub async fn pick_next_job(&self, prover_id: &str) -> Option<ZiskJob> {
        let now = std::time::Instant::now();
        let mut state = self.state.lock().await;

        // Return timed-out assigned jobs to pending.
        let timed_out: Vec<u64> = state.assigned
            .iter()
            .filter(|(_, (_, assigned_at, _))| now.duration_since(*assigned_at) >= self.assignment_timeout)
            .map(|(&batch, _)| batch)
            .collect();
        for batch in timed_out {
            if let Some((old_prover, _, data)) = state.assigned.remove(&batch) {
                tracing::warn!(batch, old_prover, "ZiSK job timed out, returning to pending");
                state.pending.insert(batch, data);
            }
        }

        // Pick oldest pending.
        let batch_number = *state.pending.keys().min()?;
        let job_data = state.pending.remove(&batch_number)?;

        let vk_hash = job_data
            .batch_metadata
            .verification_key_hash()
            .map(|h| format!("0x{h}"))
            .unwrap_or_else(|_| {
                tracing::warn!(batch = batch_number, "VK hash missing");
                String::new()
            });

        let zisk_data = job_data.zisk_data.clone();
        state.assigned.insert(batch_number, (prover_id.to_string(), now, job_data));
        Self::record_queue_gauges(&state);

        tracing::info!(
            batch = batch_number,
            prover_id,
            "ZiSK job assigned"
        );

        Some(ZiskJob {
            batch_number,
            vk_hash,
            zisk_data,
        })
    }

    /// Submit a ZiSK SNARK proof for a batch.
    ///
    /// Validates proof sizes, the program-VK tripwire, and the batch
    /// commitment against the metadata captured at job creation, then parks
    /// the proof in the `completed` map for the Airbender SNARK submission
    /// path to compose the MultiProof (`take_completed`).
    pub async fn submit_proof(
        &self,
        batch_number: u64,
        proof: Vec<u8>,
        public_values: Vec<u8>,
        prover_id: &str,
    ) -> Result<(), ZiskSubmitError> {
        // Validate sizes.
        if proof.len() != ZISK_SNARK_PROOF_BYTES {
            return Err(ZiskSubmitError::InvalidProofSize {
                got: proof.len(),
                expected: ZISK_SNARK_PROOF_BYTES,
            });
        }
        if public_values.len() != ZISK_PUBLIC_VALUES_BYTES {
            return Err(ZiskSubmitError::InvalidPublicValuesSize {
                got: public_values.len(),
                expected: ZISK_PUBLIC_VALUES_BYTES,
            });
        }

        // Program VK tripwire: the first 32 bytes of the public values
        // are the ZiSK program VK. Drift means the prover runs a different
        // guest build — reject before touching the job, so it stays assigned
        // and times out back to pending for another prover.
        let reported_vk = B256::from_slice(&public_values[..32]);
        if let Some(expected) = self.expected_program_vk {
            if reported_vk != expected {
                ZISK_LANE_METRICS.vk_drift.inc();
                tracing::error!(
                    batch = batch_number,
                    prover_id,
                    %reported_vk,
                    %expected,
                    "ZiSK program VK drift — prover is running a different guest build"
                );
                return Err(ZiskSubmitError::VkDrift {
                    reported: reported_vk,
                    expected,
                });
            }
        } else {
            tracing::info!(batch = batch_number, %reported_vk, "ZiSK program VK reported (no expected VK configured)");
        }

        // Remove from assigned jobs.
        let job_data = {
            let mut state = self.state.lock().await;
            let data = match state.assigned.remove(&batch_number) {
                Some((_, _, data)) => data,
                None => return Err(ZiskSubmitError::UnknownJob(batch_number)),
            };
            Self::record_queue_gauges(&state);
            data
        };

        // Validate batch commitment against the metadata captured at seal.
        let stored = job_data.batch_metadata.batch_info.clone().into_stored();
        let prev = &job_data.batch_metadata.previous_stored_batch_info;
        if let Err(msg) = crate::prover_api::zisk_proof_verifier::verify_zisk_snark_public_values(
            &prev.state_commitment,
            &stored,
            self.chain_id,
            self.chain_config,
            &public_values,
        ) {
            // The headline divergence alarm (one proof system is wrong):
            // always count + log; policy decides continue vs halt.
            ZISK_LANE_METRICS.commitment_mismatches.inc();
            tracing::error!(batch = batch_number, "{msg}");
            if let Some(halt) = self.halt_on_mismatch.lock().expect("halt sender lock").take() {
                let _ = halt.send(format!(
                    "ZiSK commitment mismatch on batch {batch_number}: {msg}"
                ));
            } else {
                // Continue mode: requeue so a faulty prover can be retried
                // (a deterministic divergence keeps paging via the metric).
                let mut state = self.state.lock().await;
                state.pending.insert(batch_number, job_data);
                Self::record_queue_gauges(&state);
            }
            return Err(ZiskSubmitError::CommitmentMismatch);
        }

        tracing::info!(
            batch = batch_number,
            prover_id,
            zisk_proof_bytes = proof.len(),
            "ZiSK proof accepted, awaiting Airbender SNARK for multi-proof composition"
        );

        // Aggregation stage (when enabled): buffer a copy as range input.
        // The parked original below stays the MultiProof rendezvous.
        if let Some(sink) = self.aggregation_sink() {
            sink.on_proof_completed(batch_number, proof.clone(), public_values.clone())
                .await;
        }

        {
            let mut state = self.state.lock().await;
            state.completed.insert(
                batch_number,
                CompletedZiskProof {
                    proof,
                    public_values,
                },
            );
            Self::record_queue_gauges(&state);
        }

        ZISK_LANE_METRICS.time_to_submit.observe(job_data.added_at.elapsed());
        Ok(())
    }

    /// Take the validated proof for a batch, if one is parked. Called by the
    /// Airbender SNARK submission path to compose the MultiProof.
    pub async fn take_completed(&self, batch_number: u64) -> Option<CompletedZiskProof> {
        let mut state = self.state.lock().await;
        let proof = state.completed.remove(&batch_number);
        if proof.is_some() {
            Self::record_queue_gauges(&state);
        }
        proof
    }

    /// Drop parked proofs for batches at or below `batch_to`. Called when a
    /// batch is sent downstream without its ZiSK proof (optional mode, or
    /// degraded after the wait timeout): batches are processed in order, so
    /// a proof for an already-sent batch can never be composed. In-flight
    /// jobs are deliberately left alone — their submit-time validation still
    /// provides the shadow-mode divergence signal.
    pub async fn discard_completed_up_to(&self, batch_to: u64) {
        // Batches sent without their proof can never join an aggregation
        // range either — drop the copies and any range they broke.
        if let Some(sink) = self.aggregation_sink() {
            sink.discard_up_to(batch_to).await;
        }
        let mut state = self.state.lock().await;
        let stale: Vec<u64> = state
            .completed
            .keys()
            .copied()
            .filter(|&b| b <= batch_to)
            .collect();
        if stale.is_empty() {
            return;
        }
        for batch in &stale {
            state.completed.remove(batch);
        }
        tracing::info!(
            batch_to,
            discarded = stale.len(),
            "discarded parked ZiSK proofs for batches already sent without multi-proof"
        );
        Self::record_queue_gauges(&state);
    }

    /// Drop all ZiSK state for a batch range. Used by the fake-SNARK pass so
    /// batches consumed without a real Airbender SNARK (fake-prover
    /// environments, pre-V6 replay) don't leave orphaned jobs behind.
    pub async fn discard_batches(&self, batch_from: u64, batch_to: u64) {
        // The fake-SNARK pass consumes the lowest in-flight batches, so the
        // aggregation lane treats this as an up-to cut as well.
        if let Some(sink) = self.aggregation_sink() {
            sink.discard_up_to(batch_to).await;
        }
        let mut state = self.state.lock().await;
        let mut discarded = 0usize;
        for batch in batch_from..=batch_to {
            discarded += usize::from(state.pending.remove(&batch).is_some());
            discarded += usize::from(state.assigned.remove(&batch).is_some());
            discarded += usize::from(state.completed.remove(&batch).is_some());
        }
        if discarded > 0 {
            tracing::debug!(batch_from, batch_to, discarded, "discarded ZiSK lane state");
            Self::record_queue_gauges(&state);
        }
    }

    /// Check if there are pending or assigned ZiSK jobs.
    pub async fn has_pending_jobs(&self) -> bool {
        let state = self.state.lock().await;
        !state.pending.is_empty() || !state.assigned.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover_api::test_util::create_test_batch_envelope;
    use zksync_os_batch_types::batcher_model::FriProof;

    fn job_data(batch_number: u64, zisk_data: Vec<u8>) -> ZiskJobData {
        let mut envelope = create_test_batch_envelope(batch_number, FriProof::Fake);
        // The fixture's legacy genesis version has no batch-commitment
        // encoding; submit_proof calls into_stored, which needs a current one.
        envelope.batch.batch_info.protocol_version =
            zksync_os_types::ProtocolSemanticVersion::new(0, 31, 0);
        ZiskJobData {
            zisk_data,
            batch_metadata: envelope.batch,
            added_at: std::time::Instant::now(),
        }
    }

    const TEST_CHAIN_ID: u64 = 270;
    const TEST_CHAIN_CONFIG: ZiskChainConfig = ZiskChainConfig {
        fri_proof_verification_enabled: false,
        max_tx_gas_limit: 1 << 24,
    };

    fn manager(expected_vk: Option<B256>) -> ZiskJobManager {
        ZiskJobManager::new(Duration::from_secs(60), expected_vk, TEST_CHAIN_ID, TEST_CHAIN_CONFIG)
    }

    /// Public values whose commitment word matches the job's batch metadata
    /// (computed with the shared expected-PI helper, i.e. the guest lib's own
    /// hash functions), so `submit_proof` gets past commitment verification.
    fn matching_public_values(data: &ZiskJobData) -> Vec<u8> {
        let stored = data.batch_metadata.batch_info.clone().into_stored();
        let prev = &data.batch_metadata.previous_stored_batch_info;
        let commitment = crate::prover_api::zisk_proof_verifier::expected_zisk_public_input(
            &prev.state_commitment,
            &stored,
            TEST_CHAIN_ID,
            TEST_CHAIN_CONFIG,
        );
        let mut public_values = vec![0u8; ZISK_PUBLIC_VALUES_BYTES];
        public_values[32..64].copy_from_slice(commitment.as_slice());
        public_values
    }

    /// The seal-to-rendezvous happy path: an accepted proof parks in
    /// `completed` (status `Completed`), `take_completed` hands it to the
    /// SNARK path exactly once, and the batch is `Unknown` afterwards.
    #[tokio::test]
    async fn accepted_proof_parks_until_taken() {
        let manager = manager(None);

        let zisk_data = vec![0xAB; 32];
        let data = job_data(7, zisk_data.clone());
        let public_values = matching_public_values(&data);
        manager
            .add_job(7, data)
            .await
            .unwrap_or_else(|_| panic!("add_job rejected"));
        assert_eq!(manager.batch_status(7).await, ZiskBatchStatus::InFlight);

        let picked = manager.pick_next_job("prover-1").await.expect("job available");
        assert_eq!(picked.batch_number, 7);
        assert_eq!(picked.zisk_data, zisk_data);
        assert_eq!(manager.batch_status(7).await, ZiskBatchStatus::InFlight);

        manager
            .submit_proof(7, vec![0; ZISK_SNARK_PROOF_BYTES], public_values.clone(), "prover-1")
            .await
            .expect("valid submission accepted");
        assert_eq!(manager.batch_status(7).await, ZiskBatchStatus::Completed);

        let completed = manager.take_completed(7).await.expect("proof parked");
        assert_eq!(completed.public_values, public_values);
        assert!(manager.take_completed(7).await.is_none(), "taken exactly once");
        assert_eq!(manager.batch_status(7).await, ZiskBatchStatus::Unknown);
    }

    /// `add_job` is idempotent across all three lifecycle maps: re-adding a
    /// batch that is pending, assigned, or completed leaves it untouched
    /// (the restart-regeneration path may re-offer batches).
    #[tokio::test]
    async fn add_job_is_idempotent() {
        let manager = manager(None);

        let data = job_data(7, vec![0xAB; 32]);
        let public_values = matching_public_values(&data);
        manager.add_job(7, data).await.unwrap_or_else(|_| panic!("add rejected"));
        // Pending: re-add is a no-op.
        manager
            .add_job(7, job_data(7, vec![0xCD; 8]))
            .await
            .unwrap_or_else(|_| panic!("idempotent re-add"));
        let picked = manager.pick_next_job("prover-1").await.expect("job available");
        assert_eq!(picked.zisk_data, vec![0xAB; 32], "original data kept");
        // Assigned: re-add is a no-op (no second pickable job appears).
        manager
            .add_job(7, job_data(7, vec![0xCD; 8]))
            .await
            .unwrap_or_else(|_| panic!("idempotent re-add"));
        assert!(manager.pick_next_job("prover-2").await.is_none());
        // Completed: re-add is a no-op (the parked proof is not clobbered).
        manager
            .submit_proof(7, vec![0; ZISK_SNARK_PROOF_BYTES], public_values, "prover-1")
            .await
            .expect("accepted");
        manager
            .add_job(7, job_data(7, vec![0xCD; 8]))
            .await
            .unwrap_or_else(|_| panic!("idempotent re-add"));
        assert_eq!(manager.batch_status(7).await, ZiskBatchStatus::Completed);
    }

    /// The fake-SNARK pass cleanup: discarding a range removes pending,
    /// assigned, and completed state so fake-prover environments don't
    /// accumulate orphaned jobs.
    #[tokio::test]
    async fn discard_batches_clears_all_state() {
        let manager = manager(None);

        let data8 = job_data(8, vec![2; 8]);
        let pv8 = matching_public_values(&data8);
        manager.add_job(7, job_data(7, vec![1; 8])).await.unwrap_or_else(|_| panic!());
        manager.add_job(8, data8).await.unwrap_or_else(|_| panic!());
        manager.add_job(9, job_data(9, vec![3; 8])).await.unwrap_or_else(|_| panic!());
        // 7 stays pending; 8 goes to completed; 9 assigned.
        // (pick order is by batch number: 7 first.)
        let picked = manager.pick_next_job("prover-1").await.expect("job");
        assert_eq!(picked.batch_number, 7);
        let picked = manager.pick_next_job("prover-1").await.expect("job");
        assert_eq!(picked.batch_number, 8);
        manager
            .submit_proof(8, vec![0; ZISK_SNARK_PROOF_BYTES], pv8, "prover-1")
            .await
            .expect("accepted");

        manager.discard_batches(7, 9).await;
        for batch in 7..=9 {
            assert_eq!(manager.batch_status(batch).await, ZiskBatchStatus::Unknown);
        }
        assert!(!manager.has_pending_jobs().await);
    }

    /// With halt-on-mismatch armed, a commitment mismatch fires the halt
    /// channel (bringing the node down via the critical task) instead of
    /// silently requeuing the job for endless re-proving.
    #[tokio::test]
    async fn commitment_mismatch_fires_halt_when_armed() {
        let manager = manager(None);
        let (halt_tx, halt_rx) = tokio::sync::oneshot::channel();
        manager.set_halt_on_mismatch(halt_tx);

        manager
            .add_job(7, job_data(7, vec![0xAB; 32]))
            .await
            .unwrap_or_else(|_| panic!("add_job rejected"));
        manager.pick_next_job("prover-1").await.expect("job available");

        // Garbage public values -> commitment mismatch.
        let err = manager
            .submit_proof(
                7,
                vec![0; ZISK_SNARK_PROOF_BYTES],
                vec![0xFF; ZISK_PUBLIC_VALUES_BYTES],
                "prover-1",
            )
            .await
            .expect_err("mismatch must be rejected");
        assert!(matches!(err, ZiskSubmitError::CommitmentMismatch));

        let msg = halt_rx.await.expect("halt channel must fire");
        assert!(msg.contains("batch 7"), "{msg}");
        assert!(
            !manager.has_pending_jobs().await,
            "halting mode must not requeue the mismatching job"
        );
    }

    /// With an aggregation sink attached, an accepted proof is COPIED into
    /// the aggregation input buffer while the parked original still serves
    /// the SNARK rendezvous — enabling the stage must not disturb the
    /// existing MultiProof flow.
    #[tokio::test]
    async fn accepted_proof_feeds_aggregation_sink() {
        use crate::prover_api::zisk_aggregation_job_manager::ZiskAggregationJobManager;

        let manager = manager(None);
        let agg = std::sync::Arc::new(ZiskAggregationJobManager::new(1, Duration::from_secs(60)));
        manager.set_aggregation_sink(agg.clone());

        let data = job_data(7, vec![0xAB; 32]);
        let public_values = matching_public_values(&data);
        manager.add_job(7, data).await.unwrap_or_else(|_| panic!("add rejected"));
        manager.pick_next_job("prover-1").await.expect("job available");
        manager
            .submit_proof(7, vec![0; ZISK_SNARK_PROOF_BYTES], public_values.clone(), "prover-1")
            .await
            .expect("accepted");

        // Range size 1: the copy immediately forms an aggregation job.
        let job = agg.pick_next_job("agg-1").await.expect("aggregation job formed");
        assert_eq!((job.from_batch, job.to_batch), (7, 7));
        assert_eq!(job.proofs[0].1.public_values, public_values);
        // The rendezvous parking is untouched by the copy.
        let completed = manager.take_completed(7).await.expect("still parked");
        assert_eq!(completed.public_values, public_values);
    }

    /// Discards forward to the aggregation sink so its buffered copies and
    /// broken ranges are dropped alongside the per-batch state.
    #[tokio::test]
    async fn discards_forward_to_aggregation_sink() {
        use crate::prover_api::zisk_aggregation_job_manager::ZiskAggregationJobManager;

        let manager = manager(None);
        let agg = std::sync::Arc::new(ZiskAggregationJobManager::new(1, Duration::from_secs(60)));
        manager.set_aggregation_sink(agg.clone());

        let data = job_data(7, vec![0xAB; 32]);
        let public_values = matching_public_values(&data);
        manager.add_job(7, data).await.unwrap_or_else(|_| panic!("add rejected"));
        manager.pick_next_job("prover-1").await.expect("job available");
        manager
            .submit_proof(7, vec![0; ZISK_SNARK_PROOF_BYTES], public_values, "prover-1")
            .await
            .expect("accepted");

        manager.discard_batches(7, 7).await;
        assert!(
            agg.pick_next_job("agg-1").await.is_none(),
            "discarded batch must not form an aggregation range"
        );
    }

    /// With an expected program VK configured, a submission whose public
    /// values embed a different VK is rejected before the job is touched:
    /// the job stays assigned, and a corrected submission still succeeds.
    #[tokio::test]
    async fn vk_drift_rejects_submit_and_keeps_job_assigned() {
        let expected_vk = B256::repeat_byte(0x42);
        let manager = manager(Some(expected_vk));

        let data = job_data(7, vec![0xAB; 32]);
        let mut public_values = matching_public_values(&data);
        manager
            .add_job(7, data)
            .await
            .unwrap_or_else(|_| panic!("add_job rejected"));
        manager.pick_next_job("prover-1").await.expect("job available");

        // Wrong program VK in bytes 0..32 -> drift rejection.
        public_values[..32].copy_from_slice(B256::repeat_byte(0x13).as_slice());
        let err = manager
            .submit_proof(
                7,
                vec![0; ZISK_SNARK_PROOF_BYTES],
                public_values.clone(),
                "prover-1",
            )
            .await
            .expect_err("VK drift must be rejected");
        assert!(matches!(err, ZiskSubmitError::VkDrift { .. }));

        // The job was not consumed or requeued: a submission with the
        // expected VK from the same assignment goes through.
        public_values[..32].copy_from_slice(expected_vk.as_slice());
        manager
            .submit_proof(7, vec![0; ZISK_SNARK_PROOF_BYTES], public_values, "prover-1")
            .await
            .expect("corrected submission succeeds");
        assert_eq!(
            manager.batch_status(7).await,
            ZiskBatchStatus::Completed,
            "proof parked for multi-proof composition"
        );
    }
}
