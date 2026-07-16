//! Job manager for per-batch ZiSK proof generation.
//!
//! Mirrors `FriJobManager` in architecture:
//! - Batches enter via `add_job` **when the batch is sealed** (the FRI job
//!   manager creates the ZiSK job alongside caching the prover input), so
//!   ZiSK proving runs concurrently with the Airbender FRI + SNARK lane
//!   instead of serialized behind it.
//! - External provers pick jobs via `pick_next_job` (with timeout-based
//!   reassignment) and submit proofs via `submit_proof`.
//! - An accepted proof is validated (shape, program-VK tripwire, batch
//!   commitment) and parked in the `completed` map.
//!
//! The manager runs in one of two modes, fixed at startup:
//!
//! - **Per-batch PLONK mode** (aggregation disabled): the daemon submits a
//!   768-byte PLONK-wrapped SNARK + 320-byte public values per batch. The
//!   Airbender SNARK submission path (`SnarkJobManager`) is the rendezvous
//!   point: it takes the completed ZiSK proof via `take_completed` and
//!   composes the MultiProof — whichever proof arrives last triggers the
//!   downstream send.
//! - **Aggregated mode** (aggregation enabled, marked by the attached
//!   aggregation sink): the daemon submits the raw `vadcop_final` proof
//!   stream (~330 KiB) instead. The validated stream is buffered in the
//!   aggregation manager as range input AND parked here mode-tagged (for
//!   idempotence and lane status); the MultiProof rendezvous then pairs
//!   the Airbender range SNARK with the aggregated range proof, not with
//!   per-batch proofs.
//!
//! This manager never sends downstream itself; composition and the send
//! permit live in `SnarkJobManager`.

use crate::batcher::batch_builder::ZiskChainConfig;
use crate::prover_api::metrics::ZISK_LANE_METRICS;
use crate::prover_api::zisk_aggregation_job_manager::AggregationInput;
use crate::prover_api::zisk_proof_constants::{ZISK_PUBLIC_VALUES_BYTES, ZISK_SNARK_PROOF_BYTES};
use crate::prover_api::zisk_vadcop_stream::{ZISK_VADCOP_STREAM_BYTES, parse_vadcop_final_stream};
use alloy::primitives::B256;
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

/// A validated per-batch ZiSK proof parked in the `completed` map,
/// mode-tagged by what the daemon submitted.
pub enum CompletedZiskProof {
    /// Per-batch PLONK mode: the 768-byte SNARK + 320-byte public values,
    /// ready for single-batch MultiProof composition.
    Plonk {
        proof: Vec<u8>,
        public_values: Vec<u8>,
    },
    /// Aggregated mode: the raw `vadcop_final` proof stream. Composition
    /// happens at range level via the aggregation manager (which buffered
    /// its own copy as range input); this entry marks the batch completed
    /// so job re-creation stays idempotent and lane status is accurate.
    VadcopFinal { stream: Vec<u8> },
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
    #[error("invalid proof size: {got} bytes, expected {expected}{hint}")]
    InvalidProofSize {
        got: usize,
        expected: usize,
        hint: &'static str,
    },
    #[error("invalid public values size: {got} bytes, expected {expected}")]
    InvalidPublicValuesSize { got: usize, expected: usize },
    #[error("malformed vadcop_final proof stream: {0}")]
    MalformedProof(String),
    #[error("batch commitment mismatch: ZiSK proof public values do not match batch commitment")]
    CommitmentMismatch,
    #[error("program VK mismatch: prover reported {reported}, server expects {expected}")]
    VkDrift { reported: B256, expected: B256 },
}

/// Inner state protected by a single mutex to avoid lock ordering issues.
struct ZiskJobState {
    pending: HashMap<u64, ZiskJobData>,
    assigned: HashMap<u64, (String, std::time::Instant, ZiskJobData)>,
    /// Validated proofs awaiting composition (per-batch rendezvous in PLONK
    /// mode; completion markers in aggregated mode).
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
    /// Expected ZiSK program VK of the STF guest build. When set, a
    /// submission with a different VK is rejected and counted
    /// (`zisk_lane_vk_drift`) — the prover runs a different guest build.
    /// Unset: the reported VK is only logged.
    expected_program_vk: Option<B256>,
    /// When set, the lane runs in AGGREGATED mode: per-batch submissions
    /// are `vadcop_final` streams, every accepted one is buffered in the
    /// aggregation manager as range input, and discards are forwarded so
    /// broken ranges are dropped. See `zisk_aggregation_job_manager.rs`.
    aggregation_sink: std::sync::Mutex<
        Option<std::sync::Arc<super::zisk_aggregation_job_manager::ZiskAggregationJobManager>>,
    >,
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

    /// Switch the lane to aggregated mode: per-batch submissions become
    /// `vadcop_final` streams, accepted ones are buffered in `sink` as
    /// range input, and discards are forwarded to it.
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
        self.aggregation_sink
            .lock()
            .expect("aggregation sink lock")
            .clone()
    }

    /// Refresh the queue-depth/age gauges. Called under the state lock after
    /// every mutation, and periodically so ages advance while idle.
    fn record_queue_gauges(state: &ZiskJobState) {
        ZISK_LANE_METRICS
            .jobs_pending
            .set(state.pending.len() as u64);
        ZISK_LANE_METRICS
            .jobs_assigned
            .set(state.assigned.len() as u64);
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
    pub async fn add_job(
        &self,
        batch_number: u64,
        job_data: ZiskJobData,
    ) -> Result<(), ZiskJobData> {
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
        let timed_out: Vec<u64> = state
            .assigned
            .iter()
            .filter(|(_, (_, assigned_at, _))| {
                now.duration_since(*assigned_at) >= self.assignment_timeout
            })
            .map(|(&batch, _)| batch)
            .collect();
        for batch in timed_out {
            if let Some((old_prover, _, data)) = state.assigned.remove(&batch) {
                tracing::warn!(
                    batch,
                    old_prover,
                    "ZiSK job timed out, returning to pending"
                );
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
        state
            .assigned
            .insert(batch_number, (prover_id.to_string(), now, job_data));
        Self::record_queue_gauges(&state);

        tracing::info!(batch = batch_number, prover_id, "ZiSK job assigned");

        Some(ZiskJob {
            batch_number,
            vk_hash,
            zisk_data,
        })
    }

    /// Submit a per-batch ZiSK proof.
    ///
    /// PLONK mode: `proof` is the 768-byte SNARK, `public_values` the
    /// 320-byte wire layout. Aggregated mode: `proof` is the raw
    /// `vadcop_final` stream and `public_values` must be empty (the stream
    /// carries its publics).
    ///
    /// Validates the shape, the program-VK tripwire, and the batch
    /// commitment against the metadata captured at job creation, then parks
    /// the proof in the `completed` map (and, in aggregated mode, buffers
    /// it in the aggregation manager as range input).
    pub async fn submit_proof(
        &self,
        batch_number: u64,
        proof: Vec<u8>,
        public_values: Vec<u8>,
        prover_id: &str,
    ) -> Result<(), ZiskSubmitError> {
        let sink = self.aggregation_sink();

        // Mode-dependent shape validation and public-data extraction.
        let (reported_vk, commitment, vadcop_publics) = if sink.is_some() {
            if proof.len() != ZISK_VADCOP_STREAM_BYTES {
                return Err(ZiskSubmitError::InvalidProofSize {
                    got: proof.len(),
                    expected: ZISK_VADCOP_STREAM_BYTES,
                    hint: " (aggregated mode expects the raw vadcop_final stream; \
                           run the daemon with --aggregation)",
                });
            }
            if !public_values.is_empty() {
                return Err(ZiskSubmitError::InvalidPublicValuesSize {
                    got: public_values.len(),
                    expected: 0,
                });
            }
            let parsed =
                parse_vadcop_final_stream(&proof).map_err(ZiskSubmitError::MalformedProof)?;
            (parsed.program_vk, parsed.commitment, Some(parsed))
        } else {
            if proof.len() != ZISK_SNARK_PROOF_BYTES {
                return Err(ZiskSubmitError::InvalidProofSize {
                    got: proof.len(),
                    expected: ZISK_SNARK_PROOF_BYTES,
                    hint: " (per-batch PLONK mode expects the wrapped SNARK; \
                           is the daemon running with --aggregation against a \
                           server that has zisk_aggregation disabled?)",
                });
            }
            if public_values.len() != ZISK_PUBLIC_VALUES_BYTES {
                return Err(ZiskSubmitError::InvalidPublicValuesSize {
                    got: public_values.len(),
                    expected: ZISK_PUBLIC_VALUES_BYTES,
                });
            }
            (
                B256::from_slice(&public_values[..32]),
                B256::from_slice(&public_values[32..64]),
                None,
            )
        };

        // Program VK tripwire: drift means the prover runs a different
        // guest build — reject before touching the job, so it stays assigned
        // and times out back to pending for another prover.
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

        // Validate the batch commitment against the metadata captured at
        // seal, using the guest lib's own hash functions.
        let stored = job_data.batch_metadata.batch_info.clone().into_stored();
        let prev = &job_data.batch_metadata.previous_stored_batch_info;
        let expected_commitment =
            crate::prover_api::zisk_proof_verifier::expected_zisk_public_input(
                &prev.state_commitment,
                &stored,
                self.chain_id,
                self.chain_config,
            );
        if commitment != expected_commitment {
            // The headline divergence alarm (one proof system is wrong):
            // always count + log; policy decides continue vs halt.
            let msg =
                format!("commitment mismatch: ZiSK={commitment}, expected={expected_commitment}");
            ZISK_LANE_METRICS.commitment_mismatches.inc();
            tracing::error!(batch = batch_number, "{msg}");
            if let Some(halt) = self
                .halt_on_mismatch
                .lock()
                .expect("halt sender lock")
                .take()
            {
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
            aggregated = vadcop_publics.is_some(),
            "ZiSK proof accepted"
        );

        // Aggregated mode: buffer a copy as range input for the
        // aggregation manager; the mode-tagged entry parked below keeps
        // the lane status and job idempotence intact.
        if let (Some(sink), Some(parsed)) = (&sink, &vadcop_publics) {
            sink.on_proof_completed(
                batch_number,
                AggregationInput {
                    stream: proof.clone(),
                    program_vk: parsed.program_vk,
                    vadcop_vk: parsed.vadcop_vk,
                    commitment: parsed.commitment,
                },
            )
            .await;
        }

        let completed = match vadcop_publics {
            Some(_) => CompletedZiskProof::VadcopFinal { stream: proof },
            None => CompletedZiskProof::Plonk {
                proof,
                public_values,
            },
        };
        {
            let mut state = self.state.lock().await;
            state.completed.insert(batch_number, completed);
            Self::record_queue_gauges(&state);
        }

        ZISK_LANE_METRICS
            .time_to_submit
            .observe(job_data.added_at.elapsed());
        Ok(())
    }

    /// Take the validated proof for a batch, if one is parked. Called by the
    /// Airbender SNARK submission path to compose the MultiProof (per-batch
    /// PLONK mode only; aggregated mode composes at range level via the
    /// aggregation manager).
    pub async fn take_completed(&self, batch_number: u64) -> Option<CompletedZiskProof> {
        let mut state = self.state.lock().await;
        let proof = state.completed.remove(&batch_number);
        if proof.is_some() {
            Self::record_queue_gauges(&state);
        }
        proof
    }

    /// Drop parked proofs for batches at or below `batch_to`. Called when a
    /// batch is consumed downstream (composed multi-proof, optional mode, or
    /// degraded after the wait timeout): batches are processed in order, so
    /// a proof for an already-sent batch can never be composed. In-flight
    /// jobs are deliberately left alone — their submit-time validation still
    /// provides the shadow-mode divergence signal.
    pub async fn discard_completed_up_to(&self, batch_to: u64) {
        // Batches sent downstream can never join an aggregation range
        // either — drop the buffered inputs and any range they overlapped.
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
            "discarded parked ZiSK proofs for batches already sent downstream"
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
    use crate::prover_api::zisk_vadcop_stream::test_stream::synthetic_stream;
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
        ZiskJobManager::new(
            Duration::from_secs(60),
            expected_vk,
            TEST_CHAIN_ID,
            TEST_CHAIN_CONFIG,
        )
    }

    fn expected_commitment(data: &ZiskJobData) -> B256 {
        let stored = data.batch_metadata.batch_info.clone().into_stored();
        let prev = &data.batch_metadata.previous_stored_batch_info;
        crate::prover_api::zisk_proof_verifier::expected_zisk_public_input(
            &prev.state_commitment,
            &stored,
            TEST_CHAIN_ID,
            TEST_CHAIN_CONFIG,
        )
    }

    /// Public values whose commitment word matches the job's batch metadata
    /// (computed with the shared expected-PI helper, i.e. the guest lib's own
    /// hash functions), so `submit_proof` gets past commitment verification.
    fn matching_public_values(data: &ZiskJobData) -> Vec<u8> {
        let commitment = expected_commitment(data);
        let mut public_values = vec![0u8; ZISK_PUBLIC_VALUES_BYTES];
        public_values[32..64].copy_from_slice(commitment.as_slice());
        public_values
    }

    /// A `vadcop_final` stream whose commitment matches the job's batch
    /// metadata, for aggregated-mode submissions.
    fn matching_vadcop_stream(data: &ZiskJobData) -> Vec<u8> {
        synthetic_stream([1, 2, 3, 4], [5, 6, 7, 8], expected_commitment(data).0)
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

        let picked = manager
            .pick_next_job("prover-1")
            .await
            .expect("job available");
        assert_eq!(picked.batch_number, 7);
        assert_eq!(picked.zisk_data, zisk_data);
        assert_eq!(manager.batch_status(7).await, ZiskBatchStatus::InFlight);

        manager
            .submit_proof(
                7,
                vec![0; ZISK_SNARK_PROOF_BYTES],
                public_values.clone(),
                "prover-1",
            )
            .await
            .expect("valid submission accepted");
        assert_eq!(manager.batch_status(7).await, ZiskBatchStatus::Completed);

        let completed = manager.take_completed(7).await.expect("proof parked");
        match completed {
            CompletedZiskProof::Plonk {
                public_values: pv, ..
            } => {
                assert_eq!(pv, public_values)
            }
            CompletedZiskProof::VadcopFinal { .. } => panic!("PLONK mode parks Plonk payloads"),
        }
        assert!(
            manager.take_completed(7).await.is_none(),
            "taken exactly once"
        );
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
        manager
            .add_job(7, data)
            .await
            .unwrap_or_else(|_| panic!("add rejected"));
        // Pending: re-add is a no-op.
        manager
            .add_job(7, job_data(7, vec![0xCD; 8]))
            .await
            .unwrap_or_else(|_| panic!("idempotent re-add"));
        let picked = manager
            .pick_next_job("prover-1")
            .await
            .expect("job available");
        assert_eq!(picked.zisk_data, vec![0xAB; 32], "original data kept");
        // Assigned: re-add is a no-op (no second pickable job appears).
        manager
            .add_job(7, job_data(7, vec![0xCD; 8]))
            .await
            .unwrap_or_else(|_| panic!("idempotent re-add"));
        assert!(manager.pick_next_job("prover-2").await.is_none());
        // Completed: re-add is a no-op (the parked proof is not clobbered).
        manager
            .submit_proof(
                7,
                vec![0; ZISK_SNARK_PROOF_BYTES],
                public_values,
                "prover-1",
            )
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
        manager
            .add_job(7, job_data(7, vec![1; 8]))
            .await
            .unwrap_or_else(|_| panic!());
        manager.add_job(8, data8).await.unwrap_or_else(|_| panic!());
        manager
            .add_job(9, job_data(9, vec![3; 8]))
            .await
            .unwrap_or_else(|_| panic!());
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
        manager
            .pick_next_job("prover-1")
            .await
            .expect("job available");

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

    /// Aggregated mode: an accepted `vadcop_final` stream is buffered in
    /// the aggregation manager as range input AND parked here as a
    /// mode-tagged completion marker; the aggregation job carries the
    /// stream once its SNARK range is noted.
    #[tokio::test]
    async fn aggregated_mode_accepts_stream_and_feeds_sink() {
        use crate::prover_api::zisk_aggregation_job_manager::ZiskAggregationJobManager;

        let manager = manager(None);
        let agg = std::sync::Arc::new(ZiskAggregationJobManager::new(
            1,
            Duration::from_secs(60),
            None,
        ));
        manager.set_aggregation_sink(agg.clone());

        let data = job_data(7, vec![0xAB; 32]);
        let stream = matching_vadcop_stream(&data);
        manager
            .add_job(7, data)
            .await
            .unwrap_or_else(|_| panic!("add rejected"));
        manager
            .pick_next_job("prover-1")
            .await
            .expect("job available");
        manager
            .submit_proof(7, stream.clone(), vec![], "prover-1")
            .await
            .expect("accepted");

        assert_eq!(manager.batch_status(7).await, ZiskBatchStatus::Completed);
        assert!(agg.has_input(7).await, "stream buffered as range input");

        agg.note_snark_range(7, 7).await;
        let job = agg
            .pick_next_job("agg-1")
            .await
            .expect("aggregation job formed");
        assert_eq!((job.from_batch, job.to_batch), (7, 7));
        assert_eq!(job.streams[0].1, stream);

        // The parked marker is mode-tagged with the stream.
        match manager.take_completed(7).await.expect("parked") {
            CompletedZiskProof::VadcopFinal { stream: parked } => assert_eq!(parked, stream),
            CompletedZiskProof::Plonk { .. } => panic!("aggregated mode parks VadcopFinal"),
        }
    }

    /// Aggregated mode rejects PLONK-shaped submissions (and vice versa)
    /// with a size error, and rejects malformed streams before touching
    /// the job.
    #[tokio::test]
    async fn aggregated_mode_rejects_wrong_shapes() {
        use crate::prover_api::zisk_aggregation_job_manager::ZiskAggregationJobManager;

        let manager = manager(None);
        let agg = std::sync::Arc::new(ZiskAggregationJobManager::new(
            1,
            Duration::from_secs(60),
            None,
        ));
        manager.set_aggregation_sink(agg.clone());

        let data = job_data(7, vec![0xAB; 32]);
        let stream = matching_vadcop_stream(&data);
        manager
            .add_job(7, data)
            .await
            .unwrap_or_else(|_| panic!("add rejected"));
        manager
            .pick_next_job("prover-1")
            .await
            .expect("job available");

        // A 768-byte PLONK proof is a mode mismatch.
        let err = manager
            .submit_proof(7, vec![0; ZISK_SNARK_PROOF_BYTES], vec![], "prover-1")
            .await
            .expect_err("plonk-sized proof rejected in aggregated mode");
        assert!(
            matches!(err, ZiskSubmitError::InvalidProofSize { .. }),
            "{err}"
        );
        assert!(err.to_string().contains("--aggregation"), "{err}");

        // Non-empty public values are a protocol error in aggregated mode.
        let err = manager
            .submit_proof(
                7,
                stream.clone(),
                vec![0; ZISK_PUBLIC_VALUES_BYTES],
                "prover-1",
            )
            .await
            .expect_err("non-empty publics rejected");
        assert!(matches!(
            err,
            ZiskSubmitError::InvalidPublicValuesSize { .. }
        ));

        // A right-sized but malformed stream (minimal flag) is rejected.
        let mut minimal = stream.clone();
        minimal[0] = 1;
        let err = manager
            .submit_proof(7, minimal, vec![], "prover-1")
            .await
            .expect_err("malformed stream rejected");
        assert!(matches!(err, ZiskSubmitError::MalformedProof(_)), "{err}");

        // The job survived all rejections: a valid submission still lands.
        manager
            .submit_proof(7, stream, vec![], "prover-1")
            .await
            .expect("valid stream accepted");
    }

    /// Discards forward to the aggregation sink so its buffered inputs and
    /// tracked ranges are dropped alongside the per-batch state.
    #[tokio::test]
    async fn discards_forward_to_aggregation_sink() {
        use crate::prover_api::zisk_aggregation_job_manager::ZiskAggregationJobManager;

        let manager = manager(None);
        let agg = std::sync::Arc::new(ZiskAggregationJobManager::new(
            1,
            Duration::from_secs(60),
            None,
        ));
        manager.set_aggregation_sink(agg.clone());

        let data = job_data(7, vec![0xAB; 32]);
        let stream = matching_vadcop_stream(&data);
        manager
            .add_job(7, data)
            .await
            .unwrap_or_else(|_| panic!("add rejected"));
        manager
            .pick_next_job("prover-1")
            .await
            .expect("job available");
        manager
            .submit_proof(7, stream, vec![], "prover-1")
            .await
            .expect("accepted");
        agg.note_snark_range(7, 7).await;

        manager.discard_batches(7, 7).await;
        assert!(
            agg.pick_next_job("agg-1").await.is_none(),
            "discarded batch must not form an aggregation range"
        );
        assert!(!agg.has_input(7).await);
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
        manager
            .pick_next_job("prover-1")
            .await
            .expect("job available");

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
            .submit_proof(
                7,
                vec![0; ZISK_SNARK_PROOF_BYTES],
                public_values,
                "prover-1",
            )
            .await
            .expect("corrected submission succeeds");
        assert_eq!(
            manager.batch_status(7).await,
            ZiskBatchStatus::Completed,
            "proof parked for multi-proof composition"
        );
    }
}
