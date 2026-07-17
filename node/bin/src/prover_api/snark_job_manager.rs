use crate::prover_api::fri_job_manager::FriJob;
use crate::prover_api::metrics::{ProverStage, ProverType, ZISK_LANE_METRICS};
use crate::prover_api::prover_job_map::ProverJobMap;
use crate::prover_api::zisk_aggregation_job_manager::{
    ZiskAggregationJobManager, ZiskAggregationRangeStatus,
};
use crate::prover_api::zisk_data_cache::ZiskDataCache;
use crate::prover_api::zisk_job_manager::{
    CompletedZiskProof, ZiskBatchStatus, ZiskJobData, ZiskJobManager,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Permit;
use tokio::sync::mpsc::error::TrySendError;
use zksync_os_batch_types::batcher_model::{
    FriProof, MultiProofSnarkProof, RealSnarkProof, SignedBatchEnvelope, SnarkProof,
};
use zksync_os_batcher_metrics::BatchExecutionStage;
use zksync_os_l1_sender::commands::prove::ProofCommand;
use zksync_os_types::ProvingVersion;

/// Job manager for SNARK proving.
///
/// Supports multiple SNARK provers
///
/// Supports both real and fake proofs.
///  - Fake FRI proofs always result in fake SNARK proofs.
///  - Real FRI proofs may result in real or fake SNARK proofs depending on prover availability
///
/// `SnarkJobManager` aims to assign real prover jobs to real SNARK provers -
///     but if jobs are not picked within a timeout (`max_batch_age`), it releases it to a fake prover
///
/// The Airbender SNARK submission is the multi-proof rendezvous point: ZiSK
/// proving starts at batch seal (`FriJobManager::add_job` creates the ZiSK
/// job), and when the Airbender SNARK arrives here the completed ZiSK proof
/// — if it has already landed — is taken and composed into a MultiProof on
/// the spot. In per-batch PLONK mode (single-batch SNARK ranges) the proof
/// comes from `ZiskJobManager`; in aggregated mode the Airbender SNARK
/// covers a batch RANGE and pairs with the aggregated range proof from
/// `ZiskAggregationJobManager` — the range identity is the SNARK job's
/// range, which this manager reports to the aggregation manager at pick
/// time (early start) and at submission (authoritative). Under
/// `require_multi_proof` a missing ZiSK proof blocks the submission (job
/// re-offered) for only the residual proving time; otherwise the
/// Airbender-only proof is sent downstream immediately.
pub struct SnarkJobManager {
    jobs: ProverJobMap<FriProof>,
    // outbound
    prove_batches_sender: mpsc::Sender<ProofCommand>,
    // config
    max_fris_per_snark: usize,
    zisk_data_cache: Option<Arc<ZiskDataCache>>,
    zisk_job_manager: Option<Arc<ZiskJobManager>>,
    /// When set, the ZiSK lane runs in AGGREGATED mode: the rendezvous
    /// pairs the Airbender range SNARK with one aggregated ZiSK range
    /// proof instead of a per-batch PLONK proof.
    zisk_aggregation_job_manager: Option<Arc<ZiskAggregationJobManager>>,
    /// When true, refuse to send Airbender-only proofs if ZiSK data was expected.
    /// Prevents silent fallback to single-proof mode when ZiSK provers are offline.
    require_multi_proof: bool,
    /// How long a batch may block on its ZiSK proof path before an
    /// Airbender-only submission is allowed despite `require_multi_proof`.
    /// `None`: block indefinitely (the operator escape hatch is flipping the
    /// config — no deploy needed). Measured from when the batch entered SNARK
    /// proving.
    multi_proof_wait_timeout: Option<Duration>,
}

impl SnarkJobManager {
    pub fn new(
        prove_batches_sender: mpsc::Sender<ProofCommand>,
        max_fris_per_snark: usize,
        assignment_timeout: Duration,
        max_assigned_batch_range: usize,
    ) -> Self {
        let jobs = ProverJobMap::<FriProof>::new(
            assignment_timeout,
            max_assigned_batch_range,
            ProverStage::Snark,
        );
        Self {
            jobs,
            prove_batches_sender,
            max_fris_per_snark,
            zisk_data_cache: None,
            zisk_job_manager: None,
            zisk_aggregation_job_manager: None,
            require_multi_proof: false,
            multi_proof_wait_timeout: None,
        }
    }

    /// See [`Self::multi_proof_wait_timeout`].
    pub fn set_multi_proof_wait_timeout(&mut self, timeout: Option<Duration>) {
        self.multi_proof_wait_timeout = timeout;
    }

    /// Set the ZiSK data cache for multi-proof composition.
    pub fn set_zisk_data_cache(&mut self, cache: Arc<ZiskDataCache>) {
        self.zisk_data_cache = Some(cache);
    }

    /// When true, batches with ZiSK data will NOT fall back to Airbender-only.
    /// They will be held until the ZiSK prover processes them.
    pub fn set_require_multi_proof(&mut self, require: bool) {
        self.require_multi_proof = require;
    }

    /// Set the ZiSK job manager for routing Airbender SNARKs to multi-proof composition.
    pub fn set_zisk_job_manager(&mut self, zjm: Arc<ZiskJobManager>) {
        self.zisk_job_manager = Some(zjm);
    }

    /// Switch the rendezvous to aggregated mode (see the struct docs).
    pub fn set_zisk_aggregation_job_manager(&mut self, ajm: Arc<ZiskAggregationJobManager>) {
        self.zisk_aggregation_job_manager = Some(ajm);
    }

    pub async fn add_job(&self, batch_envelope: SignedBatchEnvelope<FriProof>) {
        self.jobs.add_job(batch_envelope).await
    }

    pub async fn pick_real_job(
        &self,
        prover_id: String,
    ) -> anyhow::Result<Option<Vec<(FriJob, FriProof)>>> {
        self.process_pending_fake_fri_proofs().await?;

        // Aggregated mode: the assigned range doubles as the ZiSK
        // aggregation range, so hand out full `max_fris_per_snark` groups
        // only — a partial pick while later FRIs are still proving would
        // fragment the fixed-size ranges the range verifier expects.
        let min_group = if self.zisk_aggregation_job_manager.is_some() {
            self.max_fris_per_snark
        } else {
            1
        };
        let batches_with_real_proofs = self
            .jobs
            .pick_jobs_group_with_limit(self.max_fris_per_snark, min_group, &prover_id, |job| {
                !job.batch_envelope.data.is_fake()
            })
            .await;

        if batches_with_real_proofs.is_empty() {
            tracing::trace!(prover_id, "no SNARK prove jobs are available for pick up");
            return Ok(None);
        }

        // Aggregated mode: the assigned range IS the ZiSK aggregation
        // range. Register it now so the aggregation proof is computed
        // while the Airbender SNARK is still being proven; the submission
        // re-registers authoritatively (a timed-out range may be re-picked
        // with different bounds).
        if let (Some(ajm), Some((first, _)), Some((last, _))) = (
            self.zisk_aggregation_job_manager.as_ref(),
            batches_with_real_proofs.first(),
            batches_with_real_proofs.last(),
        ) {
            ajm.note_snark_range(first.batch_number, last.batch_number)
                .await;
        }

        Ok(Some(batches_with_real_proofs))
    }

    /// Submit a real Airbender SNARK proof.
    ///
    /// For multi-batch ranges, checks ALL batches in the range for ZiSK data.
    /// If ZiSK data exists for the first batch (single-batch ZiSK proving),
    /// the Airbender SNARK is routed to ZiskJobManager. Multi-batch ranges
    /// with ZiSK data are only supported when batch_from == batch_to.
    pub async fn submit_proof(
        &self,
        batch_from: u64,
        batch_to: u64,
        proving_version: ProvingVersion,
        payload: Vec<u8>,
        prover_id: String,
    ) -> anyhow::Result<()> {
        // note: we still hold mutex while verifying the proof -
        // this is desired since we don't want the batches to timeout

        // todo: verify_snark_proof()
        // if false {
        //     anyhow::bail!("proof validation failed")
        // }

        // Prover should generate the proof with VK received from server. These must always match.
        // If they don't, proof won't be accepted, validation will fail, therefore it's pointless to proceed.
        //
        // This should never happen, but we double-check to guarantee it's the case.
        let Some(batch_metadata) = self.jobs.get_job_batch_metadata(batch_from).await else {
            anyhow::bail!("race condition: some batches were completed earlier")
        };
        let server_vk = batch_metadata
            .verification_key_hash()
            .expect("verification key hash must be present as it was set by server");
        let prover_vk = proving_version.vk_hash();
        anyhow::ensure!(
            server_vk == prover_vk,
            "Verification key hash mismatch: server got {server_vk}, prover got {prover_vk}"
        );

        // Aggregated mode: the Airbender SNARK covers a batch range and
        // pairs with ONE aggregated ZiSK range proof of the same bounds.
        if self.zisk_aggregation_job_manager.is_some() {
            return self
                .submit_proof_aggregated(batch_from, batch_to, proving_version, payload, prover_id)
                .await;
        }

        // Per-batch PLONK mode: ZiSK multi-proof applies to single-batch
        // ranges only (enforced at startup via `max_fris_per_snark = 1`
        // when the second proof system is on without aggregation; the
        // branch below is defensive).
        let zisk_lane = match self.zisk_job_manager.as_ref() {
            Some(zjm) if batch_from == batch_to => Some(zjm),
            Some(_) => {
                // Multi-batch range: ZiSK proving not supported, send Airbender-only.
                // Log a warning so operators know multi-proof is skipped.
                tracing::warn!(
                    batch_from,
                    batch_to,
                    "multi-batch SNARK range — ZiSK proving skipped (aggregation not enabled)"
                );
                None
            }
            None => None,
        };
        // Multi-proof policy is decided BEFORE any job is consumed, so a
        // blocked submission leaves the SNARK job in place: the assignment
        // times out and the batch is re-offered until its ZiSK proof lands
        // (block-until-proof). ZiSK proving starts at batch seal, so this
        // wait covers only the residual proving time — not a full serial
        // run behind the Airbender lane. After `multi_proof_wait_timeout`
        // (when set), the batch is allowed through Airbender-only with a
        // loud signal.
        let multi_proof_expected = self.require_multi_proof && zisk_lane.is_some();
        let wait_expired = || async {
            match self.multi_proof_wait_timeout {
                None => false,
                Some(timeout) => self
                    .jobs
                    .get_job_age(batch_from)
                    .await
                    .is_some_and(|age| age >= timeout),
            }
        };
        if let Some(zjm) = zisk_lane
            && multi_proof_expected
        {
            let blocked_reason = match zjm.batch_status(batch_from).await {
                ZiskBatchStatus::Completed => None,
                ZiskBatchStatus::InFlight => {
                    Some("ZiSK proof not yet submitted (job pending or assigned)")
                }
                ZiskBatchStatus::Unknown => {
                    // Seal-time job creation was skipped (queue was full) or
                    // lost (restart) — re-create the job from the cached
                    // input so a prover can pick it up.
                    if !zjm.has_capacity().await {
                        Some("ZiSK job queue is full (provers offline or behind)")
                    } else {
                        let cache = self
                            .zisk_data_cache
                            .as_ref()
                            .expect("ZiSK job manager implies a data cache");
                        match cache.remove(batch_from).await {
                            Some(zisk_data) => {
                                tracing::warn!(
                                    batch = batch_from,
                                    "ZiSK job missing at SNARK arrival — re-created from cached input"
                                );
                                if let Err(rejected) = zjm
                                    .add_job(
                                        batch_from,
                                        ZiskJobData {
                                            zisk_data,
                                            batch_metadata: batch_metadata.clone(),
                                            added_at: std::time::Instant::now(),
                                        },
                                    )
                                    .await
                                {
                                    // Raced to full — put the input back for
                                    // the next re-offer of this batch.
                                    cache.insert(batch_from, rejected.zisk_data).await;
                                }
                                Some(
                                    "ZiSK job re-created from cached input — waiting for the proof",
                                )
                            }
                            None => Some(
                                "no ZiSK input available for the batch (evicted or not regenerated)",
                            ),
                        }
                    }
                }
            };
            if let Some(reason) = blocked_reason {
                if wait_expired().await {
                    ZISK_LANE_METRICS.degraded_to_single_proof.inc();
                    tracing::error!(
                        batch = batch_from,
                        reason,
                        "multi-proof wait timeout expired — accepting Airbender-only \
                         submission for a batch that required both proofs"
                    );
                    // fall through: consume and send Airbender-only below
                } else {
                    ZISK_LANE_METRICS.blocked_submits.inc();
                    tracing::warn!(
                        batch = batch_from,
                        reason,
                        "multi-proof required — rejecting Airbender-only submission; \
                         the job stays queued and will be re-offered"
                    );
                    anyhow::bail!(
                        "multi_proof_verifier requires a ZiSK proof for batch {batch_from} \
                         but {reason}; the Airbender submission is rejected and the job \
                         will be re-offered (waiting{})",
                        match self.multi_proof_wait_timeout {
                            Some(t) => format!(" up to {t:?}"),
                            None => " indefinitely — flip multi_proof_wait_timeout to cap".into(),
                        }
                    );
                }
            }
        }

        // Ensure we can send downstream before consuming jobs from the retryable map.
        // On the ZiSK route the permit backs the Airbender-only fallbacks.
        let permit = self.try_reserve_permit_downstream()?;

        // prove is valid - consuming proven batches
        let Some(consumed_batches_proven) = self
            .jobs
            .complete_many_jobs(batch_from, batch_to, ProverType::Real, &prover_id)
            .await
        else {
            anyhow::bail!("race condition: some batches were completed earlier")
        };

        let consumed_batches_proven: Vec<_> = consumed_batches_proven
            .into_iter()
            .map(|b| b.with_stage(BatchExecutionStage::SnarkProvedReal))
            .collect();

        // Multi-proof rendezvous: the batch's ZiSK proof has been in flight
        // since batch seal — if it already landed and multi-proof is
        // REQUIRED, compose the MultiProof now. In optional (shadow) mode
        // the MultiProof must never reach L1 (`prove.rs` always encodes it
        // as a type-5 payload, which needs the MultiProofVerifier deployed):
        // the ZiSK proof's submit-time commitment validation is the shadow
        // signal, and the batch goes downstream Airbender-only.
        if let Some(zjm) = zisk_lane {
            if self.require_multi_proof
                && let Some(completed) = zjm.take_completed(batch_from).await
            {
                match completed {
                    CompletedZiskProof::Plonk {
                        proof: zisk_proof,
                        public_values: zisk_public_values,
                    } => {
                        if let Some(cache) = self.zisk_data_cache.as_ref() {
                            cache.remove(batch_from).await;
                        }
                        tracing::info!(
                            batch = batch_from,
                            era_proof_bytes = payload.len(),
                            zisk_proof_bytes = zisk_proof.len(),
                            "Airbender SNARK received, composing Airbender + ZiSK multi-proof"
                        );
                        permit.send(ProofCommand::new(
                            consumed_batches_proven,
                            SnarkProof::MultiProof(MultiProofSnarkProof {
                                era_proof: payload,
                                zisk_proof,
                                zisk_public_values,
                                proving_execution_version: proving_version as u32,
                            }),
                        ));
                        return Ok(());
                    }
                    // Per-batch mode always parks PLONK payloads; a vadcop
                    // stream here means the lane modes disagree. The stream
                    // cannot compose — send Airbender-only below rather
                    // than dropping the already-consumed batches.
                    CompletedZiskProof::VadcopFinal { .. } => {
                        tracing::error!(
                            batch = batch_from,
                            "parked ZiSK proof is a vadcop_final stream but aggregation \
                             is not enabled — inconsistent ZiSK lane configuration; \
                             sending Airbender-only"
                        );
                    }
                }
            }
            // The batch goes downstream without a ZiSK proof — a parked
            // proof at or below this batch can never be composed (batches
            // are processed in order; in optional mode composition is off
            // entirely), so drop parked proofs up to here. In-flight jobs
            // are left alone: their submit-time validation is still the
            // shadow-mode divergence signal.
            zjm.discard_completed_up_to(batch_to).await;
        }
        self.send_airbender_only(permit, consumed_batches_proven, payload, proving_version)
    }

    /// Aggregated-mode submission: the Airbender range SNARK pairs with the
    /// aggregated ZiSK proof of exactly `[batch_from..batch_to]`.
    ///
    /// The submitted range is the authoritative range identity: it is
    /// registered with the aggregation manager (idempotent — normally the
    /// pick already did), and under `require_multi_proof` the submission
    /// blocks (job re-offered) until the aggregated proof for that exact
    /// range is parked, mirroring the per-batch block-until-proof flow.
    async fn submit_proof_aggregated(
        &self,
        batch_from: u64,
        batch_to: u64,
        proving_version: ProvingVersion,
        payload: Vec<u8>,
        prover_id: String,
    ) -> anyhow::Result<()> {
        let ajm = self
            .zisk_aggregation_job_manager
            .as_ref()
            .expect("aggregated submission implies an aggregation manager");
        ajm.note_snark_range(batch_from, batch_to).await;

        if self.require_multi_proof {
            let blocked_reason = match ajm.range_status(batch_from, batch_to).await {
                ZiskAggregationRangeStatus::Completed => None,
                ZiskAggregationRangeStatus::InFlight => {
                    // Per-batch jobs may have been skipped (queue full) or
                    // lost (restart) — re-create them from the cached
                    // inputs so their streams can still arrive.
                    self.recreate_missing_zisk_jobs(batch_from, batch_to).await;
                    Some("the aggregated ZiSK proof for the range has not been submitted yet")
                }
                // note_snark_range above tracks every range whose batches
                // are still in the job map, so this cannot happen.
                ZiskAggregationRangeStatus::Unknown => {
                    Some("the range is not tracked by the aggregation stage")
                }
            };
            if let Some(reason) = blocked_reason {
                let wait_expired = match self.multi_proof_wait_timeout {
                    None => false,
                    Some(timeout) => self
                        .jobs
                        .get_job_age(batch_from)
                        .await
                        .is_some_and(|age| age >= timeout),
                };
                if wait_expired {
                    ZISK_LANE_METRICS.degraded_to_single_proof.inc();
                    tracing::error!(
                        batch_from,
                        batch_to,
                        reason,
                        "multi-proof wait timeout expired — accepting Airbender-only \
                         submission for a range that required both proofs"
                    );
                    // fall through: consume and send Airbender-only below
                } else {
                    ZISK_LANE_METRICS.blocked_submits.inc();
                    tracing::warn!(
                        batch_from,
                        batch_to,
                        reason,
                        "multi-proof required — rejecting Airbender-only submission; \
                         the job stays queued and will be re-offered"
                    );
                    anyhow::bail!(
                        "multi_proof_verifier requires an aggregated ZiSK proof for batches \
                         {batch_from}..{batch_to} but {reason}; the Airbender submission is \
                         rejected and the job will be re-offered (waiting{})",
                        match self.multi_proof_wait_timeout {
                            Some(t) => format!(" up to {t:?}"),
                            None => " indefinitely — flip multi_proof_wait_timeout to cap".into(),
                        }
                    );
                }
            }
        }

        // Ensure we can send downstream before consuming jobs from the
        // retryable map.
        let permit = self.try_reserve_permit_downstream()?;

        let Some(consumed_batches_proven) = self
            .jobs
            .complete_many_jobs(batch_from, batch_to, ProverType::Real, &prover_id)
            .await
        else {
            anyhow::bail!("race condition: some batches were completed earlier")
        };
        let consumed_batches_proven: Vec<_> = consumed_batches_proven
            .into_iter()
            .map(|b| b.with_stage(BatchExecutionStage::SnarkProvedReal))
            .collect();

        // The rendezvous. In optional (shadow) mode the MultiProof must
        // never reach L1 (`prove.rs` always encodes it as a type-5 payload,
        // which needs the MultiProofVerifier deployed): the aggregated
        // proof's submit-time digest validation is the shadow signal, and
        // the batches go downstream Airbender-only.
        if self.require_multi_proof
            && let Some(aggregated) = ajm.take_completed(batch_from, batch_to).await
        {
            if let Some(cache) = self.zisk_data_cache.as_ref() {
                for batch in batch_from..=batch_to {
                    cache.remove(batch).await;
                }
            }
            tracing::info!(
                batch_from,
                batch_to,
                era_proof_bytes = payload.len(),
                zisk_proof_bytes = aggregated.proof.len(),
                "Airbender range SNARK received, composing Airbender + aggregated ZiSK multi-proof"
            );
            permit.send(ProofCommand::new(
                consumed_batches_proven,
                SnarkProof::MultiProof(MultiProofSnarkProof {
                    era_proof: payload,
                    zisk_proof: aggregated.proof,
                    zisk_public_values: aggregated.public_values,
                    proving_execution_version: proving_version as u32,
                }),
            ));
            // Sweep the consumed batches' per-batch completion markers
            // (and, via the sink forward, any leftover aggregation state).
            if let Some(zjm) = self.zisk_job_manager.as_ref() {
                zjm.discard_completed_up_to(batch_to).await;
            }
            return Ok(());
        }

        // Airbender-only: the consumed batches can never rendezvous
        // anymore — sweep their ZiSK lane state.
        if let Some(zjm) = self.zisk_job_manager.as_ref() {
            zjm.discard_completed_up_to(batch_to).await;
        }
        self.send_airbender_only(permit, consumed_batches_proven, payload, proving_version)
    }

    /// Re-create per-batch ZiSK jobs for batches of a blocked aggregated
    /// range whose input has not arrived and whose job vanished (seal-time
    /// creation skipped on a full queue, or lost on restart), from the
    /// cached inputs. Mirrors the per-batch SNARK-arrival fallback.
    async fn recreate_missing_zisk_jobs(&self, batch_from: u64, batch_to: u64) {
        let Some(zjm) = self.zisk_job_manager.as_ref() else {
            return;
        };
        let Some(ajm) = self.zisk_aggregation_job_manager.as_ref() else {
            return;
        };
        let Some(cache) = self.zisk_data_cache.as_ref() else {
            return;
        };
        for batch in batch_from..=batch_to {
            if ajm.has_input(batch).await
                || zjm.batch_status(batch).await != ZiskBatchStatus::Unknown
            {
                continue;
            }
            if !zjm.has_capacity().await {
                tracing::warn!(
                    batch,
                    "ZiSK job queue is full — cannot re-create the missing job yet"
                );
                return;
            }
            let Some(batch_metadata) = self.jobs.get_job_batch_metadata(batch).await else {
                continue;
            };
            match cache.remove(batch).await {
                Some(zisk_data) => {
                    tracing::warn!(
                        batch,
                        "ZiSK job missing at SNARK arrival — re-created from cached input"
                    );
                    if let Err(rejected) = zjm
                        .add_job(
                            batch,
                            ZiskJobData {
                                zisk_data,
                                batch_metadata,
                                added_at: std::time::Instant::now(),
                            },
                        )
                        .await
                    {
                        // Raced to full — put the input back for the next
                        // re-offer of this range.
                        cache.insert(batch, rejected.zisk_data).await;
                    }
                }
                None => {
                    tracing::warn!(
                        batch,
                        "no ZiSK input available for the batch (evicted or not regenerated)"
                    );
                }
            }
        }
    }

    /// Send an Airbender-only SNARK proof downstream via a reserved permit.
    /// The multi-proof gate lives in `submit_proof` BEFORE job consumption;
    /// by the time this runs the submission has already been allowed through.
    fn send_airbender_only(
        &self,
        permit: Permit<'_, ProofCommand>,
        batches: Vec<SignedBatchEnvelope<FriProof>>,
        payload: Vec<u8>,
        proving_version: ProvingVersion,
    ) -> anyhow::Result<()> {
        permit.send(ProofCommand::new(
            batches,
            SnarkProof::Real(RealSnarkProof::V2 {
                proof: payload,
                proving_execution_version: proving_version as u32,
            }),
        ));
        Ok(())
    }

    async fn process_pending_fake_fri_proofs(&self) -> anyhow::Result<()> {
        self.process_pending_fake_or_timed_out_fri_proofs(None)
            .await
    }

    async fn process_pending_fake_or_timed_out_fri_proofs(
        &self,
        timeout_for_real_fris: Option<Duration>,
    ) -> anyhow::Result<()> {
        loop {
            // Reserve downstream capacity BEFORE picking: bailing on
            // backpressure after the pick leaves the picked jobs assigned to
            // "fake_prover" until the assignment timeout, stalling the whole
            // prove pipeline for that window. An unused permit is just
            // dropped.
            let permit = self.try_reserve_permit_downstream()?;

            let assigned: Vec<(FriJob, FriProof)> = self
                .jobs
                .pick_jobs_while_with_limit(self.max_fris_per_snark, "fake_prover", |job| {
                    job.batch_envelope.data.is_fake()
                        || timeout_for_real_fris
                            .is_some_and(|t| job.metadata.added_at.elapsed() >= t)
                })
                .await;

            if assigned.is_empty() {
                return Ok(());
            }

            let real_proofs_count = assigned
                .iter()
                .filter(|(_, proof)| !proof.is_fake())
                .count();
            if let (Some(first), Some(last)) = (assigned.first(), assigned.last()) {
                tracing::info!(
                    from_batch = first.0.batch_number,
                    to_batch = last.0.batch_number,
                    real_proofs_count,
                    fake_proofs_count = assigned.len() - real_proofs_count,
                    "consuming proofs for fake SNARKing"
                );
            }

            let batch_from = assigned.first().unwrap().0.batch_number;
            let batch_to = assigned.last().unwrap().0.batch_number;
            let Some(completed) = self
                .jobs
                .complete_many_jobs(batch_from, batch_to, ProverType::Fake, "fake_prover")
                .await
            else {
                tracing::info!(
                    batch_from,
                    batch_to,
                    "skipping fake SNARK proof because another prover completed part of the range"
                );
                continue;
            };

            let batches_with_fake_proofs = completed
                .into_iter()
                .map(|batch| batch.with_stage(BatchExecutionStage::SnarkProvedFake))
                .collect();

            // Fake SNARKs can never be composed into a MultiProof — drop the
            // batches' ZiSK lane state (jobs created at seal, parked proofs)
            // so fake-prover environments don't accumulate orphans.
            if let Some(zjm) = self.zisk_job_manager.as_ref() {
                zjm.discard_batches(batch_from, batch_to).await;
            }

            permit.send(ProofCommand::new(
                batches_with_fake_proofs,
                SnarkProof::Fake,
            ));
        }
    }

    fn try_reserve_permit_downstream(&self) -> anyhow::Result<Permit<'_, ProofCommand>> {
        Ok(match self.prove_batches_sender.try_reserve() {
            Ok(permit) => permit,
            Err(TrySendError::Full(_)) => {
                anyhow::bail!("downstream backpressure");
            }
            Err(TrySendError::Closed(_)) => {
                anyhow::bail!("server is shutting down");
            }
        })
    }
}

const POLL_INTERVAL_MS: u64 = 1000;

pub struct FakeSnarkProver {
    job_manager: Arc<SnarkJobManager>,
    max_batch_age: Duration,
    polling_interval: Duration,
}

impl FakeSnarkProver {
    pub fn new(job_manager: Arc<SnarkJobManager>, max_batch_age: Duration) -> Self {
        Self {
            job_manager,
            max_batch_age,
            polling_interval: Duration::from_millis(POLL_INTERVAL_MS),
        }
    }

    pub async fn run(self) {
        loop {
            tokio::time::sleep(self.polling_interval).await;
            if let Err(err) = self
                .job_manager
                .process_pending_fake_or_timed_out_fri_proofs(Some(self.max_batch_age))
                .await
            {
                tracing::info!("`FakeSnarkProver` iteration failed: {err}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batcher::batch_builder::ZiskChainConfig;
    use crate::prover_api::test_util::create_test_batch_envelope;
    use crate::prover_api::zisk_proof_constants::{
        ZISK_PUBLIC_VALUES_BYTES, ZISK_SNARK_PROOF_BYTES,
    };
    use zksync_os_types::ProtocolSemanticVersion;

    const TEST_CHAIN_ID: u64 = 270;
    const TEST_CHAIN_CONFIG: ZiskChainConfig = ZiskChainConfig {
        fri_proof_verification_enabled: false,
        max_tx_gas_limit: 1 << 24,
    };

    fn envelope(batch: u64) -> SignedBatchEnvelope<FriProof> {
        let mut e = create_test_batch_envelope(batch, FriProof::Fake);
        e.batch.batch_info.protocol_version = ProtocolSemanticVersion::new(0, 31, 0);
        e
    }

    async fn manager_with_job(
        require: bool,
        wait_timeout: Option<Duration>,
    ) -> (
        SnarkJobManager,
        Arc<ZiskJobManager>,
        mpsc::Receiver<ProofCommand>,
        ProvingVersion,
    ) {
        let (tx, rx) = mpsc::channel(4);
        let mut sjm = SnarkJobManager::new(tx, 1, Duration::from_secs(60), 10);
        let zjm = Arc::new(ZiskJobManager::new(
            Duration::from_secs(60),
            None,
            TEST_CHAIN_ID,
            TEST_CHAIN_CONFIG,
        ));
        sjm.set_zisk_data_cache(Arc::new(ZiskDataCache::new()));
        sjm.set_zisk_job_manager(zjm.clone());
        sjm.set_require_multi_proof(require);
        sjm.set_multi_proof_wait_timeout(wait_timeout);
        let envelope = envelope(1);
        let proving_version = envelope.batch.proving_version().expect("proving version");
        sjm.add_job(envelope).await;
        (sjm, zjm, rx, proving_version)
    }

    /// Run the batch's ZiSK job through the manager so a validated proof is
    /// parked in `completed` — the state the rendezvous composes from.
    async fn park_zisk_proof(zjm: &ZiskJobManager, batch: u64) {
        let batch_metadata = envelope(batch).batch;
        let stored = batch_metadata.batch_info.clone().into_stored();
        let prev = &batch_metadata.previous_stored_batch_info;
        let commitment = crate::prover_api::zisk_proof_verifier::expected_zisk_public_input(
            &prev.state_commitment,
            &stored,
            TEST_CHAIN_ID,
            TEST_CHAIN_CONFIG,
        );
        let mut public_values = vec![0u8; ZISK_PUBLIC_VALUES_BYTES];
        public_values[32..64].copy_from_slice(commitment.as_slice());

        zjm.add_job(
            batch,
            ZiskJobData {
                zisk_data: vec![0xAB; 16],
                batch_metadata,
                added_at: std::time::Instant::now(),
            },
        )
        .await
        .unwrap_or_else(|_| panic!("add_job rejected"));
        zjm.pick_next_job("zisk-prover")
            .await
            .expect("job available");
        zjm.submit_proof(
            batch,
            vec![0; ZISK_SNARK_PROOF_BYTES],
            public_values,
            "zisk-prover",
        )
        .await
        .expect("zisk proof accepted");
    }

    /// With multi-proof required and no ZiSK input for the batch, the
    /// Airbender submission is rejected BEFORE the job is consumed: the job
    /// stays in the map and is re-offered instead of being dropped.
    #[tokio::test]
    async fn blocked_submit_keeps_the_job() {
        let (sjm, _zjm, _rx, proving_version) = manager_with_job(true, None).await;

        let err = sjm
            .submit_proof(1, 1, proving_version, vec![0xAA; 8], "prover-1".into())
            .await
            .expect_err("must be blocked");
        assert!(
            err.to_string().contains("multi_proof_verifier requires"),
            "{err}"
        );
        assert!(
            sjm.jobs.get_job_batch_metadata(1).await.is_some(),
            "job must remain queued after a blocked submission"
        );
    }

    /// With multi-proof required and the batch's ZiSK proof still in flight
    /// (job pending), the submission blocks without consuming the job.
    #[tokio::test]
    async fn blocked_while_zisk_proof_in_flight() {
        let (sjm, zjm, _rx, proving_version) = manager_with_job(true, None).await;
        zjm.add_job(
            1,
            ZiskJobData {
                zisk_data: vec![0xAB; 16],
                batch_metadata: envelope(1).batch,
                added_at: std::time::Instant::now(),
            },
        )
        .await
        .unwrap_or_else(|_| panic!("add_job rejected"));

        let err = sjm
            .submit_proof(1, 1, proving_version, vec![0xAA; 8], "prover-1".into())
            .await
            .expect_err("must be blocked while the proof is in flight");
        assert!(err.to_string().contains("not yet submitted"), "{err}");
        assert!(sjm.jobs.get_job_batch_metadata(1).await.is_some());
    }

    /// The rendezvous: with the batch's validated ZiSK proof parked, the
    /// Airbender submission composes and sends the MultiProof immediately.
    #[tokio::test]
    async fn completed_zisk_proof_composes_multi_proof() {
        let (sjm, zjm, mut rx, proving_version) = manager_with_job(true, None).await;
        park_zisk_proof(&zjm, 1).await;

        sjm.submit_proof(1, 1, proving_version, vec![0xAA; 8], "prover-1".into())
            .await
            .expect("submission with a parked ZiSK proof must pass");
        let cmd = rx.try_recv().expect("MultiProof command sent downstream");
        let (_batches, proof) = cmd.into_parts();
        match proof {
            SnarkProof::MultiProof(mp) => {
                assert_eq!(mp.era_proof, vec![0xAA; 8]);
                assert_eq!(mp.zisk_proof.len(), ZISK_SNARK_PROOF_BYTES);
            }
            other => panic!("expected MultiProof, got {other:?}"),
        }
        assert!(
            zjm.take_completed(1).await.is_none(),
            "the parked proof must be consumed by composition"
        );
    }

    /// Once the wait timeout expires, the same submission degrades to
    /// Airbender-only instead of blocking forever.
    #[tokio::test]
    async fn wait_timeout_degrades_to_single_proof() {
        let (sjm, _zjm, mut rx, proving_version) =
            manager_with_job(true, Some(Duration::ZERO)).await;

        sjm.submit_proof(1, 1, proving_version, vec![0xAA; 8], "prover-1".into())
            .await
            .expect("degrade must be allowed after the timeout");
        let cmd = rx
            .try_recv()
            .expect("Airbender-only command sent downstream");
        drop(cmd);
        assert!(
            sjm.jobs.get_job_batch_metadata(1).await.is_none(),
            "job must be consumed by the degraded submission"
        );
    }

    /// Without the multi-proof requirement nothing blocks — and even with a
    /// parked ZiSK proof, optional (shadow) mode sends Airbender-only:
    /// a MultiProof always encodes as a type-5 L1 payload, which shadow
    /// deployments (no MultiProofVerifier on L1) cannot accept. The parked
    /// proof is swept.
    #[tokio::test]
    async fn optional_multi_proof_sends_airbender_only() {
        let (sjm, zjm, mut rx, proving_version) = manager_with_job(false, None).await;
        park_zisk_proof(&zjm, 1).await;
        sjm.submit_proof(1, 1, proving_version, vec![0xAA; 8], "prover-1".into())
            .await
            .expect("optional mode must pass through");
        let cmd = rx.try_recv().expect("command sent downstream");
        let (_batches, proof) = cmd.into_parts();
        assert!(
            matches!(proof, SnarkProof::Real(_)),
            "optional mode must never send a MultiProof to L1"
        );
        assert!(
            zjm.take_completed(1).await.is_none(),
            "the parked proof is swept once the batch went Airbender-only"
        );
    }

    // ---- aggregated mode ----

    use crate::prover_api::zisk_aggregation_job_manager::{
        AggregationInput, ZiskAggregationJobManager, expected_aggregated_public_input,
    };
    use crate::prover_api::zisk_vadcop_stream::test_stream::synthetic_stream;
    use alloy::primitives::B256;

    const TEST_PROGRAM_VK: [u64; 4] = [1, 2, 3, 4];
    const TEST_VADCOP_VK: [u64; 4] = [5, 6, 7, 8];

    fn vk_be(limbs: [u64; 4]) -> B256 {
        let mut out = [0u8; 32];
        for (i, chunk) in out.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&limbs[i].to_be_bytes());
        }
        B256::from(out)
    }

    /// A SNARK manager wired for AGGREGATED mode over 2-batch ranges, with
    /// jobs for batches 1..=2 added.
    async fn aggregated_manager(
        require: bool,
        wait_timeout: Option<Duration>,
    ) -> (
        SnarkJobManager,
        Arc<ZiskJobManager>,
        Arc<ZiskAggregationJobManager>,
        mpsc::Receiver<ProofCommand>,
        ProvingVersion,
    ) {
        let (tx, rx) = mpsc::channel(4);
        let mut sjm = SnarkJobManager::new(tx, 2, Duration::from_secs(60), 10);
        let zjm = Arc::new(ZiskJobManager::new(
            Duration::from_secs(60),
            None,
            TEST_CHAIN_ID,
            TEST_CHAIN_CONFIG,
        ));
        let ajm = Arc::new(ZiskAggregationJobManager::new(
            2,
            Duration::from_secs(60),
            None,
        ));
        zjm.set_aggregation_sink(ajm.clone());
        sjm.set_zisk_data_cache(Arc::new(ZiskDataCache::new()));
        sjm.set_zisk_job_manager(zjm.clone());
        sjm.set_zisk_aggregation_job_manager(ajm.clone());
        sjm.set_require_multi_proof(require);
        sjm.set_multi_proof_wait_timeout(wait_timeout);
        let mut proving_version = None;
        for batch in 1..=2 {
            let envelope = envelope(batch);
            proving_version = Some(envelope.batch.proving_version().expect("proving version"));
            sjm.add_job(envelope).await;
        }
        (sjm, zjm, ajm, rx, proving_version.unwrap())
    }

    /// Run a batch's per-batch ZiSK job through the manager in aggregated
    /// mode (matching vadcop_final stream), returning the batch commitment.
    async fn submit_zisk_stream(zjm: &ZiskJobManager, batch: u64) -> B256 {
        let batch_metadata = envelope(batch).batch;
        let stored = batch_metadata.batch_info.clone().into_stored();
        let prev = &batch_metadata.previous_stored_batch_info;
        let commitment = crate::prover_api::zisk_proof_verifier::expected_zisk_public_input(
            &prev.state_commitment,
            &stored,
            TEST_CHAIN_ID,
            TEST_CHAIN_CONFIG,
        );
        let stream = synthetic_stream(TEST_PROGRAM_VK, TEST_VADCOP_VK, commitment.0);
        zjm.add_job(
            batch,
            ZiskJobData {
                zisk_data: vec![0xAB; 16],
                batch_metadata,
                added_at: std::time::Instant::now(),
            },
        )
        .await
        .unwrap_or_else(|_| panic!("add_job rejected"));
        zjm.pick_next_job("zisk-prover")
            .await
            .expect("job available");
        zjm.submit_proof(batch, stream, vec![], "zisk-prover")
            .await
            .expect("zisk stream accepted");
        commitment
    }

    /// Aggregated public values whose digest matches the given commitments.
    fn aggregated_public_values(commitments: &[B256]) -> Vec<u8> {
        let inputs: Vec<AggregationInput> = commitments
            .iter()
            .map(|&commitment| AggregationInput {
                stream: vec![],
                program_vk: vk_be(TEST_PROGRAM_VK),
                vadcop_vk: vk_be(TEST_VADCOP_VK),
                commitment,
            })
            .collect();
        let refs: Vec<&AggregationInput> = inputs.iter().collect();
        let digest = expected_aggregated_public_input(&refs).expect("digest");
        let mut pv = vec![0u8; ZISK_PUBLIC_VALUES_BYTES];
        pv[32..64].copy_from_slice(digest.as_slice());
        pv
    }

    /// The aggregated rendezvous end to end: a blocked Airbender range
    /// submission registers the range; the per-batch streams arrive; the
    /// aggregation prover proves the range; the re-submitted Airbender
    /// range SNARK composes the range MultiProof carrying the AGGREGATED
    /// proof, and the per-batch markers are swept.
    #[tokio::test]
    async fn aggregated_rendezvous_composes_range_multi_proof() {
        let (sjm, zjm, ajm, mut rx, proving_version) = aggregated_manager(true, None).await;

        // Airbender arrives first: blocked, range registered, jobs kept.
        let err = sjm
            .submit_proof(1, 2, proving_version, vec![0xAA; 8], "prover-1".into())
            .await
            .expect_err("must block until the aggregated proof lands");
        assert!(err.to_string().contains("aggregated ZiSK proof"), "{err}");
        assert!(sjm.jobs.get_job_batch_metadata(1).await.is_some());

        // Per-batch streams land; the range forms and gets proven.
        let c1 = submit_zisk_stream(&zjm, 1).await;
        let c2 = submit_zisk_stream(&zjm, 2).await;
        let job = ajm.pick_next_job("agg-1").await.expect("aggregation job");
        assert_eq!((job.from_batch, job.to_batch), (1, 2));
        ajm.submit_proof(
            1,
            2,
            vec![0x77; ZISK_SNARK_PROOF_BYTES],
            aggregated_public_values(&[c1, c2]),
            "agg-1",
        )
        .await
        .expect("aggregated proof accepted");

        // The Airbender range SNARK now composes the range MultiProof.
        sjm.submit_proof(1, 2, proving_version, vec![0xAA; 8], "prover-1".into())
            .await
            .expect("rendezvous must compose");
        let cmd = rx.try_recv().expect("MultiProof command sent downstream");
        let (batches, proof) = cmd.into_parts();
        assert_eq!(batches.len(), 2, "the command covers the whole range");
        match proof {
            SnarkProof::MultiProof(mp) => {
                assert_eq!(mp.era_proof, vec![0xAA; 8]);
                assert_eq!(mp.zisk_proof, vec![0x77; ZISK_SNARK_PROOF_BYTES]);
                assert_eq!(mp.zisk_public_values, aggregated_public_values(&[c1, c2]));
            }
            other => panic!("expected MultiProof, got {other:?}"),
        }
        // Consumed range: markers swept, aggregated proof taken exactly once.
        assert!(zjm.take_completed(1).await.is_none());
        assert!(zjm.take_completed(2).await.is_none());
        assert!(ajm.take_completed(1, 2).await.is_none());
    }

    /// Aggregated + optional (shadow) mode: nothing blocks, the range goes
    /// downstream Airbender-only, and the aggregation state for the
    /// consumed batches is swept.
    #[tokio::test]
    async fn aggregated_optional_mode_sends_airbender_only() {
        let (sjm, zjm, ajm, mut rx, proving_version) = aggregated_manager(false, None).await;
        submit_zisk_stream(&zjm, 1).await;
        submit_zisk_stream(&zjm, 2).await;

        sjm.submit_proof(1, 2, proving_version, vec![0xAA; 8], "prover-1".into())
            .await
            .expect("optional mode must pass through");
        let cmd = rx.try_recv().expect("command sent downstream");
        let (_batches, proof) = cmd.into_parts();
        assert!(
            matches!(proof, SnarkProof::Real(_)),
            "optional mode must never send a MultiProof to L1"
        );
        assert!(
            !ajm.has_input(1).await && !ajm.has_input(2).await,
            "inputs swept"
        );
        assert!(
            ajm.pick_next_job("agg-1").await.is_none(),
            "no aggregation job for batches already sent"
        );
    }

    /// Aggregated + wait timeout expired: the range degrades to
    /// Airbender-only instead of blocking forever.
    #[tokio::test]
    async fn aggregated_wait_timeout_degrades_to_single_proof() {
        let (sjm, _zjm, _ajm, mut rx, proving_version) =
            aggregated_manager(true, Some(Duration::ZERO)).await;

        sjm.submit_proof(1, 2, proving_version, vec![0xAA; 8], "prover-1".into())
            .await
            .expect("degrade must be allowed after the timeout");
        let cmd = rx
            .try_recv()
            .expect("Airbender-only command sent downstream");
        drop(cmd);
        assert!(
            sjm.jobs.get_job_batch_metadata(1).await.is_none(),
            "jobs must be consumed by the degraded submission"
        );
    }

    /// Optional mode with no parked proof: the batch goes Airbender-only and
    /// a proof parked afterwards for that batch is swept by the next send.
    #[tokio::test]
    async fn optional_mode_sweeps_stale_parked_proofs() {
        let (sjm, zjm, mut rx, proving_version) = manager_with_job(false, None).await;

        sjm.submit_proof(1, 1, proving_version, vec![0xAA; 8], "prover-1".into())
            .await
            .expect("optional mode must pass through");
        let cmd = rx
            .try_recv()
            .expect("Airbender-only command sent downstream");
        let (_batches, proof) = cmd.into_parts();
        assert!(matches!(proof, SnarkProof::Real(_)));

        // A late proof for the already-sent batch parks, then the next
        // Airbender-only send (batch 2) sweeps it as never-composable.
        park_zisk_proof(&zjm, 1).await;
        sjm.add_job(envelope(2)).await;
        sjm.submit_proof(2, 2, proving_version, vec![0xBB; 8], "prover-1".into())
            .await
            .expect("optional mode must pass through");
        assert!(
            zjm.take_completed(1).await.is_none(),
            "stale parked proof must be swept once its batch went Airbender-only"
        );
    }
}
