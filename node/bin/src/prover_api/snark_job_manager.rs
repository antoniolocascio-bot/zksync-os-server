use crate::prover_api::fri_job_manager::FriJob;
use crate::prover_api::metrics::{ProverStage, ProverType, ZISK_LANE_METRICS};
use crate::prover_api::prover_job_map::ProverJobMap;
use crate::prover_api::zisk_data_cache::ZiskDataCache;
use crate::prover_api::zisk_job_manager::{ZiskJobData, ZiskJobManager};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Permit;
use tokio::sync::mpsc::error::TrySendError;
use zksync_os_batch_types::batcher_model::{
    FriProof, RealSnarkProof, SignedBatchEnvelope, SnarkProof,
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
/// When an Airbender SNARK is submitted and ZiSK data exists for the batch,
/// the batch is routed to `ZiskJobManager` for multi-proof composition.
/// Otherwise, the Airbender-only proof is sent downstream immediately.
pub struct SnarkJobManager {
    jobs: ProverJobMap<FriProof>,
    // outbound
    prove_batches_sender: mpsc::Sender<ProofCommand>,
    // config
    max_fris_per_snark: usize,
    zisk_data_cache: Option<Arc<ZiskDataCache>>,
    zisk_job_manager: Option<Arc<ZiskJobManager>>,
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

    /// Get a reference to the downstream proof command sender.
    /// Used by ZiskJobManager to share the same downstream channel.
    pub fn prove_sender(&self) -> &mpsc::Sender<ProofCommand> {
        &self.prove_batches_sender
    }

    pub async fn add_job(&self, batch_envelope: SignedBatchEnvelope<FriProof>) {
        self.jobs.add_job(batch_envelope).await
    }

    pub async fn pick_real_job(
        &self,
        prover_id: String,
    ) -> anyhow::Result<Option<Vec<(FriJob, FriProof)>>> {
        self.process_pending_fake_fri_proofs().await?;

        let batches_with_real_proofs = self
            .jobs
            .pick_jobs_while_with_limit(self.max_fris_per_snark, &prover_id, |job| {
                !job.batch_envelope.data.is_fake()
            })
            .await;

        if batches_with_real_proofs.is_empty() {
            tracing::trace!(prover_id, "no SNARK prove jobs are available for pick up");
            return Ok(None);
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

        // Check ZiSK data availability. For multi-batch ranges we only support
        // ZiSK proving when the range is exactly one batch (enforced at
        // startup via `max_fris_per_snark = 1` when the second proof system
        // is on; the branch below is defensive).
        let has_zisk = if let Some(ref cache) = self.zisk_data_cache {
            if batch_from != batch_to {
                // Multi-batch range: ZiSK proving not supported, send Airbender-only.
                // Log a warning so operators know multi-proof is skipped.
                tracing::warn!(
                    batch_from,
                    batch_to,
                    "multi-batch SNARK range — ZiSK proving skipped (not yet supported for ranges)"
                );
                false
            } else {
                cache.contains(batch_from).await
            }
        } else {
            false
        };

        // Multi-proof policy is decided BEFORE any job is consumed, so a
        // blocked submission leaves the SNARK job in place: the assignment
        // times out and the batch is re-offered until its ZiSK path clears
        // (block-until-proof). After `multi_proof_wait_timeout` (when set),
        // the batch is allowed through Airbender-only with a loud signal.
        let multi_proof_expected = self.require_multi_proof && self.zisk_data_cache.is_some();
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
        if multi_proof_expected && batch_from == batch_to {
            let blocked_reason = if !has_zisk {
                Some("no ZiSK input available for the batch (evicted or not regenerated)")
            } else if let Some(zjm) = self.zisk_job_manager.as_ref()
                && !zjm.has_capacity().await
            {
                Some("ZiSK job queue is full (provers offline or behind)")
            } else {
                None
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

        if has_zisk {
            let Some(zjm) = self.zisk_job_manager.as_ref() else {
                tracing::error!(
                    "ZiSK data exists but ZiskJobManager not initialized — sending Airbender-only"
                );
                return self.send_airbender_only(permit, consumed_batches_proven, payload, proving_version);
            };
            let cache = self.zisk_data_cache.as_ref().expect("checked above");
            // Atomic remove — avoids TOCTOU race between contains() and remove().
            let Some(zisk_data) = cache.remove(batch_from).await else {
                tracing::warn!(
                    batch = batch_from,
                    "ZiSK data consumed by concurrent submit or expired, sending Airbender-only"
                );
                return self.send_airbender_only(permit, consumed_batches_proven, payload, proving_version);
            };

            tracing::info!(
                batch = batch_from,
                era_proof_bytes = payload.len(),
                zisk_data_bytes = zisk_data.len(),
                "Airbender SNARK received, routing to ZiSK job manager"
            );

            match zjm
                .add_job(
                    batch_from,
                    ZiskJobData {
                        zisk_data,
                        era_proof: payload,
                        proving_execution_version: proving_version as u32,
                        batches: consumed_batches_proven,
                    },
                )
                .await
            {
                Ok(()) => Ok(()),
                Err(rejected) => {
                    // Queue filled up between the capacity pre-check and here —
                    // fall back to Airbender-only using the recovered data
                    // (under require_multi_proof the pre-check above already
                    // rejected without consuming; this race window is benign).
                    tracing::warn!(
                        batch = batch_from,
                        "ZiSK job queue full, sending Airbender-only proof"
                    );
                    permit.send(ProofCommand::new(
                        rejected.batches,
                        SnarkProof::Real(RealSnarkProof::V2 {
                            proof: rejected.era_proof,
                            proving_execution_version: rejected.proving_execution_version,
                        }),
                    ));
                    Ok(())
                }
            }
        } else {
            self.send_airbender_only(permit, consumed_batches_proven, payload, proving_version)
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
    use crate::prover_api::test_util::create_test_batch_envelope;
    use zksync_os_types::ProtocolSemanticVersion;

    fn envelope(batch: u64) -> SignedBatchEnvelope<FriProof> {
        let mut e = create_test_batch_envelope(batch, FriProof::Fake);
        e.batch.batch_info.protocol_version = ProtocolSemanticVersion::new(0, 31, 0);
        e
    }

    async fn manager_with_job(
        require: bool,
        wait_timeout: Option<Duration>,
    ) -> (SnarkJobManager, mpsc::Receiver<ProofCommand>, ProvingVersion) {
        let (tx, rx) = mpsc::channel(4);
        let mut sjm = SnarkJobManager::new(tx, 1, Duration::from_secs(60), 10);
        sjm.set_zisk_data_cache(Arc::new(ZiskDataCache::new()));
        sjm.set_require_multi_proof(require);
        sjm.set_multi_proof_wait_timeout(wait_timeout);
        let envelope = envelope(1);
        let proving_version = envelope.batch.proving_version().expect("proving version");
        sjm.add_job(envelope).await;
        (sjm, rx, proving_version)
    }

    /// With multi-proof required and no ZiSK input for the batch, the
    /// Airbender submission is rejected BEFORE the job is consumed: the job
    /// stays in the map and is re-offered instead of being dropped.
    #[tokio::test]
    async fn blocked_submit_keeps_the_job() {
        let (sjm, _rx, proving_version) = manager_with_job(true, None).await;

        let err = sjm
            .submit_proof(1, 1, proving_version, vec![0xAA; 8], "prover-1".into())
            .await
            .expect_err("must be blocked");
        assert!(err.to_string().contains("multi_proof_verifier requires"), "{err}");
        assert!(
            sjm.jobs.get_job_batch_metadata(1).await.is_some(),
            "job must remain queued after a blocked submission"
        );
    }

    /// Once the wait timeout expires, the same submission degrades to
    /// Airbender-only instead of blocking forever.
    #[tokio::test]
    async fn wait_timeout_degrades_to_single_proof() {
        let (sjm, mut rx, proving_version) = manager_with_job(true, Some(Duration::ZERO)).await;

        sjm.submit_proof(1, 1, proving_version, vec![0xAA; 8], "prover-1".into())
            .await
            .expect("degrade must be allowed after the timeout");
        let cmd = rx.try_recv().expect("Airbender-only command sent downstream");
        drop(cmd);
        assert!(
            sjm.jobs.get_job_batch_metadata(1).await.is_none(),
            "job must be consumed by the degraded submission"
        );
    }

    /// Without the multi-proof requirement nothing blocks.
    #[tokio::test]
    async fn optional_multi_proof_sends_airbender_only() {
        let (sjm, mut rx, proving_version) = manager_with_job(false, None).await;

        sjm.submit_proof(1, 1, proving_version, vec![0xAA; 8], "prover-1".into())
            .await
            .expect("optional mode must pass through");
        rx.try_recv().expect("Airbender-only command sent downstream");
    }
}
