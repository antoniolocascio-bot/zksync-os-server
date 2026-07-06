use crate::prover_api::fri_job_manager::FriJob;
use crate::prover_api::metrics::{ProverStage, ProverType};
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
        }
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
        // ZiSK proving when the range is exactly one batch. Multi-batch SNARK
        // proofs combined with ZiSK require chaining tree updates across blocks
        // which is not yet implemented.
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
                    // Queue was full — fall back to Airbender-only using recovered data
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
    fn send_airbender_only(
        &self,
        permit: Permit<'_, ProofCommand>,
        batches: Vec<SignedBatchEnvelope<FriProof>>,
        payload: Vec<u8>,
        proving_version: ProvingVersion,
    ) -> anyhow::Result<()> {
        if self.require_multi_proof && self.zisk_data_cache.is_some() {
            let batch_num = batches.first().map(|b| b.batch_number()).unwrap_or(0);
            anyhow::bail!(
                "multi_proof_verifier is required but ZiSK proof unavailable for batch {batch_num}. \
                 The batch cannot be submitted as Airbender-only. Check ZiSK prover status."
            );
        }
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
            let permit = self.try_reserve_permit_downstream()?;
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


