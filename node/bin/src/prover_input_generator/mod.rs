pub(crate) mod zisk_input_builder;

use self::tree_adapter::TreeOutputAdapter;
use self::tree_adapter::VersionedMerkleTree;
use crate::prover_block::ProverBlock;
use anyhow::Result;
use async_trait::async_trait;
use futures::StreamExt;
use futures::stream::FuturesOrdered;
use reth_tasks::Runtime;
use std::collections::VecDeque;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use vise::{Buckets, Histogram, LabeledFamily, Metrics, Unit};
use zksync_os_batch_types::BlockMerkleTreeData;
use zksync_os_batch_types::batcher_model::ProverInput;
use zksync_os_contract_interface::models::DACommitmentScheme;
use zksync_os_interface::traits::TxListSource;
use zksync_os_merkle_tree::{MerkleTree, MerkleTreeVersion, RocksDBWrapper};
use zksync_os_observability::{ComponentStateReporter, GenericComponentState};
use zksync_os_pipeline::{PeekableReceiver, PipelineComponent, SendAndRecordExt};
use zksync_os_storage_api::{ReadStateHistory, ReplayRecord, TreeBlock};
use zksync_os_types::{ProvingVersion, PubdataMode, ZksyncOsEncode};

mod tree_adapter;

/// This component generates prover input from batch replay data.
///
/// When `disabled` is `true` the component acts as a passthrough: it forwards each block
/// unchanged but sets `ProverInput::Fake` instead of computing real witness data.
/// This is only valid when both FRI and SNARK provers are faked.
pub struct ProverInputGenerator<ReadState> {
    pub enable_logging: bool,
    pub maximum_in_flight_blocks: usize,
    pub read_state: ReadState,
    pub pubdata_mode: PubdataMode,
    pub runtime: Runtime,
    pub merkle_tree: MerkleTree<RocksDBWrapper>,
    /// When true, skip all computation and emit `ProverInput::Fake` for every block.
    pub disabled: bool,
    /// When true, generate second proof system (ZiSK) input alongside the
    /// airbender witness. The two run in parallel — airbender is always primary.
    pub enable_second_proof_system: bool,
}

#[async_trait]
impl<ReadState: ReadStateHistory + Clone + Send + 'static> PipelineComponent
    for ProverInputGenerator<ReadState>
{
    type Input = TreeBlock;
    type Output = ProverBlock;

    const COMPONENT_ID: zksync_os_pipeline::ComponentId =
        zksync_os_pipeline::ComponentId::ProverInputGenerator;

    /// Works on multiple blocks in parallel, up to [Self::maximum_in_flight_blocks].
    /// Each computation runs on the blocking pool and is tracked as a graceful task so
    /// the RocksDB tree lock held by [`VersionedMerkleTree`] is always released before
    /// [graceful_shutdown_with_timeout] returns.
    async fn run(
        self,
        mut input: PeekableReceiver<Self::Input>,
        output: mpsc::Sender<Self::Output>,
        state_reporter: ComponentStateReporter,
    ) -> Result<()> {
        if self.disabled {
            tracing::info!(
                "ProverInputGenerator is disabled — passing through blocks with ProverInput::Fake"
            );
            loop {
                state_reporter.enter_state(GenericComponentState::Idle);
                let Some(TreeBlock {
                    output: block_output,
                    record: replay_record,
                    tree,
                }) = input.recv_and_record_picked(&state_reporter).await
                else {
                    return Ok(());
                };
                state_reporter.enter_state(GenericComponentState::Active);
                output.send_and_record(
                    ProverBlock {
                        output: block_output,
                        record: replay_record,
                        prover_input: ProverInput::Fake,
                        tree_output: tree.output,
                    },
                    &state_reporter,
                )?;
            }
        }
        // Process the first item alone — it involves heavy trusted-setup precomputation
        // and we want it isolated before concurrent processing starts.
        state_reporter.enter_state(GenericComponentState::Idle);
        let first_item = match input.recv_and_record_picked(&state_reporter).await {
            Some(item) => item,
            None => return Ok(()),
        };
        state_reporter.enter_state(GenericComponentState::Active);
        let result = self.spawn_computation(first_item).await?;
        tracing::debug!(
            block_number = result.output.header.number,
            "sending block with prover input to batcher",
        );
        output.send_and_record(result, &state_reporter)?;

        // Process remaining items with up to `maximum_in_flight_blocks` in parallel.
        // Results are delivered in arrival order via FuturesOrdered.
        let mut pending: FuturesOrdered<oneshot::Receiver<ProverBlock>> = FuturesOrdered::new();
        let mut input_done = false;

        loop {
            if input_done && pending.is_empty() {
                break;
            }

            state_reporter.enter_state(GenericComponentState::Idle);
            tokio::select! {
                maybe_item = input.recv(),
                    if !input_done && pending.len() < self.maximum_in_flight_blocks =>
                {
                    state_reporter.enter_state(GenericComponentState::Active);
                    match maybe_item {
                        Some(item) => {
                            state_reporter.record_picked(item.output.header.number, Some(item.record.block_context.timestamp), None);
                            pending.push_back(self.spawn_computation(item));
                        }
                        None => input_done = true,
                    }
                }
                Some(result) = pending.next(), if !pending.is_empty() => {
                    state_reporter.enter_state(GenericComponentState::Active);
                    let item = result.map_err(|_| anyhow::anyhow!("prover input computation task dropped sender"))?;
                    tracing::debug!(
                        block_number = item.output.header.number,
                        "sending block with prover input to batcher",
                    );
                    output.send_and_record(item, &state_reporter)?;
                }
            }
        }

        Ok(())
    }
}

impl<ReadState: ReadStateHistory + Clone + Send + 'static> ProverInputGenerator<ReadState> {
    /// Submits one block's prover-input computation to the blocking CPU pool and returns
    /// a receiver for the result. The computation is tracked as a graceful task so its
    /// [`VersionedMerkleTree`] (holding the tree RocksDB lock) is guaranteed to be dropped
    /// before [graceful_shutdown_with_timeout] returns.
    fn spawn_computation(&self, input: TreeBlock) -> oneshot::Receiver<ProverBlock> {
        let TreeBlock {
            output: block_output,
            record: replay_record,
            tree,
        } = input;
        let (result_tx, result_rx) = oneshot::channel();
        let read_state = self.read_state.clone();
        let enable_logging = self.enable_logging;
        let da_commitment_scheme = self
            .pubdata_mode
            .adapt_for_protocol_version(&replay_record.protocol_version)
            .da_commitment_scheme();
        let block_number = replay_record.block_context.block_number;
        tracing::debug!(
            block_number,
            "ProverInputGenerator started processing block {} with {} transactions",
            block_number,
            replay_record.transactions.len(),
        );
        let versioned_tree = VersionedMerkleTree::new(self.merkle_tree.clone(), block_number - 1);
        let enable_second_proof = self.enable_second_proof_system;
        // Pointwise tree views before/after the block for the ZiSK input
        // builder (it extracts per-slot merkle proofs, which the streamed
        // BlockMerkleTreeData does not carry).
        let zisk_tree_before = MerkleTreeVersion {
            tree: self.merkle_tree.clone(),
            block: block_number - 1,
        };
        let zisk_tree_after = MerkleTreeVersion {
            tree: self.merkle_tree.clone(),
            block: block_number,
        };

        let mut handle = tokio::task::spawn_blocking(move || {
            let tree_output = tree.output;
            let prover_input = compute_prover_input(
                &replay_record,
                read_state,
                tree,
                versioned_tree,
                zisk_tree_before,
                zisk_tree_after,
                &block_output,
                da_commitment_scheme,
                enable_logging,
                enable_second_proof,
            );
            ProverBlock {
                output: block_output,
                record: replay_record,
                prover_input,
                tree_output,
            }
        });
        self.runtime.spawn_critical_with_graceful_shutdown_signal(
            "prover input computation",
            |shutdown| async move {
                tokio::select! {
                    Ok(result) = &mut handle => {
                        let _ = result_tx.send(result);
                    }
                    _guard = shutdown => {
                        // Wait for CPU task to finish while holding shutdown guard. This blocks
                        // shutdown until prover input generation task finishes and frees up tree DB.
                        let _ = handle.await;
                    }
                }
            },
        );

        result_rx
    }
}

fn compute_prover_input(
    replay_record: &ReplayRecord,
    state_handle: impl ReadStateHistory + Clone,
    tree_view: BlockMerkleTreeData,
    versioned_tree: VersionedMerkleTree,
    zisk_tree_before: MerkleTreeVersion<RocksDBWrapper>,
    zisk_tree_after: MerkleTreeVersion<RocksDBWrapper>,
    block_output: &BlockOutput,
    da_commitment_scheme: DACommitmentScheme,
    enable_logging: bool,
    enable_second_proof: bool,
) -> ProverInput {
    let block_number = replay_record.block_context.block_number;
    let state_view = state_handle.state_view_at(block_number - 1).unwrap();
    let transactions = replay_record
        .transactions
        .iter()
        .map(|tx| tx.clone().encode())
        .collect::<VecDeque<_>>();

    let prover_input_generation_latency =
        PROVER_INPUT_GENERATOR_METRICS.prover_input_generation[&"prover_input_generation"].start();
    let proving_version = ProvingVersion::try_from(replay_record.protocol_version.clone())
        .expect("invalid protocol version");

    // Always generate airbender witness (primary proof system)
    let witness = match proving_version {
        ProvingVersion::V1
        | ProvingVersion::V2
        | ProvingVersion::V3
        | ProvingVersion::V4
        | ProvingVersion::V5 => {
            // EN-dump-mode patch: instead of panicking, emit a Fake input so
            // the pipeline can walk past historical blocks on pre-V6 protocol
            // versions and reach the V6+ era where ZiSK proofs are supported.
            tracing::warn!(
                block_number,
                ?proving_version,
                "skipping prover input generation for pre-V6 block (returning ProverInput::Fake)"
            );
            drop(prover_input_generation_latency);
            return ProverInput::Fake;
        }
        ProvingVersion::V6 => {
            use zk_ee_prev::{
                common_structs::ProofData, system::metadata::zk_metadata::BlockMetadataFromOracle,
            };
            use zk_os_forward_system_prev::run::{
                StorageCommitment, convert::FromInterface, generate_proof_input_from_bytes,
            };

            let initial_storage_commitment = StorageCommitment {
                root: tree_view.input.root_hash.0.into(),
                next_free_slot: tree_view.input.leaf_count,
            };
            let list_source = TxListSource { transactions };
            let bin_bytes = if enable_logging {
                zksync_os_multivm::apps::v6::SINGLEBLOCK_BATCH_LOGGING_ENABLED
            } else {
                zksync_os_multivm::apps::v6::SINGLEBLOCK_BATCH_APP
            };
            let da_commitment_scheme = (da_commitment_scheme as u8)
                .try_into()
                .expect("Failed to convert DA commitment scheme");
            generate_proof_input_from_bytes(
                bin_bytes,
                BlockMetadataFromOracle::from_interface(replay_record.block_context),
                ProofData {
                    state_root_view: initial_storage_commitment,
                    last_block_timestamp: replay_record.previous_block_timestamp,
                },
                da_commitment_scheme,
                TreeOutputAdapter::new(tree_view).with_fallback(versioned_tree),
                state_view,
                list_source,
            )
            .expect("proof gen failed")
        }
        ProvingVersion::V7 | ProvingVersion::ZiskV1 => {
            use zk_ee::{
                common_structs::ProofData, system::metadata::zk_metadata::BlockMetadataFromOracle,
            };
            use zk_os_forward_system::run::{
                StorageCommitment, convert::FromInterface, generate_proof_input_from_bytes,
            };

            let initial_storage_commitment = StorageCommitment {
                root: tree_view.input.root_hash.0.into(),
                next_free_slot: tree_view.input.leaf_count,
            };
            let list_source = TxListSource { transactions };
            let bin_bytes = if enable_logging {
                zksync_os_multivm::apps::v7::SINGLEBLOCK_BATCH_LOGGING_ENABLED
            } else {
                zksync_os_multivm::apps::v7::SINGLEBLOCK_BATCH_APP
            };
            let da_commitment_scheme = (da_commitment_scheme as u8)
                .try_into()
                .expect("Failed to convert DA commitment scheme");
            generate_proof_input_from_bytes(
                bin_bytes,
                BlockMetadataFromOracle::from_interface(replay_record.block_context),
                ProofData {
                    state_root_view: initial_storage_commitment,
                    last_block_timestamp: replay_record.previous_block_timestamp,
                },
                da_commitment_scheme,
                TreeOutputAdapter::new(tree_view).with_fallback(versioned_tree),
                state_view,
                list_source,
            )
            .expect("proof gen failed")
        }
    };

    // Optionally generate ZiSK prover input alongside airbender witness
    let zisk_data = if enable_second_proof {
        tracing::debug!(block_number, "Generating ZiSK prover input alongside airbender witness");
        match zisk_input_builder::build_block_data(block_output, replay_record, &zisk_tree_before, &zisk_tree_after, &state_handle) {
            Ok(block_data) => Some(
                bincode1::serialize(&block_data).expect("failed to serialize ZiSK BlockData"),
            ),
            Err(e) => {
                tracing::error!(block_number, "ZiSK input generation failed: {e:#}");
                None
            }
        }
    } else {
        None
    };

    let prover_input = ProverInput::Real {
        witness,
        zisk_data,
    };
    let latency = prover_input_generation_latency.observe();
    let zisk_size = prover_input.zisk_data().map(|d| d.len()).unwrap_or(0);
    tracing::info!(
        block_number,
        zisk_data_bytes = zisk_size,
        "Completed prover input computation in {:?}. Airbender witness: {} words, ZiSK data: {} bytes",
        latency,
        prover_input.unwrap_real().len(),
        zisk_size,
    );
    prover_input
}

const LEN_BUCKETS: Buckets = Buckets::exponential(1.0..=1000.0, 2.0);
const LATENCIES_FAST: Buckets = Buckets::exponential(0.001..=30.0, 2.0);

#[derive(Debug, Metrics)]
#[metrics(prefix = "prover_input_generator")]
struct ProverInputGeneratorMetrics {
    #[metrics(unit = Unit::Seconds, labels = ["stage"], buckets = LATENCIES_FAST)]
    prover_input_generation: LabeledFamily<&'static str, Histogram<Duration>>,
    /// Number of unexpected existing storage slots queried per block. Positive values are abnormal.
    #[metrics(buckets = LEN_BUCKETS)]
    unexpected_queried_keys: Histogram<usize>,
    /// Number of unexpected missing storage slots queried per block. Positive values are abnormal.
    #[metrics(buckets = LEN_BUCKETS)]
    unexpected_queried_missing_keys: Histogram<usize>,
    /// Number of unexpected Merkle proofs queried per block. Positive values are abnormal.
    #[metrics(buckets = LEN_BUCKETS)]
    unexpected_queried_proofs: Histogram<usize>,
}

#[vise::register]
static PROVER_INPUT_GENERATOR_METRICS: vise::Global<ProverInputGeneratorMetrics> =
    vise::Global::new();
