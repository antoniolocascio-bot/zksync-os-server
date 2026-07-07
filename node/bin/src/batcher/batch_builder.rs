use alloy::primitives::Address;
use alloy::consensus::BlobTransactionSidecar;
use zksync_os_batch_types::PendingBatchInfo;
use zksync_os_batch_types::batcher_model::{
    BatchEnvelope, BatchForSigning, BatchMetadata, ProverInput,
};
use zksync_os_batcher_metrics::BatchExecutionStage;
use zksync_os_contract_interface::models::{L2Log, StoredBatchInfo};
use zksync_os_storage_api::{ReadStateHistory, ReplayRecord, read_multichain_root};
use zksync_os_types::{BlockOutput, ProvingVersion, PubdataMode, SystemTxType, ZkEnvelope};

/// Takes a vector of blocks and produces a batch envelope.
#[allow(clippy::too_many_arguments)]
/// Chain-config parameters committed into the ZiSK batch public input
/// (`chain_config_hash` preimage, together with the chain id).
#[derive(Clone, Copy, Debug)]
pub struct ZiskChainConfig {
    pub fri_proof_verification_enabled: bool,
    pub max_tx_gas_limit: u64,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn seal_batch<ReadState: ReadStateHistory>(
    blocks: &[(
        BlockOutput,
        ReplayRecord,
        zksync_os_merkle_tree::TreeBatchOutput,
        ProverInput,
    )],
    prev_batch_info: StoredBatchInfo,
    batch_number: u64,
    chain_id: u64,
    chain_address_sl: Address,
    pubdata_mode: PubdataMode,
    sl_chain_id: u64,
    read_state: &ReadState,
    zisk_chain_config: ZiskChainConfig,
    batch_tree_start: Option<zksync_os_merkle_tree::MerkleTreeVersion>,
) -> anyhow::Result<BatchForSigning<ProverInput>> {
    let block_number_from = blocks.first().unwrap().1.block_context.block_number;
    let block_number_to = blocks.last().unwrap().1.block_context.block_number;
    let last_block_hash = blocks.last().unwrap().0.header.hash();
    let protocol_version = blocks.first().unwrap().1.protocol_version.clone();
    let (_, last_replay_record, _, _) = blocks.last().unwrap();

    let state_view = read_state.state_view_at(block_number_to)?;
    let multichain_root = read_multichain_root(state_view);
    let (batch_info, blob_sidecar) = PendingBatchInfo::build(
        blocks
            .iter()
            .map(|(block_output, replay_record, tree, _)| {
                (block_output, replay_record.transactions.as_slice(), tree)
            })
            .collect(),
        chain_id,
        batch_number,
        pubdata_mode,
        sl_chain_id,
        multichain_root,
        &protocol_version,
        &last_replay_record.block_context.block_hashes.0,
    );

    let mut logs = Vec::new();
    let mut messages = Vec::new();
    for block in blocks {
        for output in block.0.tx_results.iter().flatten() {
            for l2_to_l1_log in &output.l2_to_l1_logs {
                logs.push(L2Log {
                    l2_shard_id: l2_to_l1_log.log.l2_shard_id,
                    is_service: l2_to_l1_log.log.is_service,
                    tx_number_in_batch: l2_to_l1_log.log.tx_number_in_block,
                    sender: l2_to_l1_log.log.sender,
                    key: l2_to_l1_log.log.key,
                    value: l2_to_l1_log.log.value,
                });
                if let Some(preimage) = l2_to_l1_log.preimage.as_ref() {
                    messages.push(preimage.clone());
                }
            }
        }
    }

    let proving_version =
        ProvingVersion::try_from(blocks.first().unwrap().1.protocol_version.clone())?;
    // execution version should be the same for all the blocks, it is ensured by the seal criteria
    // Extract after-state account preimages for 0x8003 verification.
    let account_preimages_after = {
        use zksync_os_interface::traits::{PreimageSource, ReadStorage};
        let last_block_number = blocks.last().unwrap().1.block_context.block_number;
        let mut state_after = read_state.state_view_at(last_block_number)?;
        let mut seen = std::collections::HashSet::new();
        let mut preimages = Vec::new();
        for (block_output, _, _, _) in blocks {
            for diff in &block_output.account_diffs {
                if !seen.insert(diff.address) { continue; }
                let addr_bytes: [u8; 20] = diff.address.into();
                let flat_key = zksync_os_zisk_lib::merkle::derive_account_properties_key(&addr_bytes);
                if let Some(hash_value) =
                    ReadStorage::read(&mut state_after, alloy::primitives::B256::from(flat_key.0))
                    && let Some(preimage) = state_after.get_preimage(hash_value)
                {
                    preimages.push((diff.address, preimage));
                }
            }
        }
        preimages
    };

    let batch_prover_input = compute_batch_prover_input(
        blocks,
        proving_version,
        pubdata_mode,
        multichain_root,
        sl_chain_id,
        &batch_info,
        &blob_sidecar,
        zisk_chain_config,
        batch_tree_start,
        account_preimages_after,
    )?;

    // Sanity check: all blocks in the batch should have the same protocol version
    for (_, replay_record, _, _) in blocks.iter().skip(1) {
        anyhow::ensure!(
            replay_record.protocol_version == protocol_version,
            "mismatched protocol versions in batch: expected {}, found {}; blocks: {:?}",
            protocol_version,
            replay_record.protocol_version,
            blocks,
        );
    }

    // Detect any `SetSLChainId` system transaction across all blocks in the batch.
    // Excludes the sentinel value `u64::MAX` which is used during protocol upgrades and is
    // unrelated to gateway migrations.
    // Detect any `SetSLChainId` system transaction across all blocks in the batch.
    // Excludes the sentinel value `u64::MAX` which is used during protocol upgrades and is
    // unrelated to gateway migrations.
    let set_sl_chain_id_migration_number = blocks.iter().find_map(|(_, replay_record, _, _)| {
        replay_record.transactions.iter().find_map(|tx| {
            if let ZkEnvelope::System(system_tx) = tx.envelope()
                && let SystemTxType::SetSLChainId(_, n) = system_tx.system_subtype()
                && *n != u64::MAX
            {
                Some(*n)
            } else {
                None
            }
        })
    });

    let batch_envelope = BatchEnvelope::new(
        BatchMetadata {
            previous_stored_batch_info: prev_batch_info,
            batch_info,
            chain_address: chain_address_sl,
            blob_sidecar,
            first_block_number: block_number_from,
            last_block_number: block_number_to,
            last_block_hash: Some(last_block_hash),
            pubdata_mode,
            tx_count: blocks
                .iter()
                .map(|(block_output, _, _, _)| block_output.tx_results.len())
                .sum(),
            computational_native_used: Some(
                blocks
                    .iter()
                    .map(|(block_output, _, _, _)| block_output.computational_native_used)
                    .sum(),
            ),
            logs,
            messages,
            multichain_root,
            set_sl_chain_id_migration_number,
        },
        batch_prover_input,
    )
    .with_stage(BatchExecutionStage::BatchSealed);

    Ok(batch_envelope)
}

#[allow(clippy::too_many_arguments)]
fn compute_batch_prover_input(
    blocks: &[(
        BlockOutput,
        ReplayRecord,
        zksync_os_merkle_tree::TreeBatchOutput,
        ProverInput,
    )],
    proving_version: ProvingVersion,
    pubdata_mode: PubdataMode,
    multichain_root: alloy::primitives::B256,
    sl_chain_id: u64,
    batch_info: &PendingBatchInfo,
    blob_sidecar: &Option<BlobTransactionSidecar>,
    zisk_chain_config: ZiskChainConfig,
    batch_tree_start: Option<zksync_os_merkle_tree::MerkleTreeVersion>,
    account_preimages_after: Vec<(Address, Vec<u8>)>,
) -> anyhow::Result<ProverInput> {
    use zk_os_forward_system::run::generate_batch_proof_input;
    use zk_os_forward_system_prev::run::generate_batch_proof_input as generate_batch_proof_input_prev;

    if blocks.iter().any(|(_, _, _, pi)| pi.is_fake()) {
        return Ok(ProverInput::Fake);
    }

    // Generate airbender batch witness (primary proof system)
    let da_scheme_u8 = pubdata_mode.da_commitment_scheme() as u8;
    let block_witnesses: Vec<&[u32]> = blocks
        .iter()
        .map(|(_, _, _, pi)| pi.unwrap_real())
        .collect();
    let block_pubdata: Vec<&[u8]> = blocks
        .iter()
        .map(|(bo, _, _, _)| bo.pubdata.as_slice())
        .collect();

    let witness = match proving_version {
        ProvingVersion::V1 | ProvingVersion::V2 | ProvingVersion::V3
        | ProvingVersion::V4 | ProvingVersion::V5 => {
            panic!("sealing batch with prover version v1-v5 is not supported");
        }
        ProvingVersion::V6 => {
            // TODO: in the long-term we should generate proof input per batch
            let da = da_scheme_u8
                .try_into()
                .map_err(|_| anyhow::anyhow!("Failed to convert DA commitment scheme"))?;
            generate_batch_proof_input_prev(block_witnesses, da, block_pubdata)
        }
        ProvingVersion::V7 | ProvingVersion::ZiskV1 => {
            // TODO: in the long-term we should generate proof input per batch
            let da = da_scheme_u8
                .try_into()
                .map_err(|_| anyhow::anyhow!("Failed to convert DA commitment scheme"))?;
            generate_batch_proof_input(block_witnesses, da, block_pubdata)
        }
    };

    // If any block carries ZiSK data, assemble the batch-level ZiSK BatchInput.
    let zisk_data = if blocks.iter().any(|(_, _, _, pi)| pi.zisk_data().is_some()) {
        Some(assemble_zisk_batch(
            blocks,
            pubdata_mode,
            multichain_root,
            sl_chain_id,
            batch_info,
            blob_sidecar,
            zisk_chain_config,
            batch_tree_start,
            account_preimages_after,
        )?)
    } else {
        None
    };

    Ok(ProverInput::Real { witness, zisk_data })
}

/// Assemble per-block ZiSK data into a single batch-level BatchInput.
#[allow(clippy::too_many_arguments)]
fn assemble_zisk_batch(
    blocks: &[(
        zksync_os_types::BlockOutput,
        zksync_os_storage_api::ReplayRecord,
        zksync_os_merkle_tree::TreeBatchOutput,
        ProverInput,
    )],
    pubdata_mode: PubdataMode,
    multichain_root: alloy::primitives::B256,
    sl_chain_id: u64,
    batch_info: &PendingBatchInfo,
    blob_sidecar: &Option<BlobTransactionSidecar>,
    zisk_chain_config: ZiskChainConfig,
    batch_tree_start: Option<zksync_os_merkle_tree::MerkleTreeVersion>,
    account_preimages_after: Vec<(Address, Vec<u8>)>,
) -> anyhow::Result<Vec<u8>> {
    use blake2::{Blake2s256, Digest};
    use crate::prover_input_generator::zisk_input_builder::ZiskBlockData;
    use zksync_os_zisk_lib::types::*;

    let mut block_data_vec = Vec::with_capacity(blocks.len());
    for (_, _, _, pi) in blocks {
        let bytes = pi.zisk_data()
            .ok_or_else(|| anyhow::anyhow!("ZiSK data missing from ProverInput"))?;
        let data: ZiskBlockData = bincode1::deserialize(bytes)
            .map_err(|e| anyhow::anyhow!("failed to deserialize ZiSK BlockData: {e}"))?;
        block_data_vec.push(data);
    }

    let first = &block_data_vec[0];
    let first_replay = &blocks.first().unwrap().1;
    let first_ctx = &first_replay.block_context;
    let da_scheme = pubdata_mode.da_commitment_scheme() as u8;

    let pubdata: Vec<u8> = blocks
        .iter()
        .flat_map(|(bo, _, _, _)| bo.pubdata.iter().copied())
        .collect();

    // Compute block_hashes_blake for the state BEFORE the first block in this batch.
    // This must match the state commitment preimage used by the server/L1:
    //   Blake2s(previous_255_block_hashes || current_block_hash)
    // where "previous_255" are hashes of the 255 blocks before the "current" block,
    // and "current_block_hash" is the hash of the block that produced this state.
    //
    // The block_context.block_hashes array has block_hashes[N] = hash of block (current - N - 1).
    // For the "before" state at block B, the "current block" that produced this state is block B-1.
    // The genesis state uses: Blake2s(255 * [0; 32] || genesis_header_hash).
    //
    // We need to reconstruct the same ordering: the first 255 entries are the hashes
    // BEFORE the previous block (indices 1..255 of block_hashes), and the last entry
    // is block_hashes[0] (the previous block's hash, which IS the "current" for the state).
    //
    // However, block_hashes_for_first_block() puts genesis at index 255, not index 0.
    // So for block 1, block_hashes[0] = 0 and block_hashes[255] = genesis_hash.
    // The state commitment uses: Blake2s(0, 0, ..., 0, genesis_hash) with genesis_hash LAST.
    // We need to match that: hash all 256 entries in order [0, 1, 2, ..., 255].
    let block_hashes_blake_before = {
        let mut hasher = Blake2s256::new();
        for hash in &first_ctx.block_hashes.0 {
            hasher.update(hash.to_be_bytes::<32>());
        }
        alloy::primitives::B256::from_slice(&hasher.finalize())
    };

    // Use the LAST block's context for previous_block_hashes — this feeds into
    // block_hashes_blake_after in the executor, which must match the server's
    // state commitment that uses last_block_context.block_hashes.0[1..].
    let last_replay = &blocks.last().unwrap().1;
    let last_ctx = &last_replay.block_context;
    let previous_block_hashes: Vec<alloy::primitives::B256> = last_ctx
        .block_hashes
        .0[1..]
        .iter()
        .map(|h| alloy::primitives::B256::from(h.to_be_bytes::<32>()))
        .collect();

    let upgrade_tx_hash = batch_info
        .upgrade_tx_hash
        .unwrap_or(alloy::primitives::B256::ZERO);

    let spec_id = match crate::prover_input_generator::zisk_input_builder::spec_id_from_execution_version(
        first_ctx.execution_version,
    ) {
        zksync_os_revm::ZkSpecId::AtlasV1 => 0u8,
        zksync_os_revm::ZkSpecId::AtlasV2 => 1u8,
        zksync_os_revm::ZkSpecId::AtlasV3 => 2u8,
    };

    let batch_input = BatchInput {
        chain_id: first_ctx.chain_id,
        spec_id,
        protocol_version_minor: first_replay.protocol_version.minor as u32,
        batch_meta: BatchMeta {
            tree_root_before: first.tree_root_before,
            leaf_count_before: first.leaf_count_before,
            block_number_before: first.block_number_before,
            last_block_timestamp_before: first.previous_block_timestamp,
            block_hashes_blake_before,
            previous_block_hashes,
            upgrade_tx_hash,
            da_commitment_scheme: da_scheme,
            pubdata,
            multichain_root,
            sl_chain_id,
            blob_versioned_hashes: blob_sidecar
                .as_ref()
                .map(|sidecar| {
                    sidecar.commitments.iter().map(|commitment| {
                        alloy::eips::eip4844::kzg_to_versioned_hash(commitment.as_slice())
                    }).collect()
                })
                .unwrap_or_default(),
            tree_update: build_batch_tree_update(blocks, batch_tree_start)?,
            account_preimages_after,
            fri_proof_verification_enabled: zisk_chain_config.fri_proof_verification_enabled,
            max_tx_gas_limit: zisk_chain_config.max_tx_gas_limit,
        },
        blocks: block_data_vec
            .iter()
            .map(|d| {
                let mut bi = d.block_input.clone();
                bi.expected_tree_root = d.tree_root_before;
                bi
            })
            .collect(),
        bytecodes: {
            let mut seen = std::collections::HashSet::new();
            let mut all_bytecodes = Vec::new();
            for d in &block_data_vec {
                for (hash, code) in &d.bytecodes {
                    if seen.insert(*hash) {
                        all_bytecodes.push((*hash, code.clone()));
                    }
                }
            }
            all_bytecodes
        },
    };

    let serialized = bincode1::serialize(&batch_input).expect("failed to serialize ZiSK BatchInput");

    // If ZISK_DUMP_DIR is set, write the BatchInput to disk for external proving.
    if let Ok(dump_dir) = std::env::var("ZISK_DUMP_DIR") {
        let path = std::path::Path::new(&dump_dir);
        let _ = std::fs::create_dir_all(path);
        let batch_num = batch_info.commit_info.batch_number;
        let file_path = path.join(format!("batch_{batch_num}_zisk.bin"));
        // Write in ZiSK stdin format: [len:u64_LE][bincode][padding_to_8]
        let len = serialized.len() as u64;
        let mut buf = Vec::with_capacity(8 + serialized.len() + 8);
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&serialized);
        let total = 8 + serialized.len();
        let padding = (8 - (total % 8)) % 8;
        buf.extend(std::iter::repeat_n(0u8, padding));
        match std::fs::write(&file_path, &buf) {
            Ok(()) => tracing::info!(
                "ZiSK BatchInput dumped: {} ({} bytes, ZiSK stdin format)",
                file_path.display(),
                buf.len()
            ),
            Err(e) => tracing::warn!("Failed to dump ZiSK data: {e}"),
        }

        // Run native executor and dump the commitment for verification
        match zksync_os_zisk_lib::executor::execute_and_commit_from_bincode(&serialized) {
            Ok((_output, commitment)) => {
                let commitment_path = path.join(format!("batch_{batch_num}_commitment.hex"));
                let _ = std::fs::write(&commitment_path, format!("{commitment}"));
                tracing::info!(
                    batch_num,
                    commitment = %commitment,
                    "ZiSK native commitment computed"
                );
            }
            Err(e) => {
                tracing::warn!(batch_num, error = %e, "ZiSK native execution failed");
            }
        }
    }

    Ok(serialized)
}

/// Build a batch-level tree update from the batch-start tree view: pre-state
/// leaf proofs (touched leaves + anchors) and old-root sibling hashes. The
/// guest recomputes the new root from that authenticated pre-state and the
/// REVM-verified writes alone — no post-state data is shipped at all.
fn build_batch_tree_update(
    blocks: &[(
        zksync_os_types::BlockOutput,
        zksync_os_storage_api::ReplayRecord,
        zksync_os_merkle_tree::TreeBatchOutput,
        ProverInput,
    )],
    batch_tree_start: Option<zksync_os_merkle_tree::MerkleTreeVersion>,
) -> anyhow::Result<Option<zksync_os_zisk_lib::merkle::BatchTreeUpdate>> {
    // Collect all storage writes across all blocks, deduplicate (last-writer-wins per key)
    let mut combined_writes: Vec<zksync_os_interface::types::StorageWrite> = Vec::new();
    let mut seen_keys: std::collections::HashMap<alloy::primitives::B256, usize> =
        std::collections::HashMap::new();
    for (block_output, _, _, _) in blocks {
        for write in &block_output.storage_writes {
            let key = alloy::primitives::B256::from(write.key);
            if let Some(&pos) = seen_keys.get(&key) {
                combined_writes[pos] = write.clone();
            } else {
                seen_keys.insert(key, combined_writes.len());
                combined_writes.push(write.clone());
            }
        }
    }

    if combined_writes.is_empty() {
        return Ok(None);
    }

    let Some(mut tree_start) = batch_tree_start else {
        tracing::warn!("batch tree view not available, falling back to None tree_update");
        return Ok(None);
    };

    let leaf_count = tree_start.root_info()?.1;

    Ok(Some(
        crate::prover_input_generator::zisk_input_builder::build_tree_update(
            &mut tree_start,
            &combined_writes,
            leaf_count,
        ),
    ))
}
