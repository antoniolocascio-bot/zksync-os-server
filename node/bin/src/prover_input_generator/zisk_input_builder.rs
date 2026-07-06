//! Converts server-side block data into a ZiSK `BlockInput` with merkle proofs.
//!
//! Runs a pre-execution pass with REVM to discover all storage reads, then
//! extracts merkle proofs for every accessed slot from the server's merkle tree.

use alloy::consensus::Transaction;
use alloy::eips::Encodable2718;
use alloy::primitives::{Address, B256, Bytes, U256};
use revm::database::CacheDB;
use revm::database_interface::DBErrorMarker;
use revm::primitives::{TxKind, KECCAK_EMPTY};
use revm::state::{AccountInfo, Bytecode};
use revm::{DatabaseRef, ExecuteCommitEvm};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use zk_ee::utils::Bytes32;
use zk_os_forward_system::run::ReadStorageTree;
use zksync_os_interface::traits::{PreimageSource, ReadStorage};
use zksync_os_types::BlockOutput;
use zksync_os_merkle_tree::{MerkleTreeVersion, RocksDBWrapper};
use zksync_os_revm::transaction::abstraction::ZKsyncTxBuilder;
use zksync_os_revm::{DefaultZk, ZKsyncTx, ZkBuilder, ZkContext, ZkSpecId};
use zksync_os_storage_api::{ReadStateHistory, ReplayRecord, ViewState};
use zksync_os_types::{ExecutionVersion, ZkEnvelope, ZkTransaction};

use serde::{Deserialize, Serialize};
use zksync_os_zisk_lib::merkle::{
    self as zisk_merkle, BatchTreeUpdate, NeighborProofEntry, SlotProofEntry, StorageProof,
    TreeLeaf, WriteOp, TREE_DEPTH,
};
use zksync_os_zisk_lib::types::*;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Per-block ZiSK data carried through the pipeline.
/// Account preimages and per-slot storage proofs extracted from the tree.
type AccountProofs = (Vec<(Address, Vec<u8>)>, Vec<(B256, StorageProof)>);

/// Read keys, read accounts, storage reads and resolved preimages discovered
/// by the pre-execution pass.
type PreExecutionReads = (
    HashSet<B256>,
    HashSet<Address>,
    Vec<(Address, U256, U256)>,
    Vec<(B256, Vec<u8>)>,
);

/// Accounts, keccak-keyed bytecodes, and blake2s-keyed full preimages
/// discovered while loading state for the pre-execution pass.
type LoadedAccountsAndBytecodes = (
    HashMap<Address, AccountInfo>,
    HashMap<B256, Bytecode>,
    Vec<(B256, Vec<u8>)>,
);

#[derive(Serialize, Deserialize, Clone)]
pub struct ZiskBlockData {
    pub block_input: BlockInput,
    pub tree_root_before: B256,
    pub leaf_count_before: u64,
    pub block_number_before: u64,
    pub previous_block_timestamp: u64,
    pub tree_update: Option<BatchTreeUpdate>,
    /// All bytecodes needed for this block's execution, keyed by keccak256 hash.
    pub bytecodes: Vec<(B256, Vec<u8>)>,
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/// Build per-block ZiSK data from server block data, including merkle proofs.
pub fn build_block_data<ReadState: ReadStateHistory>(
    block_output: &BlockOutput,
    replay_record: &ReplayRecord,
    tree_view: &MerkleTreeVersion<RocksDBWrapper>,
    tree_view_after: &MerkleTreeVersion<RocksDBWrapper>,
    read_state: &ReadState,
) -> anyhow::Result<ZiskBlockData> {
    let ctx = &replay_record.block_context;
    let block_number = ctx.block_number;
    let mut tree = tree_view.clone();
    // Get leaf_count early (stable across versions), but defer root_hash until
    // after proof extraction to avoid race with concurrent tree updates.
    // The underlying RocksDB is shared via Arc; another thread may apply new
    // blocks between root_info() and merkle_proof() calls.
    let (_initial_root, leaf_count) = tree_view.root_info()?;
    let basefee: u64 = ctx.eip1559_basefee.try_into().unwrap_or(u64::MAX);
        // Use the block header's prevrandao value from the BlockOutput (computed by Airbender),
    // not the BlockContext's mix_hash (which may be 0). The Airbender VM sets
    // the header's mix_hash to the actual prevrandao value.
    let prev_randao = block_output.header.mix_hash;
    let spec_id = spec_id_from_execution_version(ctx.execution_version);

    let transactions = convert_all_txs(&replay_record.transactions, block_output);

    // Phase 1: collect addresses + pre-execute to discover storage reads
    let mut initial_addrs = collect_touched_addresses(replay_record, block_output, ctx.coinbase);

    // For upgrade blocks, include all known system/user contract addresses.
    // The genesis upgrade accesses many addresses that aren't in storage_writes/account_diffs.
    if transactions.iter().any(|tx| matches!(tx.auth, TxAuth::Upgrade { .. })) {
        for i in 0..=0x0c {
            let addr: Address = format!("0x{:040x}", 0x10000u64 + i).parse().unwrap();
            if !initial_addrs.contains(&addr) {
                initial_addrs.push(addr);
            }
        }
    }
    let mut state_view = read_state.state_view_at(block_number - 1)?;
    // Create a state view with published preimages as overrides.
    // This resolves system contract bytecodes for genesis/upgrade blocks where
    // preimages are published during execution but aren't in the state view at block N-1.
    let all_preimages: Vec<(B256, Vec<u8>)> = block_output.published_preimages
        .iter()
        .chain(&replay_record.force_preimages)
        .cloned()
        .collect();
    let mut state_with_preimages = zksync_os_storage_api::OverriddenStateView::with_preimages(
        state_view.clone(),
        &all_preimages,
    );

    let (mut accounts_map, mut bytecodes_map, mut bytecodes_out) =
        load_accounts_and_bytecodes(&initial_addrs, &mut state_with_preimages, block_output, replay_record);

    // For upgrade txs: pre-create accounts that are force-deployed in this block.
    let has_upgrade = transactions.iter().any(|tx| matches!(tx.auth, TxAuth::Upgrade { .. }));
    let mut bytecodes_extra = Vec::new();
    if has_upgrade {
        pre_create_upgrade_accounts(
            block_output, block_number, read_state, &mut state_view,
            &mut accounts_map, &mut bytecodes_map, &mut bytecodes_out,
            &mut bytecodes_extra,
        )?;

        // Scan upgrade tx calldata for bytecode hashes and resolve from preimage DB.
        // The inner calldata contains ABI-encoded ForceDeployment structs with bytecodeHash.
        // Scan ALL 32-byte aligned chunks and try each as a preimage key.
        let mut state_for_scan = read_state.state_view_at(block_number)?;
        let mut scanned = HashSet::new();
        let mut calldata_resolved = 0;
        for tx in &transactions {
            let abi_data = match &tx.auth {
                TxAuth::Upgrade { abi_encoded, .. } => abi_encoded,
                _ => continue,
            };
            // Extract calldata from the ABI-encoded L2CanonicalTransaction.
            // Field 14 is the data offset (relative to outer offset 32).
            let data_rel_offset: usize = alloy::primitives::U256::from_be_slice(&abi_data[32 + 14*32..32 + 15*32]).to();
            let data_abs_offset = 32 + data_rel_offset;
            let data_len: usize = alloy::primitives::U256::from_be_slice(&abi_data[data_abs_offset..data_abs_offset + 32]).to();
            let data = &abi_data[data_abs_offset + 32..data_abs_offset + 32 + data_len];
            // Scan at every byte offset, not just 32-byte aligned,
            // because nested ABI encoding places hashes at arbitrary offsets.
            for offset in 0..data.len() {
                if offset + 32 > data.len() { break; }
                let hash = B256::from_slice(&data[offset..offset + 32]);
                if hash.is_zero() || scanned.contains(&hash) || bytecodes_map.contains_key(&hash) { continue; }
                scanned.insert(hash);
                if let Some(preimage) = state_for_scan.get_preimage(hash)
                    && preimage.len() > 100
                {
                    {
                        tracing::info!(
                            hash = %hash, preimage_len = preimage.len(),
                            "resolved bytecode from upgrade tx calldata scan"
                        );
                        let bytecode = Bytecode::new_raw(Bytes::copy_from_slice(&preimage));
                        bytecodes_map.insert(hash, bytecode);
                        bytecodes_extra.push((hash, preimage));
                        calldata_resolved += 1;
                    }
                }
            }
        }
        if calldata_resolved > 0 {
            tracing::info!(calldata_resolved, scanned = scanned.len(), "calldata bytecode scan results");
        }
    }

    let mut storage_prestate = load_storage_prestate(&block_output.storage_writes, &mut state_view);

    let mut all_addrs = initial_addrs;
    let mut seen_addrs: HashSet<Address> = all_addrs.iter().copied().collect();
    let mut all_storage_read_keys = HashSet::new();
    let mut all_storage_reads: Vec<(Address, U256, U256)> = Vec::new();

    // Run pre-execution even for upgrade blocks to discover storage reads.
    // The REVM execution may fail or produce incorrect writes for upgrade txs
    // (since bootloader-level operations aren't reproduced), but the storage
    // reads discovered are needed for merkle proofs.
    let max_iterations = if has_upgrade { 5 } else { 1 };

    for iteration in 0..max_iterations {
        // Use post-execution state for upgrade blocks so the preimage DB has all
        // bytecodes that were deployed during the upgrade. For non-upgrade blocks,
        // use pre-execution state (block_number - 1).
        let state_view_for_pre = if has_upgrade {
            read_state.state_view_at(block_number)?
        } else {
            read_state.state_view_at(block_number - 1)?
        };
        let (read_keys, extra_addrs, storage_reads, pre_exec_preimages) = pre_execute_for_reads(
            ctx, spec_id, basefee, prev_randao, &transactions, block_output,
            &accounts_map, &storage_prestate, &bytecodes_map,
            state_view_for_pre,
        );

        // Merge bytecodes resolved from preimage DB during pre-execution.
        if !pre_exec_preimages.is_empty() {
            tracing::info!(count = pre_exec_preimages.len(), "pre-execution resolved preimages from DB");
        }
        for (hash, preimage) in pre_exec_preimages {
            bytecodes_map
                .entry(hash)
                .or_insert_with(|| Bytecode::new_raw(Bytes::copy_from_slice(&preimage)));
            bytecodes_extra.push((hash, preimage));
        }

        let new_keys = read_keys.difference(&all_storage_read_keys).count();
        tracing::info!(
            iteration, total_read_keys = read_keys.len(), new_keys,
            extra_addrs = extra_addrs.len(), storage_reads = storage_reads.len(),
            bytecodes_available = bytecodes_map.len(),
            "pre-execution discovery results",
        );
        all_storage_read_keys.extend(read_keys);

        // Merge new storage reads into prestate so next iteration has them
        let mut new_reads = 0;
        for (addr, slot, val) in &storage_reads {
            if storage_prestate.insert((*addr, *slot), *val).is_none() {
                new_reads += 1;
            }
        }
        all_storage_reads.extend(storage_reads);

        // Load newly discovered accounts — try pre-execution state first, then post-execution.
        let mut state_view_reload = read_state.state_view_at(block_number - 1)?;
        let mut state_after_reload = if has_upgrade { Some(read_state.state_view_at(block_number)?) } else { None };
        let mut new_accounts = 0;
        for addr in extra_addrs {
            if seen_addrs.insert(addr) {
                all_addrs.push(addr);
                new_accounts += 1;
                // Try pre-execution state first
                let mut resolved = false;
                if let Some(props) = state_view_reload.get_account(addr) {
                    let preimage_hash = B256::from(props.bytecode_hash.as_u8_array());
                    let observable_hash = B256::from(props.observable_bytecode_hash.as_u8_array());
                    let effective = if observable_hash.is_zero() {
                        if props.nonce == 0 && props.balance == U256::ZERO { B256::ZERO } else { KECCAK_EMPTY }
                    } else { observable_hash };
                    accounts_map.insert(addr, AccountInfo {
                        nonce: props.nonce, balance: props.balance, code_hash: effective,
                        code: None, account_id: None,
                    });
                    if !preimage_hash.is_zero()
                        && !observable_hash.is_zero()
                        && let Some(padded_code) = state_view_reload.get_preimage(preimage_hash)
                    {
                        let raw_len = props.unpadded_code_len as usize;
                        let raw_code = if raw_len > 0 && raw_len <= padded_code.len() {
                            &padded_code[..raw_len]
                        } else {
                            &padded_code[..]
                        };
                        if let std::collections::hash_map::Entry::Vacant(entry) =
                            bytecodes_map.entry(observable_hash)
                        {
                            bytecodes_out.push((observable_hash, raw_code.to_vec()));
                            entry.insert(Bytecode::new_raw(Bytes::copy_from_slice(raw_code)));
                        }
                        resolved = true;
                    }
                }
                // If pre-execution state had observable_hash=0, try post-execution state
                if !resolved
                    && let Some(ref mut state_after) = state_after_reload
                    && let Some(props) = state_after.get_account(addr)
                {
                    let obs_hash = B256::from(props.observable_bytecode_hash.as_u8_array());
                    let pre_hash = B256::from(props.bytecode_hash.as_u8_array());
                    if !obs_hash.is_zero()
                        && !pre_hash.is_zero()
                        && let Some(full_preimage) = state_after.get_preimage(pre_hash)
                    {
                        let raw_len = props.unpadded_code_len as usize;
                        let raw_code = if raw_len > 0 && raw_len <= full_preimage.len() {
                            &full_preimage[..raw_len]
                        } else {
                            &full_preimage[..]
                        };
                        if let std::collections::hash_map::Entry::Vacant(entry) =
                            bytecodes_map.entry(obs_hash)
                        {
                            bytecodes_out.push((obs_hash, raw_code.to_vec()));
                            entry.insert(Bytecode::new_raw(Bytes::copy_from_slice(raw_code)));
                        }
                        accounts_map.insert(addr, AccountInfo {
                            nonce: props.nonce, balance: props.balance, code_hash: obs_hash,
                            code: None, account_id: None,
                        });
                        // Store full preimage (code+artifacts) under blake2s hash
                        // for deployer precompile.
                        bytecodes_extra.push((pre_hash, full_preimage));
                    }
                }
            }
        }

        tracing::debug!(
            iteration, new_keys, new_reads, new_accounts,
            "Pre-execution iteration"
        );

        // Stable if no new state discovered
        if new_keys == 0 && new_reads == 0 && new_accounts == 0 {
            break;
        }
    }
    // For upgrade txs: add the proxy's implementation slot read to the proof set.
    // The upgrade tx reads the ComplexUpgrader's ERC1967 implementation slot.
    // The ZiSK executor needs a merkle proof for this read.
    if has_upgrade {
        use crate::prover_api::zisk_proof_constants::{COMPLEX_UPGRADER_ADDRESS, ERC1967_IMPLEMENTATION_SLOT};
        let proxy_addr: Address = COMPLEX_UPGRADER_ADDRESS.parse().expect("invalid upgrader address constant");
        let impl_slot = B256::from_slice(
            &alloy::primitives::hex::decode(ERC1967_IMPLEMENTATION_SLOT)
                .expect("invalid ERC1967 slot constant"),
        );
        let flat_key = zisk_merkle::derive_flat_storage_key(&proxy_addr.into_array(), &impl_slot);
        all_storage_read_keys.insert(flat_key);
    }

    let mut state_view = read_state.state_view_at(block_number - 1)?;
    let mut state_view_post = Some(read_state.state_view_at(block_number)?);
    let storage_read_keys = all_storage_read_keys;
    let _storage_reads = all_storage_reads;

    // Phase 2: extract merkle proofs for all accessed keys
    let (account_preimages, mut storage_proofs) =
        extract_account_proofs(&all_addrs, &mut tree, &mut state_view, &mut state_view_post);

    let mut proven_flat_keys: HashSet<B256> = storage_proofs.iter().map(|(k, _)| *k).collect();

    let _storage_out = extract_storage_write_proofs(
        &block_output.storage_writes, &storage_prestate, &mut tree, &mut proven_flat_keys, &mut storage_proofs,
    );

    extract_storage_read_proofs(&storage_read_keys, &mut tree, &mut proven_flat_keys, &mut storage_proofs);

    // Compute actual tree root from extracted proofs. All proofs were extracted from
    // the same tree version (even if RocksDB was updated concurrently), so they're
    // internally consistent. Use the first proof's root recovery as the authoritative root.
    let root_hash = if let Some((key, proof)) = storage_proofs.first() {
        match proof.verify(key) {
            Ok((root, _)) => root,
            Err(_) => tree_view.root_info()?.0,  // fallback
        }
    } else {
        tree_view.root_info()?.0  // no proofs, use tree directly
    };

    // Phase 3: tree update
    let tree_update = if !block_output.storage_writes.is_empty() {
        let mut tree_end = tree_view_after.clone();
        Some(build_tree_update(&mut tree, &mut tree_end, &block_output.storage_writes, leaf_count))
    } else {
        None
    };

    // Phase 4: assemble
    let block_hashes = extract_block_hashes(&ctx.block_hashes, block_number);

    let l2_to_l1_logs = extract_l2_to_l1_logs(block_output);

    Ok(ZiskBlockData {
        block_input: BlockInput {
            number: block_number,
            timestamp: ctx.timestamp,
            base_fee: basefee,
            gas_limit: ctx.gas_limit,
            coinbase: ctx.coinbase,
            prev_randao,
            block_header_hash: B256::ZERO,
            storage_proofs,
            account_preimages,
            transactions,
            block_hashes,
            l2_to_l1_logs,
            expected_tree_root: root_hash,
        },
        tree_root_before: root_hash,
        leaf_count_before: leaf_count,
        block_number_before: block_number.saturating_sub(1),
        previous_block_timestamp: replay_record.previous_block_timestamp,
        tree_update,
        bytecodes: {
            // All bytecodes keyed by keccak256. Force-deploy preimages are stored
            // in the preimage DB by blake2s — re-key them by keccak256 here.
            let mut all = bytecodes_out;
            let mut seen: std::collections::HashSet<B256> =
                all.iter().map(|(h, _)| *h).collect();
            for (_blake2s_hash, code) in block_output.published_preimages.iter()
                .chain(&replay_record.force_preimages)
                .chain(bytecodes_extra.iter())
            {
                let keccak_hash = alloy::primitives::keccak256(code);
                if seen.insert(keccak_hash) {
                    all.push((keccak_hash, code.clone()));
                }
            }
            all
        },
    })
}

pub fn spec_id_from_execution_version(version: u32) -> ZkSpecId {
    match ExecutionVersion::try_from(version) {
        Ok(ExecutionVersion::V1 | ExecutionVersion::V2 | ExecutionVersion::V3) => ZkSpecId::AtlasV1,
        _ => ZkSpecId::AtlasV2,
    }
}

// ---------------------------------------------------------------------------
// Phase 1: Address collection
// ---------------------------------------------------------------------------

fn collect_touched_addresses(
    replay_record: &ReplayRecord,
    block_output: &BlockOutput,
    coinbase: Address,
) -> Vec<Address> {
    let mut addrs = Vec::new();
    let mut seen = HashSet::new();
    let push = |addr: Address, seen: &mut HashSet<Address>, addrs: &mut Vec<Address>| {
        if seen.insert(addr) { addrs.push(addr); }
    };
    for tx in &replay_record.transactions {
        push(tx.signer(), &mut seen, &mut addrs);
        if let Some(to) = tx.to() { push(to, &mut seen, &mut addrs); }
    }
    push(coinbase, &mut seen, &mut addrs);
    // REVM calls basic_ref on precompile addresses during CALL (for balance checks),
    // even though the precompile intercepts execution later. Include them explicitly.
    for sys in [0x8006u64, 0x8008, 0x800a] {
        let mut bytes = [0u8; 20];
        bytes[18..].copy_from_slice(&(sys as u16).to_be_bytes());
        push(Address::from(bytes), &mut seen, &mut addrs);
    }
    for diff in &block_output.account_diffs {
        push(diff.address, &mut seen, &mut addrs);
    }
    // Include all addresses that have storage writes — these are system contracts
    // (ContractDeployer, NonceHolder, AccountCodeStorage, etc.) that the upgrade
    // transaction modifies. REVM needs their bytecodes to execute the call chain.
    for write in &block_output.storage_writes {
        push(write.account, &mut seen, &mut addrs);
    }
    addrs
}

fn load_accounts_and_bytecodes<S: ViewState>(
    addrs: &[Address],
    state_view: &mut S,
    block_output: &BlockOutput,
    replay_record: &ReplayRecord,
) -> LoadedAccountsAndBytecodes {
    let mut accounts = HashMap::new();
    let mut bytecodes_map = HashMap::new();
    let mut bytecodes_out = Vec::new();
    let mut seen_hashes = HashSet::new();

    // Build a lookup for force_preimages (system contract bytecodes from upgrade tx)
    let force_preimage_map: HashMap<B256, &Vec<u8>> = block_output.published_preimages
        .iter()
        .chain(&replay_record.force_preimages)
        .map(|(h, c)| (*h, c))
        .collect();
    if !force_preimage_map.is_empty() {
        tracing::debug!(
            count = force_preimage_map.len(),
            "Force preimages available for bytecode resolution"
        );
    }

    for &addr in addrs {
        if let Some(props) = state_view.get_account(addr) {
            // AccountProperties has two hashes:
            // - bytecode_hash (blake2s256 of padded code) — used for preimage DB lookup
            // - observable_bytecode_hash (keccak256 of raw code) — the EVM-visible code_hash
            // REVM uses keccak256 as code_hash, so we use observable_bytecode_hash.
            let observable_hash = B256::from(props.observable_bytecode_hash.as_u8_array());
            let preimage_hash = B256::from(props.bytecode_hash.as_u8_array());

            let mut effective = if observable_hash.is_zero() {
                if props.nonce == 0 && props.balance == U256::ZERO { B256::ZERO } else { KECCAK_EMPTY }
            } else {
                observable_hash // keccak256 of raw code — correct for REVM
            };
            // Load bytecode: preimage DB stores (blake2s256(padded), padded_code).
            // REVM needs (keccak256(raw), raw_code). Extract raw code by truncating
            // padding using unpadded_code_len from AccountProperties.
            if !preimage_hash.is_zero() {
                if !observable_hash.is_zero() {
                    if let Some(padded_code) = state_view.get_preimage(preimage_hash) {
                        let raw_len = props.unpadded_code_len as usize;
                        let raw_code = if raw_len > 0 && raw_len <= padded_code.len() {
                            &padded_code[..raw_len]
                        } else {
                            &padded_code
                        };
                        if seen_hashes.insert(preimage_hash) {
                            bytecodes_out.push((observable_hash, raw_code.to_vec()));
                            bytecodes_map.insert(observable_hash, Bytecode::new_raw(Bytes::copy_from_slice(raw_code)));
                        }
                    }
                } else if let Some(code) = force_preimage_map.get(&preimage_hash) {
                    // Account has bytecode_hash (blake2s) but no observable_bytecode_hash (keccak).
                    // This happens for system contracts during genesis/upgrade: they're deployed via
                    // force_preimages but haven't had their observable hash set yet.
                    // Resolve the bytecode from force_preimages and compute keccak256 as code_hash.
                    let keccak_hash = alloy::primitives::keccak256(code);
                    effective = keccak_hash;
                    if seen_hashes.insert(preimage_hash) {
                        bytecodes_out.push((keccak_hash, code.to_vec()));
                        bytecodes_map.insert(keccak_hash, Bytecode::new_raw(Bytes::copy_from_slice(code)));
                    }
                    tracing::debug!(
                        addr = %addr,
                        blake2s_hash = %preimage_hash,
                        keccak_hash = %keccak_hash,
                        code_len = code.len(),
                        "resolved force_preimage bytecode for account with zero observable_hash"
                    );
                }
            }
            accounts.insert(addr, AccountInfo {
                nonce: props.nonce, balance: props.balance, code_hash: effective,
                code: None, account_id: None,
            });
        }
    }
    // Load force_preimages (system contract bytecodes from upgrade/genesis) into bytecodes.
    for (hash, code) in block_output.published_preimages.iter().chain(&replay_record.force_preimages) {
        let keccak_hash = alloy::primitives::keccak256(code);
        if seen_hashes.insert(*hash) {
            bytecodes_out.push((keccak_hash, code.clone()));
            let bytecode = Bytecode::new_raw(Bytes::copy_from_slice(code));
            bytecodes_map.insert(keccak_hash, bytecode.clone());
            // Also store under original blake2s hash for deployer precompile / pre-execution.
            bytecodes_map.insert(*hash, bytecode);
        }
    }
    (accounts, bytecodes_map, bytecodes_out)
}

fn load_storage_prestate(
    writes: &[zksync_os_interface::types::StorageWrite],
    state_view: &mut impl ReadStorage,
) -> HashMap<(Address, U256), U256> {
    let mut prestate = HashMap::new();
    for w in writes {
        let old = state_view.read(w.key).unwrap_or(B256::ZERO);
        prestate.insert((w.account, U256::from_be_bytes(w.account_key.0)), U256::from_be_bytes(old.0));
    }
    prestate
}

// ---------------------------------------------------------------------------
// Phase 1: Pre-execution for read tracking
// ---------------------------------------------------------------------------

/// Returns (storage_read_flat_keys, extra_account_addresses, storage_reads).
/// storage_reads: (address, slot, value) for all storage accessed during pre-execution.
#[allow(clippy::too_many_arguments)]
fn pre_execute_for_reads(
    ctx: &zksync_os_storage_api::BlockContext,
    spec_id: ZkSpecId,
    basefee: u64,
    prev_randao: B256,
    transactions: &[TxInput],
    block_output: &BlockOutput,
    accounts: &HashMap<Address, AccountInfo>,
    storage_prestate: &HashMap<(Address, U256), U256>,
    bytecodes: &HashMap<B256, Bytecode>,
    state_view: impl ViewState,
) -> PreExecutionReads {
    let read_keys: RefCell<HashSet<B256>> = RefCell::new(HashSet::new());
    let read_accounts: RefCell<HashSet<Address>> = RefCell::new(HashSet::new());
    let read_storage: RefCell<Vec<(Address, U256, U256)>> = RefCell::new(Vec::new());
    let resolved_preimages: RefCell<Vec<(B256, Vec<u8>)>> = RefCell::new(Vec::new());

    let tracking_db = TrackingDB {
        accounts, storage_prestate,
        state_view: RefCell::new(state_view),
        bytecodes,
        block_hashes: &ctx.block_hashes,
        block_number: ctx.block_number,
        read_keys: &read_keys,
        read_accounts: &read_accounts,
        read_storage: &read_storage,
        resolved_preimages: &resolved_preimages,
    };

    let cache_db = CacheDB::new(tracking_db);
    run_pre_execution(
        ctx.chain_id, spec_id, ctx.block_number, ctx.timestamp, ctx.coinbase,
        basefee, ctx.gas_limit, prev_randao, transactions, block_output, cache_db,
    );

    (read_keys.into_inner(), read_accounts.into_inner(), read_storage.into_inner(), resolved_preimages.into_inner())
}

// ---------------------------------------------------------------------------
// Phase 2: Merkle proof extraction
// ---------------------------------------------------------------------------

fn extract_account_proofs<S1: ViewState, S2: ViewState>(
    addrs: &[Address],
    tree: &mut MerkleTreeVersion<RocksDBWrapper>,
    state_view: &mut S1,
    state_view_post: &mut Option<S2>,
) -> AccountProofs {
    let mut preimages = Vec::new();
    let mut proofs = Vec::new();

    for &addr in addrs {
        let flat_key = account_flat_key(addr);
        let proof = extract_proof(tree, flat_key);
        proofs.push((flat_key, proof));

        if let Some(hash_value) = ReadStorage::read(state_view, flat_key) {
            // Try pre-execution state first, fall back to post-execution state.
            // Some system contracts have preimages only in the post-execution state
            // (e.g. force-deployed contracts in genesis/upgrade blocks).
            let preimage = state_view.get_preimage(hash_value)
                .or_else(|| state_view_post.as_mut().and_then(|sv| sv.get_preimage(hash_value)));
            if let Some(preimage) = preimage {
                preimages.push((addr, preimage));
            } else {
                tracing::warn!(
                    addr = %addr, hash = %hash_value,
                    "account exists in tree but no preimage found in pre or post-execution state"
                );
            }
        }
    }
    (preimages, proofs)
}

fn extract_storage_write_proofs(
    writes: &[zksync_os_interface::types::StorageWrite],
    prestate: &HashMap<(Address, U256), U256>,
    tree: &mut MerkleTreeVersion<RocksDBWrapper>,
    proven: &mut HashSet<B256>,
    proofs: &mut Vec<(B256, StorageProof)>,
) -> Vec<(Address, U256, U256)> {
    let mut storage_out = Vec::new();
    for w in writes {
        if proven.insert(w.key) {
            proofs.push((w.key, extract_proof(tree, w.key)));
        }
        let slot = U256::from_be_bytes(w.account_key.0);
        let old = prestate.get(&(w.account, slot)).copied().unwrap_or(U256::ZERO);
        storage_out.push((w.account, slot, old));
    }
    storage_out
}

fn extract_storage_read_proofs(
    read_keys: &HashSet<B256>,
    tree: &mut MerkleTreeVersion<RocksDBWrapper>,
    proven: &mut HashSet<B256>,
    proofs: &mut Vec<(B256, StorageProof)>,
) {
    for &key in read_keys {
        if proven.insert(key) {
            proofs.push((key, extract_proof(tree, key)));
        }
    }
}

// ---------------------------------------------------------------------------
// Phase 3: Tree update proof construction
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct LeafWithProof {
    index: u64,
    key: B256,
    value: B256,
    next_index: u64,
    siblings: Vec<B256>, // 64 entries
}

fn get_leaf_proof(tree: &mut MerkleTreeVersion<RocksDBWrapper>, idx: u64) -> LeafWithProof {
    let p = tree.merkle_proof(idx);
    LeafWithProof {
        index: p.index,
        key: B256::from(p.leaf.key.as_u8_array()),
        value: B256::from(p.leaf.value.as_u8_array()),
        next_index: p.leaf.next,
        siblings: p.path.iter().map(|h| B256::from(h.as_u8_array())).collect(),
    }
}

pub fn build_tree_update(
    tree: &mut MerkleTreeVersion<RocksDBWrapper>,
    tree_after: &mut MerkleTreeVersion<RocksDBWrapper>,
    writes: &[zksync_os_interface::types::StorageWrite],
    leaf_count: u64,
) -> BatchTreeUpdate {
    let mut operations = Vec::new();
    let mut entries = Vec::new();
    let mut leaf_proofs: HashMap<u64, LeafWithProof> = HashMap::new();

    // Track in-memory linked list for correct insert ordering.
    // Maps key → (index, next_index) for both existing and newly inserted leaves.
    let mut key_to_index: BTreeMap<B256, u64> = BTreeMap::new();
    let mut index_to_next: HashMap<u64, u64> = HashMap::new();
    let mut next_free_index = leaf_count;

    // Seed the key map from leaves we discover.
    // Only load proofs for indices that actually exist in the tree (< leaf_count).
    let ensure_leaf = |tree: &mut MerkleTreeVersion<RocksDBWrapper>,
                           idx: u64,
                           leaf_proofs: &mut HashMap<u64, LeafWithProof>,
                           key_to_index: &mut BTreeMap<B256, u64>,
                           index_to_next: &mut HashMap<u64, u64>| {
        if idx < leaf_count && !leaf_proofs.contains_key(&idx) {
            let p = get_leaf_proof(tree, idx);
            key_to_index.insert(p.key, p.index);
            index_to_next.insert(p.index, p.next_index);
            leaf_proofs.insert(idx, p);
        }
    };

    for write in writes {
        let flat_key = B256::from(Bytes32::from_array(write.key.0).as_u8_array());
        let flat_key_bytes32 = Bytes32::from_array(write.key.0);

        if let Some(tree_index) = tree.tree_index(flat_key_bytes32) {
            // Update existing leaf
            operations.push(WriteOp::Update { index: tree_index });
            entries.push((flat_key, write.value));
            ensure_leaf(tree, tree_index, &mut leaf_proofs, &mut key_to_index, &mut index_to_next);
        } else {
            // Insert new leaf — find predecessor using in-memory state
            // First check if we already know the predecessor from previous inserts
            let prev_index = if let Some((&prev_key, &prev_idx)) = key_to_index.range(..flat_key).next_back() {
                let _ = prev_key;
                prev_idx
            } else {
                // Fallback to tree (first insert, or predecessor not yet loaded)
                let idx = tree.prev_tree_index(flat_key_bytes32);
                ensure_leaf(tree, idx, &mut leaf_proofs, &mut key_to_index, &mut index_to_next);
                idx
            };

            // Ensure predecessor is loaded and get its next
            ensure_leaf(tree, prev_index, &mut leaf_proofs, &mut key_to_index, &mut index_to_next);
            let old_next = index_to_next[&prev_index];
            ensure_leaf(tree, old_next, &mut leaf_proofs, &mut key_to_index, &mut index_to_next);

            let this_index = next_free_index;
            next_free_index += 1;

            operations.push(WriteOp::Insert { prev_index });
            entries.push((flat_key, write.value));

            // Update in-memory linked list: prev → this → old_next
            index_to_next.insert(prev_index, this_index);
            index_to_next.insert(this_index, old_next);
            key_to_index.insert(flat_key, this_index);
        }
    }

    // Build sorted_leaves
    let mut sorted_leaves: Vec<(u64, TreeLeaf)> = leaf_proofs
        .values()
        .map(|p| (p.index, TreeLeaf { key: p.key, value: p.value, next_index: p.next_index }))
        .collect();
    sorted_leaves.sort_by_key(|(idx, _)| *idx);

    // Compute intermediate hashes for BOTH the old leaf set AND the new leaf set.
    // apply() calls zip_leaves twice: once to verify old root, once for new root.
    let old_leaf_indices: Vec<u64> = sorted_leaves.iter().map(|(idx, _)| *idx).collect();

    // Simulate apply() to determine the final leaf indices
    let mut sim_next_index = leaf_count;
    let mut new_indices: Vec<u64> = old_leaf_indices.clone();
    for op in &operations {
        if let WriteOp::Insert { .. } = op {
            new_indices.push(sim_next_index);
            sim_next_index += 1;
        }
    }
    new_indices.sort();
    new_indices.dedup();

    // For new leaf indices (>= leaf_count), there are no tree proofs.
    // Their siblings in the tree are empty subtrees. We need to use the
    // tree's hash_at_position() to get the actual sibling hash at each depth.
    // Build a function that resolves sibling hashes for ANY position.
    // Compute separate intermediate hashes for old root verification and new root computation.
    tracing::info!(
        old_leaf_count = old_leaf_indices.len(),
        new_leaf_count = new_indices.len(),
        leaf_count_before = leaf_count,
        leaf_count_after = sim_next_index,
        leaf_proofs_count = leaf_proofs.len(),
        "Computing intermediate hashes for tree update"
    );
    let (intermediate_hashes, intermediate_hashes_new) = compute_intermediate_hashes_full(
        &old_leaf_indices, leaf_count,
        &new_indices, sim_next_index,
        &leaf_proofs, tree, tree_after,
    );
    tracing::info!(
        old_hashes = intermediate_hashes.len(),
        new_hashes = intermediate_hashes_new.len(),
        "Intermediate hashes computed"
    );

    // Get the actual tree root after from the block_end tree
    let expected_root_after = tree_after.root_info().ok().map(|(root, _)| root);

    BatchTreeUpdate {
        operations, entries, sorted_leaves,
        intermediate_hashes,
        intermediate_hashes_new,
        leaf_count_before: leaf_count,
        expected_root_after,
    }
}

/// Compute intermediate hashes for both old and new leaf sets.
/// Uses the tree directly to resolve sibling hashes at any position.
fn compute_intermediate_hashes_full(
    old_indices: &[u64],
    old_leaf_count: u64,
    new_indices: &[u64],
    new_leaf_count: u64,
    leaf_proofs: &HashMap<u64, LeafWithProof>,
    tree: &mut MerkleTreeVersion<RocksDBWrapper>,
    tree_after: &mut MerkleTreeVersion<RocksDBWrapper>,
) -> (Vec<B256>, Vec<B256>) {
    let empty_hashes = zisk_merkle::empty_subtree_hashes_vec();

    // Build sibling cache from already-loaded proofs.
    // Key: (depth, node_index_at_that_depth) → hash of that node
    let mut sibling_cache: HashMap<(u8, u64), B256> = HashMap::new();
    for proof in leaf_proofs.values() {
        for d in 0..TREE_DEPTH {
            let sibling_node = (proof.index >> d) ^ 1;
            sibling_cache.entry((d, sibling_node)).or_insert(proof.siblings[d as usize]);
        }
    }

    // Function to resolve sibling hash, loading from tree if necessary.
    // We pass tree as a mutable reference so we can load new proofs on demand.
    let mut resolve_sibling = |depth: u8, sibling_node: u64, leaf_count: u64| -> B256 {
        // Check cache first
        if let Some(&h) = sibling_cache.get(&(depth, sibling_node)) {
            return h;
        }
        // Beyond tree → empty subtree
        let range_start = sibling_node << depth;
        if range_start >= leaf_count {
            return empty_hashes[depth as usize];
        }
        // Load a proof from a leaf in this subtree to populate cache
        let leaf_in_subtree = range_start.min(old_leaf_count.saturating_sub(1));
        if leaf_in_subtree < old_leaf_count {
            let p = get_leaf_proof(tree, leaf_in_subtree);
            for d in 0..TREE_DEPTH {
                let sn = (p.index >> d) ^ 1;
                sibling_cache.entry((d, sn)).or_insert(p.siblings[d as usize]);
            }
            if let Some(&h) = sibling_cache.get(&(depth, sibling_node)) {
                return h;
            }
        }
        empty_hashes[depth as usize]
    };

    // Simulate zip_leaves for old leaf set
    let mut old_hashes = Vec::new();
    {
        let mut node_indices: Vec<u64> = old_indices.to_vec();
        let mut last_idx = old_leaf_count - 1;
        for depth in 0..TREE_DEPTH {
            let mut i = 0;
            let mut next_level = Vec::new();
            while i < node_indices.len() {
                let idx = node_indices[i];
                if idx % 2 == 1 {
                    old_hashes.push(resolve_sibling(depth, idx - 1, old_leaf_count));
                    next_level.push(idx / 2);
                    i += 1;
                } else if node_indices.get(i + 1).copied() == Some(idx + 1) {
                    next_level.push(idx / 2);
                    i += 2;
                } else {
                    if idx != last_idx {
                        old_hashes.push(resolve_sibling(depth, idx + 1, old_leaf_count));
                    }
                    next_level.push(idx / 2);
                    i += 1;
                }
            }
            node_indices = next_level;
            last_idx /= 2;
        }
    }

    // Simulate zip_leaves for new leaf set — use tree_after for sibling resolution
    let mut new_hashes = Vec::new();
    {
        // Build sibling cache from the AFTER tree
        let mut new_sibling_cache: HashMap<(u8, u64), B256> = HashMap::new();
        let mut resolve_new_sibling = |depth: u8, sibling_node: u64| -> B256 {
            if let Some(&h) = new_sibling_cache.get(&(depth, sibling_node)) {
                return h;
            }
            let range_start = sibling_node << depth;
            if range_start >= new_leaf_count {
                return empty_hashes[depth as usize];
            }
            // Load from the AFTER tree
            let leaf_in_subtree = range_start.min(new_leaf_count.saturating_sub(1));
            let p = get_leaf_proof(tree_after, leaf_in_subtree);
            for d in 0..TREE_DEPTH {
                let sn = (p.index >> d) ^ 1;
                new_sibling_cache.entry((d, sn)).or_insert(p.siblings[d as usize]);
            }
            new_sibling_cache.get(&(depth, sibling_node))
                .copied()
                .unwrap_or(empty_hashes[depth as usize])
        };

        let mut node_indices: Vec<u64> = new_indices.to_vec();
        let mut last_idx = new_leaf_count - 1;
        for depth in 0..TREE_DEPTH {
            let mut i = 0;
            let mut next_level = Vec::new();
            while i < node_indices.len() {
                let idx = node_indices[i];
                if idx % 2 == 1 {
                    new_hashes.push(resolve_new_sibling(depth, idx - 1));
                    next_level.push(idx / 2);
                    i += 1;
                } else if node_indices.get(i + 1).copied() == Some(idx + 1) {
                    next_level.push(idx / 2);
                    i += 2;
                } else {
                    if idx != last_idx {
                        new_hashes.push(resolve_new_sibling(depth, idx + 1));
                    }
                    next_level.push(idx / 2);
                    i += 1;
                }
            }
            node_indices = next_level;
            last_idx /= 2;
        }
    }

    (old_hashes, new_hashes)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn account_flat_key(account: Address) -> B256 {
    zisk_merkle::derive_account_properties_key(&account.into_array())
}

fn extract_proof(tree: &mut MerkleTreeVersion<RocksDBWrapper>, flat_key: B256) -> StorageProof {
    let key_bytes = Bytes32::from_array(flat_key.0);
    if let Some(tree_index) = tree.tree_index(key_bytes) {
        let p = tree.merkle_proof(tree_index);
        StorageProof::Existing(SlotProofEntry {
            index: p.index,
            value: B256::from(p.leaf.value.as_u8_array()),
            next_index: p.leaf.next,
            siblings: p.path.iter().map(|h| B256::from(h.as_u8_array())).collect(),
        })
    } else {
        let prev_index = tree.prev_tree_index(key_bytes);
        let left = tree.merkle_proof(prev_index);
        let right = tree.merkle_proof(left.leaf.next);
        StorageProof::NonExisting {
            left_neighbor: NeighborProofEntry {
                entry: SlotProofEntry {
                    index: left.index,
                    value: B256::from(left.leaf.value.as_u8_array()),
                    next_index: left.leaf.next,
                    siblings: left.path.iter().map(|h| B256::from(h.as_u8_array())).collect(),
                },
                leaf_key: B256::from(left.leaf.key.as_u8_array()),
            },
            right_neighbor: NeighborProofEntry {
                entry: SlotProofEntry {
                    index: right.index,
                    value: B256::from(right.leaf.value.as_u8_array()),
                    next_index: right.leaf.next,
                    siblings: right.path.iter().map(|h| B256::from(h.as_u8_array())).collect(),
                },
                leaf_key: B256::from(right.leaf.key.as_u8_array()),
            },
        }
    }
}

fn extract_block_hashes(
    hashes: &zksync_os_storage_api::BlockHashes,
    block_number: u64,
) -> Vec<(u64, B256)> {
    hashes.0.iter().enumerate().filter_map(|(i, hash)| {
        let h = B256::from(hash.to_be_bytes::<32>());
        if !h.is_zero() && block_number > 0 {
            // Map index to block number: hashes[0] = current-1, hashes[255] = current-256
            // For block 1: hashes[255] = genesis block (block 0)
            let offset = 256u64.saturating_sub(i as u64);
            if offset <= block_number {
                let num = block_number - offset;
                Some((num, h))
            } else {
                None
            }
        } else { None }
    }).collect()
}

fn extract_l2_to_l1_logs(block_output: &BlockOutput) -> Vec<L2ToL1LogEntry> {
    let mut logs = Vec::new();
    for tx_result in block_output.tx_results.iter().flatten() {
        for log in &tx_result.l2_to_l1_logs {
            logs.push(L2ToL1LogEntry {
                l2_shard_id: log.log.l2_shard_id,
                is_service: log.log.is_service,
                tx_number_in_block: log.log.tx_number_in_block,
                sender: log.log.sender,
                key: log.log.key,
                value: log.log.value,
            });
        }
    }
    logs
}

// ---------------------------------------------------------------------------
// Transaction conversion
// ---------------------------------------------------------------------------

fn convert_all_txs(transactions: &[ZkTransaction], block_output: &BlockOutput) -> Vec<TxInput> {
    transactions.iter().enumerate().filter_map(|(i, tx)| {
        let mut tx_input = convert_tx(tx)?;
        // Include the server's gas_used for all transactions.
        // REVM's gas computation may differ from ZKsync OS native gas
        // (especially for L1 deposits and upgrade txs), so the server's
        // gas value is authoritative for block header computation.
        match block_output.tx_results.get(i) {
            Some(Ok(result)) => {
                tx_input.gas_used_override = Some(result.gas_used);
            }
            Some(Err(_)) => {
                tx_input.gas_used_override = Some(0);
                tx_input.force_fail = true;
            }
            None => {}
        }
        Some(tx_input)
    }).collect()
}

fn convert_tx(tx: &ZkTransaction) -> Option<TxInput> {
    use alloy::sol_types::SolValue;

    // Helper to ABI-encode an L1/upgrade tx as L2CanonicalTransaction.
    fn abi_encode_l1<T: zksync_os_types::L1TxType>(i: &zksync_os_types::L1Tx<T>, tx_type_byte: u8) -> Vec<u8> {
        zksync_os_contract_interface::L2CanonicalTransaction {
            txType: U256::from(tx_type_byte),
            from: U256::from_be_slice(i.initiator.as_slice()),
            to: U256::from_be_slice(i.to.as_slice()),
            gasLimit: U256::from(i.gas_limit),
            gasPerPubdataByteLimit: U256::from(i.gas_per_pubdata_byte_limit),
            maxFeePerGas: U256::from(i.max_fee_per_gas),
            maxPriorityFeePerGas: U256::from(i.max_priority_fee_per_gas),
            paymaster: U256::ZERO,
            nonce: U256::from(i.nonce),
            value: U256::from(i.value),
            reserved: [
                U256::from(i.to_mint),
                U256::from_be_slice(i.refund_recipient.as_slice()),
                U256::ZERO, U256::ZERO,
            ],
            data: i.input().to_vec().into(),
            signature: Default::default(),
            factoryDeps: i.factory_deps.iter().map(|h| U256::from_be_bytes(h.0)).collect(),
            paymasterInput: Default::default(),
            reservedDynamic: Default::default(),
        }.abi_encode()
    }

    let auth = match tx.envelope() {
        ZkEnvelope::System(_) => return None,
        ZkEnvelope::L2(_) => {
            TxAuth::L2 { signed_bytes: tx.envelope().encoded_2718() }
        }
        ZkEnvelope::L1(l1) => {
            let i = &l1.inner;
            TxAuth::L1 { tx_hash: i.hash, abi_encoded: abi_encode_l1(i, 0x7f) }
        }
        ZkEnvelope::Upgrade(u) => {
            let i = &u.inner;
            TxAuth::Upgrade { tx_hash: i.hash, abi_encoded: abi_encode_l1(i, 0x7e) }
        }
    };

    Some(TxInput {
        chain_id: tx.envelope().chain_id(),
        gas_used_override: None,
        force_fail: false,
        auth,
    })
}

// ---------------------------------------------------------------------------
// Tracking database for pre-execution
// ---------------------------------------------------------------------------

struct TrackingDB<'a, S> {
    accounts: &'a HashMap<Address, AccountInfo>,
    storage_prestate: &'a HashMap<(Address, U256), U256>,
    state_view: RefCell<S>,
    bytecodes: &'a HashMap<B256, Bytecode>,
    block_hashes: &'a zksync_os_storage_api::BlockHashes,
    block_number: u64,
    read_keys: &'a RefCell<HashSet<B256>>,
    read_accounts: &'a RefCell<HashSet<Address>>,
    /// Storage reads captured during pre-execution: (address, slot, value).
    read_storage: &'a RefCell<Vec<(Address, U256, U256)>>,
    /// Bytecode preimages resolved from state_view during pre-execution.
    /// These need to be included in extra_bytecodes.
    resolved_preimages: &'a RefCell<Vec<(B256, Vec<u8>)>>,
}

#[derive(Debug)]
struct TrackingDBError;
impl core::fmt::Display for TrackingDBError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result { write!(f, "tracking db") }
}
impl std::error::Error for TrackingDBError {}
impl DBErrorMarker for TrackingDBError {}

impl<S: ViewState> DatabaseRef for TrackingDB<'_, S> {
    type Error = TrackingDBError;

    fn basic_ref(&self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.read_accounts.borrow_mut().insert(address);
        if let Some(info) = self.accounts.get(&address) {
            return Ok(Some(info.clone()));
        }
        // Fallback: try loading from state_view (post-execution state for upgrade blocks).
        // Pre-load bytecode just like the server's REVM adapter does, since code_by_hash_ref
        // can't resolve keccak256 hashes from the blake2s-keyed preimage DB.
        let mut sv = self.state_view.borrow_mut();
        if let Some(props) = sv.get_account(address) {
            let obs_hash = B256::from(props.observable_bytecode_hash.as_u8_array());
            let pre_hash = B256::from(props.bytecode_hash.as_u8_array());
            let effective = if obs_hash.is_zero() {
                if props.nonce == 0 && props.balance == U256::ZERO { return Ok(None); }
                KECCAK_EMPTY
            } else {
                obs_hash
            };
            // Pre-load bytecode via blake2s hash (the preimage DB key).
            let code = if !pre_hash.is_zero() {
                sv.get_preimage(pre_hash).map(|padded_code| {
                    let raw_len = props.unpadded_code_len as usize;
                    let raw = if raw_len > 0 && raw_len <= padded_code.len() {
                        &padded_code[..raw_len]
                    } else {
                        &padded_code[..]
                    };
                    Bytecode::new_raw(Bytes::copy_from_slice(raw))
                })
            } else {
                None
            };
            return Ok(Some(AccountInfo {
                nonce: props.nonce, balance: props.balance, code_hash: effective,
                code, account_id: None,
            }));
        }
        Ok(None)
    }

    fn code_by_hash_ref(&self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        if let Some(bytecode) = self.bytecodes.get(&code_hash) {
            return Ok(bytecode.clone());
        }
        // Fallback: try preimage DB via state_view (like the server's OverriddenStateView).
        if code_hash != KECCAK_EMPTY && code_hash != B256::ZERO {
            if let Some(preimage) = self.state_view.borrow_mut().get_preimage(code_hash)
                && !preimage.is_empty()
            {
                self.resolved_preimages.borrow_mut().push((code_hash, preimage.clone()));
                return Ok(Bytecode::new_raw(Bytes::copy_from_slice(&preimage)));
            }
            tracing::debug!(%code_hash, "TrackingDB code_by_hash miss");
        }
        Ok(Bytecode::default())
    }

    fn storage_ref(&self, address: Address, index: U256) -> Result<U256, Self::Error> {
        let flat_key = zisk_merkle::derive_flat_storage_key(&address.into_array(), &B256::from(index.to_be_bytes::<32>()));
        self.read_keys.borrow_mut().insert(flat_key);

        let val = if let Some(&val) = self.storage_prestate.get(&(address, index)) {
            val
        } else {
            self.state_view.borrow_mut().read(flat_key)
                .map(|v| U256::from_be_bytes(v.0))
                .unwrap_or(U256::ZERO)
        };
        // Capture read for SimpleDB storage population
        self.read_storage.borrow_mut().push((address, index, val));
        // DEBUG: print storage reads for upgrade-related addresses
        if address.as_slice()[18] >= 0x80 || (address.as_slice()[16] == 0x00 && address.as_slice()[17] == 0x01) {
            tracing::debug!("SLOAD({address}, slot={index}) = 0x{val:064x}");
        }
        Ok(val)
    }

    fn block_hash_ref(&self, number: u64) -> Result<B256, Self::Error> {
        if self.block_number > 0 && number < self.block_number {
            let idx = 256usize.saturating_sub((self.block_number - number) as usize);
            if idx < 256 {
                return Ok(B256::from(self.block_hashes.0[idx].to_be_bytes::<32>()));
            }
        }
        Ok(B256::ZERO)
    }
}

#[allow(clippy::too_many_arguments)]
fn run_pre_execution<DB: DatabaseRef>(
    chain_id: u64, spec_id: ZkSpecId, block_number: u64, timestamp: u64,
    coinbase: Address, basefee: u64, gas_limit: u64, prev_randao: B256,
    transactions: &[TxInput], block_output: &BlockOutput, mut cache_db: CacheDB<DB>,
) where DB::Error: core::fmt::Debug {
    let mut evm = <ZkContext<_>>::default()
        .with_db(&mut cache_db)
        .modify_cfg_chained(|cfg| { cfg.chain_id = chain_id; cfg.spec = spec_id; })
        .modify_block_chained(|blk| {
            blk.number = U256::from(block_number); blk.timestamp = U256::from(timestamp);
            blk.beneficiary = coinbase; blk.basefee = basefee;
            blk.gas_limit = gas_limit; blk.prevrandao = Some(prev_randao);
        })
        .build_zk();

    for (i, tx_input) in transactions.iter().enumerate() {
        let (gas_override, force_fail) = match block_output.tx_results.get(i) {
            Some(Ok(o)) => (Some(o.gas_used), false),
            Some(Err(_)) => (Some(0), true),
            None => (None, false),
        };
        // Decode tx fields from the authenticated source, matching the guest's logic.
        let (caller, kind, value, data, nonce, gas_limit, gas_price, gas_priority_fee,
             chain_id, tx_type, mint, refund_recipient, tx_hash) = match &tx_input.auth {
            TxAuth::L1 { tx_hash, abi_encoded } | TxAuth::Upgrade { tx_hash, abi_encoded } => {
                let w = |f: usize| alloy::primitives::U256::from_be_slice(&abi_encoded[32 + f*32..32 + (f+1)*32]);
                let a = |f: usize| Address::from_slice(&w(f).to_be_bytes::<32>()[12..]);
                let raw_gl: u64 = w(3).to();
                let tt: u8 = w(0).to();
                let gl = if tt == 0x7e { raw_gl.saturating_mul(10) } else { raw_gl };
                let data_rel: usize = w(14).to();
                let data_abs = 32 + data_rel;
                let data_len: usize = alloy::primitives::U256::from_be_slice(&abi_encoded[data_abs..data_abs+32]).to();
                let data = abi_encoded[data_abs+32..data_abs+32+data_len].to_vec();
                let rr = a(11);
                (a(1), TxKind::Call(a(2)), w(9), data, w(8).to::<u64>(), gl, w(5).to::<u128>(),
                 None, tx_input.chain_id, tt, w(10),
                 if rr.is_zero() { None } else { Some(rr) }, *tx_hash)
            }
            TxAuth::L2 { signed_bytes } => {
                use alloy::consensus::Transaction;
                use alloy::consensus::TxEnvelope;
                use alloy::eips::Decodable2718;
                let env = TxEnvelope::decode_2718(&mut &signed_bytes[..]).expect("decode");
                let signer = alloy::consensus::transaction::SignerRecoverable::recover_signer(&env).expect("ecrecover");
                let k = match env.to() { Some(a) => TxKind::Call(a), None => TxKind::Create };
                let h = alloy::primitives::keccak256(signed_bytes);
                (signer, k, env.value(), env.input().to_vec(), env.nonce(), env.gas_limit(),
                 env.max_fee_per_gas(), env.max_priority_fee_per_gas(),
                 env.chain_id().or(tx_input.chain_id), env.tx_type() as u8,
                 U256::ZERO, None, h)
            }
        };
        let mut b = revm::context::TxEnv::builder()
            .caller(caller).gas_limit(gas_limit).gas_price(gas_price)
            .kind(kind).value(value).data(Bytes::from(data)).nonce(nonce)
            .tx_type(Some(tx_type)).chain_id(chain_id).blob_hashes(vec![]);
        if let Some(fee) = gas_priority_fee { b = b.gas_priority_fee(Some(fee)); }
        let tx: ZKsyncTx<revm::context::TxEnv> = ZKsyncTxBuilder::new()
            .base(b).mint(mint).refund_recipient(refund_recipient)
            .gas_used_override(gas_override).force_fail(force_fail)
            .tx_hash(tx_hash)
            .build().expect("tx build failed");
        match evm.transact_commit(tx) {
            Ok(result) => {
                if matches!(tx_input.auth, TxAuth::Upgrade { .. }) {
                    tracing::info!(
                        success = result.is_success(),
                        gas_used = result.tx_gas_used(),
                        "pre-execution upgrade tx result"
                    );
                }
            }
            Err(e) => {
                if matches!(tx_input.auth, TxAuth::Upgrade { .. }) {
                    tracing::warn!("pre-execution upgrade tx error: {e:?}");
                }
            }
        }
    }
}

/// Pre-create accounts that are force-deployed during upgrade transactions.
///
/// The ComplexUpgrader proxy at 0x800f delegates to an implementation whose address
/// is in the ERC1967 storage slot. That implementation doesn't exist yet at
/// block_number-1 (it's force-deployed in the current block). We must pre-create
/// it from the post-execution state so REVM can execute the upgrade tx.
#[allow(clippy::too_many_arguments)]
fn pre_create_upgrade_accounts<ReadState: ReadStateHistory>(
    block_output: &BlockOutput,
    block_number: u64,
    read_state: &ReadState,
    state_view: &mut impl ReadStorage,
    accounts_map: &mut HashMap<Address, AccountInfo>,
    bytecodes_map: &mut HashMap<B256, Bytecode>,
    bytecodes_out: &mut Vec<(B256, Vec<u8>)>,
    extra_bytecodes: &mut Vec<(B256, Vec<u8>)>,
) -> anyhow::Result<()> {
    // Pre-create all addresses from storage writes and account diffs.
    for write in &block_output.storage_writes {
        accounts_map
            .entry(write.account)
            .or_insert_with(|| AccountInfo {
                nonce: 0, balance: U256::ZERO, code_hash: KECCAK_EMPTY,
                code: None, account_id: None,
            });
    }
    for diff in &block_output.account_diffs {
        accounts_map
            .entry(diff.address)
            .or_insert_with(|| AccountInfo {
                nonce: 1, balance: U256::ZERO, code_hash: KECCAK_EMPTY,
                code: None, account_id: None,
            });
    }

    // Resolve ALL accounts with missing bytecodes from post-execution state.
    // During genesis/upgrade, system contracts are force-deployed. Their bytecodes
    // exist in force_preimages but the pre-execution state has observable_bytecode_hash=0.
    // Read the post-execution state to get the correct bytecode hashes.
    {
        let mut state_after = read_state.state_view_at(block_number)?;
        let addrs_needing_code: Vec<Address> = accounts_map
            .iter()
            .filter(|(_, info)| info.code_hash == KECCAK_EMPTY || info.code_hash == B256::ZERO)
            .map(|(addr, _)| *addr)
            .collect();
        tracing::info!(count = addrs_needing_code.len(), "resolving post-execution bytecodes");
        for addr in addrs_needing_code {
            if let Some(props) = state_after.get_account(addr) {
                let obs_hash = B256::from(props.observable_bytecode_hash.as_u8_array());
                let pre_hash = B256::from(props.bytecode_hash.as_u8_array());
                if obs_hash.is_zero() {
                    continue;
                }
                let effective = obs_hash;
                if !pre_hash.is_zero()
                    && let Some(padded_code_with_artifacts) = state_after.get_preimage(pre_hash)
                {
                    {
                        let raw_len = props.unpadded_code_len as usize;
                        let raw_code = if raw_len > 0 && raw_len <= padded_code_with_artifacts.len() {
                            &padded_code_with_artifacts[..raw_len]
                        } else {
                            &padded_code_with_artifacts[..]
                        };
                        if let std::collections::hash_map::Entry::Vacant(entry) =
                            bytecodes_map.entry(effective)
                        {
                            bytecodes_out.push((effective, raw_code.to_vec()));
                            entry.insert(Bytecode::new_raw(Bytes::copy_from_slice(raw_code)));
                        }
                        // Store the FULL preimage (code + artifacts) under the blake2s hash.
                        // The deployer precompile looks up by this hash.
                        tracing::info!(
                            addr = %addr,
                            blake2s_hash = %pre_hash,
                            preimage_len = padded_code_with_artifacts.len(),
                            "storing force_deploy_bytecode (blake2s → preimage)"
                        );
                        extra_bytecodes.push((pre_hash, padded_code_with_artifacts));
                    }
                }
                accounts_map.insert(addr, AccountInfo {
                    nonce: props.nonce, balance: props.balance, code_hash: effective,
                    code: None, account_id: None,
                });
                tracing::info!(
                    addr = %addr, code_hash = %effective, code_len = bytecodes_map.get(&effective).map(|b| b.len()).unwrap_or(0),
                    "resolved post-execution bytecode for force-deployed account"
                );
            }
        }
    }

    // Resolve deployer bytecode hashes captured during server execution.
    // The server marks these with 1-byte marker values in published_preimages.
    {
        let mut state_for_deployer = read_state.state_view_at(block_number)?;
        let mut deployer_resolved = 0;
        for (hash, marker) in &block_output.published_preimages {
            // 0xDE marker: deployer bytecode hash whose preimage must be resolved.
            if marker.len() == 1
                && marker[0] == 0xDE
                && let Some(preimage) = state_for_deployer.get_preimage(*hash)
                && !preimage.is_empty()
            {
                bytecodes_map
                    .entry(*hash)
                    .or_insert_with(|| Bytecode::new_raw(Bytes::copy_from_slice(&preimage)));
                extra_bytecodes.push((*hash, preimage));
                deployer_resolved += 1;
            }
        }
        if deployer_resolved > 0 {
            tracing::info!(deployer_resolved, "resolved deployer bytecode preimages");
        }
    }

    // Include ALL published_preimages as extra_bytecodes.
    // Published preimages include both AccountProperties (short, ~124 bytes) and
    // actual bytecodes (long, thousands of bytes). The deployer precompile's
    // setDeployedCodeEVM uses the blake2s hash to look up bytecodes.
    // By including all published preimages, the deployer can find them.
    {
        let mut extra_from_published = 0;
        for (hash, data) in &block_output.published_preimages {
            if !data.is_empty() && !bytecodes_map.contains_key(hash) {
                bytecodes_map.insert(*hash, Bytecode::new_raw(Bytes::copy_from_slice(data)));
                extra_bytecodes.push((*hash, data.clone()));
                extra_from_published += 1;
            }
        }
        if extra_from_published > 0 {
            tracing::info!(extra_from_published, "included published_preimages as extra_bytecodes");
        }
    }

    // Extract bytecode preimages from storage writes to 0x8003 (AccountProperties).
    // Each write stores a hash of AccountProperties. Resolve the preimage, decode the
    // bytecode_hash field, then resolve the bytecode preimage from the DB.
    // This captures ALL bytecodes deployed during the upgrade, including those the
    // deployer precompile installs via setDeployedCodeEVM.
    {
        let mut state_for_bytecodes = read_state.state_view_at(block_number)?;
        let mut seen_bytecode_hashes = HashSet::new();
        let mut resolved_count = 0;
        // Scan ALL storage write values as potential preimage keys.
        // AccountProperties writes have account-property-hash values.
        // Other writes may reference bytecode hashes.
        let mut total_writes = 0;
        let mut preimage_found = 0;
        let mut props_decoded = 0;
        for write in &block_output.storage_writes {
            let value_hash = write.value;
            if value_hash.is_zero() { continue; }
            total_writes += 1;
            // Resolve AccountProperties preimage
            if let Some(props_bytes) = state_for_bytecodes.get_preimage(value_hash) {
                preimage_found += 1;
                if props_bytes.len() < 124 { continue; }
                props_decoded += 1;
                // AccountProperties layout: versioning_data(4) + nonce(8) + balance(32) + bytecode_hash(32) + ...
                // The bytecode_hash is at a fixed offset. Let's use the merkle module's decoder.
                let props = zisk_merkle::AccountProperties::decode(&props_bytes);
                let bytecode_hash = props.bytecode_hash;
                if !bytecode_hash.is_zero() {
                    tracing::debug!(
                        account = %write.account,
                        bytecode_hash = %bytecode_hash,
                        "AccountProperties scan: found bytecode_hash"
                    );
                }
                if bytecode_hash.is_zero() || !seen_bytecode_hashes.insert(bytecode_hash) { continue; }
                if bytecodes_map.contains_key(&bytecode_hash) { continue; }
                if let Some(code_preimage) = state_for_bytecodes.get_preimage(bytecode_hash)
                    && !code_preimage.is_empty()
                {
                    bytecodes_map.insert(
                        bytecode_hash,
                        Bytecode::new_raw(Bytes::copy_from_slice(&code_preimage)),
                    );
                    extra_bytecodes.push((bytecode_hash, code_preimage));
                    resolved_count += 1;
                }
            }
        }
        tracing::info!(
            total_writes, preimage_found, props_decoded, resolved_count,
            "AccountProperties bytecode scan stats"
        );
        if resolved_count > 0 {
            tracing::info!(
                resolved_count,
                "extracted bytecode preimages from AccountProperties storage writes"
            );
        }
    }

    // Resolve the proxy implementation target via the ERC1967 storage slot.
    use crate::prover_api::zisk_proof_constants::{COMPLEX_UPGRADER_ADDRESS, ERC1967_IMPLEMENTATION_SLOT};
    let proxy_addr: Address = COMPLEX_UPGRADER_ADDRESS
        .parse()
        .expect("invalid upgrader address constant");
    let impl_slot = U256::from_be_bytes(
        B256::from_slice(
            &alloy::primitives::hex::decode(ERC1967_IMPLEMENTATION_SLOT)
                .expect("invalid ERC1967 slot constant"),
        )
        .0,
    );
    let impl_flat_key = zisk_merkle::derive_flat_storage_key(
        &proxy_addr.into_array(),
        &B256::from(impl_slot.to_be_bytes::<32>()),
    );

    let Some(impl_value) = state_view.read(impl_flat_key) else {
        return Ok(());
    };
    let impl_addr = Address::from_slice(&impl_value.0[12..32]);
    if impl_addr.is_zero() || accounts_map.contains_key(&impl_addr) {
        return Ok(());
    }

    // Load the implementation from post-execution state (it's force-deployed in this block).
    let mut state_after = read_state.state_view_at(block_number)?;
    if let Some(props) = state_after.get_account(impl_addr) {
        let obs_hash = B256::from(props.observable_bytecode_hash.as_u8_array());
        let pre_hash = B256::from(props.bytecode_hash.as_u8_array());
        let effective = if obs_hash.is_zero() { KECCAK_EMPTY } else { obs_hash };
        tracing::info!(address = %impl_addr, code_hash = %effective, "pre-creating upgrade implementation");
        accounts_map.insert(impl_addr, AccountInfo {
            nonce: props.nonce, balance: props.balance, code_hash: effective,
            code: None, account_id: None,
        });
        if !pre_hash.is_zero()
            && let Some(padded_code) = state_after.get_preimage(pre_hash)
        {
            {
                let raw_len = props.unpadded_code_len as usize;
                let raw_code = if raw_len > 0 && raw_len <= padded_code.len() {
                    &padded_code[..raw_len]
                } else {
                    &padded_code[..]
                };
                if let std::collections::hash_map::Entry::Vacant(entry) =
                    bytecodes_map.entry(effective)
                {
                    bytecodes_out.push((effective, raw_code.to_vec()));
                    entry.insert(
                        Bytecode::new_raw(Bytes::copy_from_slice(raw_code)),
                    );
                }
            }
        }
    } else {
        tracing::info!(address = %impl_addr, "pre-creating empty upgrade implementation");
        accounts_map.insert(impl_addr, AccountInfo {
            nonce: 1, balance: U256::ZERO, code_hash: KECCAK_EMPTY,
            code: None, account_id: None,
        });
    }
    Ok(())
}
