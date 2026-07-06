//! Extracts block data from a local zksync-os-server database, converts it
//! to the ZiSK BatchInput format, and runs the REVM executor.
//!
//! Usage:
//!   # Run server first, then:
//!   cargo run -p zksync_os_zisk_batch_test -- --db ./db/sequencer
//!
//! The tool reads directly from the server's RocksDB replay WAL,
//! converts to our BatchInput format, and runs the zksync-os-revm executor.

use std::path::PathBuf;

mod replay_reader;

use alloy::consensus::Transaction as _;
use alloy::primitives::{Address, B256, U256};
use clap::Parser;
use replay_reader::ReplayData;
use zksync_os_types::{ExecutionVersion, ZkEnvelope, ZkTransaction};

use zksync_os_zisk_lib::executor;
use zksync_os_zisk_lib::types::*;

#[derive(Parser)]
#[command(name = "zisk-batch-test")]
#[command(about = "Test ZiSK REVM executor against real server block data")]
struct Cli {
    /// Path to the server's RocksDB directory (e.g. ./db/sequencer)
    #[arg(long)]
    db: PathBuf,
    /// Block number to test (default: latest)
    #[arg(long)]
    block: Option<u64>,
    /// Export BatchInput as JSON to this path
    #[arg(long)]
    export: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();

    // Open the raw RocksDB to read replay records
    let replay_db_path = cli.db.join("block_replay_wal");
    eprintln!("Opening replay DB at {}", replay_db_path.display());

    let reader = replay_reader::ReplayReader::open(&replay_db_path)?;

    let latest = reader.latest_block();
    let target_block = cli.block.unwrap_or(latest);

    eprintln!("Latest block: {latest}");
    eprintln!("Testing block: {target_block}");
    eprintln!();

    if target_block == 0 || target_block > latest {
        anyhow::bail!("Block {target_block} not available (latest: {latest})");
    }

    let replay_data = reader.read_record(target_block)?;

    eprintln!(
        "Block {}: {} transactions, chain_id={}, timestamp={}",
        target_block,
        replay_data.transactions.len(),
        replay_data.block_context.chain_id,
        replay_data.block_context.timestamp,
    );

    // Convert
    let batch_input = convert_replay_to_batch_input(&replay_data)?;

    // Optionally export
    if let Some(ref export_path) = cli.export {
        let json = serde_json::to_string_pretty(&batch_input)?;
        std::fs::write(export_path, &json)?;
        eprintln!("Exported BatchInput JSON to {}", export_path.display());
    }

    // Execute via zksync-os-revm
    eprintln!("\nExecuting via zksync-os-revm...");
    let output = executor::execute_batch(&batch_input);

    for br in &output.block_results {
        eprintln!("\n--- Block {} Results ---", br.block_number);
        for (i, tx) in br.tx_results.iter().enumerate() {
            eprintln!(
                "  tx[{i}]: success={}, gas_used={}, output_len={}",
                tx.success, tx.gas_used, tx.output.len()
            );
        }
        eprintln!("  account_diffs: {}", br.account_diffs.len());
        for d in &br.account_diffs {
            eprintln!(
                "    {}: nonce {}→{}, balance {}→{}",
                d.address, d.nonce_before, d.nonce_after, d.balance_before, d.balance_after
            );
        }
        eprintln!("  storage_diffs: {}", br.storage_diffs.len());
    }

    let hash = executor::compute_output_hash(&output);
    eprintln!("\nBatch output hash: 0x{}", hex::encode(hash));
    eprintln!("\nZiSK REVM executor completed successfully.");

    Ok(())
}

fn convert_replay_to_batch_input(record: &ReplayData) -> anyhow::Result<BatchInput> {
    let ctx = &record.block_context;

    let spec_id: u8 = match ExecutionVersion::try_from(ctx.execution_version) {
        Ok(ExecutionVersion::V1 | ExecutionVersion::V2 | ExecutionVersion::V3) => 0,
        Ok(ExecutionVersion::V4 | ExecutionVersion::V5 | ExecutionVersion::V6) => 1,
        Err(_) => anyhow::bail!("Unsupported execution version: {}", ctx.execution_version),
    };

    let mut transactions = Vec::new();
    for tx in &record.transactions {
        if let Some(converted) = convert_tx(tx) {
            transactions.push(converted);
        }
    }

    // Synthetic pre-state: gas_used_override mode means REVM doesn't check balances
    let mut accounts = Vec::new();
    let mut seen: std::collections::HashSet<Address> = std::collections::HashSet::new();

    for tx in &record.transactions {
        let signer = tx.signer();
        if seen.insert(signer) {
            accounts.push((signer, AccountData {
                nonce: tx.nonce(),
                balance: U256::MAX,
                code_hash: B256::ZERO,
            }));
        }
        if let Some(to) = tx.to() {
            if seen.insert(to) {
                accounts.push((to, AccountData { nonce: 0, balance: U256::ZERO, code_hash: B256::ZERO }));
            }
        }
    }
    if seen.insert(ctx.coinbase) {
        accounts.push((ctx.coinbase, AccountData { nonce: 0, balance: U256::ZERO, code_hash: B256::ZERO }));
    }

    let block_hashes: Vec<(u64, B256)> = ctx.block_hashes.0.iter().enumerate().filter_map(|(i, hash)| {
        let h: B256 = (*hash).into();
        if !h.is_zero() && ctx.block_number > 0 {
            let num = ctx.block_number.saturating_sub(256 - i as u64);
            if num > 0 { Some((num, h)) } else { None }
        } else {
            None
        }
    }).collect();

    let basefee: u64 = ctx.eip1559_basefee.try_into().unwrap_or(u64::MAX);

    Ok(BatchInput {
        chain_id: ctx.chain_id,
        spec_id,
        protocol_version_minor: 30,
        batch_meta: BatchMeta {
            tree_root_before: B256::ZERO,
            leaf_count_before: 0,
            block_number_before: ctx.block_number.saturating_sub(1),
            last_block_timestamp_before: 0,
            block_hashes_blake_before: B256::ZERO,
            previous_block_hashes: vec![],
            upgrade_tx_hash: B256::ZERO,
            da_commitment_scheme: 0,
            pubdata: vec![],
            multichain_root: B256::ZERO,
            sl_chain_id: 0,
            blob_versioned_hashes: vec![],
            tree_update: None,
        },
        blocks: vec![BlockInput {
            number: ctx.block_number,
            timestamp: ctx.timestamp,
            base_fee: basefee,
            gas_limit: ctx.gas_limit,
            coinbase: ctx.coinbase,
            prev_randao: B256::from(U256::from(1).to_be_bytes::<32>()),
            block_header_hash: B256::ZERO,
            storage_proofs: vec![],
            account_preimages: vec![],
            transactions,
            accounts,
            storage: vec![],
            bytecodes: vec![],
            block_hashes,
            l2_to_l1_logs: vec![],
        }],
    })
}

fn convert_tx(tx: &ZkTransaction) -> Option<TxInput> {
    let caller = tx.signer();

    let (gas_price, gas_priority_fee, value, data, chain_id, tx_type, mint, refund_recipient):
        (u128, Option<u128>, U256, Vec<u8>, Option<u64>, u8, Option<U256>, Option<Address>) =
        match tx.envelope() {
            ZkEnvelope::System(_) => return None,
            ZkEnvelope::L2(l2_tx) => (
                l2_tx.max_fee_per_gas(),
                l2_tx.max_priority_fee_per_gas(),
                l2_tx.value(),
                l2_tx.input().to_vec(),
                l2_tx.chain_id(),
                l2_tx.tx_type() as u8,
                None,
                None,
            ),
            ZkEnvelope::L1(l1_tx) => {
                let inner = &l1_tx.inner;
                (
                    l1_tx.max_fee_per_gas(),
                    l1_tx.max_priority_fee_per_gas(),
                    inner.value(),
                    inner.input().to_vec(),
                    None,
                    0x7f,
                    Some(U256::from_limbs(inner.to_mint.into_limbs())),
                    Some(inner.refund_recipient),
                )
            }
            ZkEnvelope::Upgrade(upgrade_tx) => {
                let inner = &upgrade_tx.inner;
                (
                    0,
                    None,
                    inner.value(),
                    inner.input().to_vec(),
                    None,
                    0x7e,
                    Some(U256::from_limbs(inner.to_mint.into_limbs())),
                    Some(inner.refund_recipient),
                )
            }
        };

    Some(TxInput {
        caller,
        gas_limit: tx.gas_limit(),
        gas_price,
        gas_priority_fee: gas_priority_fee.or(Some(0)),
        to: tx.to(),
        value,
        data,
        nonce: tx.nonce(),
        chain_id,
        tx_type,
        gas_used_override: Some(21_000),
        force_fail: false,
        mint,
        refund_recipient,
        is_l1_tx: false,
        l1_tx_hash: None,
        signed_tx_bytes: None,
    })
}
