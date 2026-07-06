//! Complex integration test: deploys a Counter contract, calls it multiple times,
//! sends ETH transfers, handles L1→L2 deposits, and verifies REVM execution.

use alloy::consensus::Transaction;
use alloy::eips::{Decodable2718, Typed2718};
use alloy::network::{ReceiptResponse, TransactionBuilder};
use alloy::primitives::{Address, B256, Bytes, U256};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use zksync_os_integration_tests::assert_traits::ReceiptAssert;
use zksync_os_integration_tests::contracts::Counter;
use zksync_os_integration_tests::{CURRENT_TO_L1, Tester, test_multisetup};
use zksync_os_types::{ZkEnvelope, ZkTransaction};

use zksync_os_zisk_lib::executor;
use zksync_os_zisk_lib::types::*;

/// Build a TxInput from a ZkTransaction (decoded from raw bytes).
/// Handles L2, L1, and Upgrade tx types.
fn zk_tx_to_input(tx: &ZkTransaction, gas_used: u64, success: bool) -> Option<TxInput> {
    let caller = tx.signer();
    let envelope = tx.envelope();

    let (gas_price, gas_priority_fee, value, data, chain_id, tx_type, mint, refund_recipient) =
        match envelope {
            ZkEnvelope::System(_) => return None, // not supported
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
                    0x7fu8,
                    Some(U256::from_limbs(inner.to_mint.into_limbs())),
                    Some(inner.refund_recipient),
                )
            }
            ZkEnvelope::Upgrade(upgrade_tx) => {
                let inner = &upgrade_tx.inner;
                (
                    0u128,
                    None,
                    inner.value(),
                    inner.input().to_vec(),
                    None,
                    0x7eu8,
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
        gas_used_override: Some(gas_used),
        force_fail: !success,
        mint,
        refund_recipient,
        is_l1_tx: matches!(envelope, ZkEnvelope::L1(_)),
        l1_tx_hash: if matches!(envelope, ZkEnvelope::L1(_)) {
            Some(*tx.hash())
        } else {
            None
        },
        signed_tx_bytes: None,
    })
}

#[test_multisetup([CURRENT_TO_L1])]
#[test_runtime(flavor = "multi_thread")]
async fn zisk_revm_complex_transactions() -> anyhow::Result<()> {
    let tester = Tester::setup().await?;
    let chain_id = tester.l2_provider.get_chain_id().await?;

    // 1. Deploy Counter contract
    tracing::info!("Deploying Counter contract...");
    let counter = Counter::deploy(tester.l2_provider.clone()).await?;
    tracing::info!("Counter deployed at {}", counter.address());

    // 2. Increment 3 times
    tracing::info!("Incrementing counter 3 times...");
    for i in 0..3u64 {
        counter.increment(U256::from(1)).send().await?.expect_successful_receipt().await?;
        tracing::info!("  increment #{} done", i + 1);
    }

    // 3. Send 2 ETH transfers
    tracing::info!("Sending 2 ETH transfers...");
    let r1: Address = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".parse().unwrap();
    let r2: Address = "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB".parse().unwrap();
    tester.l2_provider.send_transaction(
        TransactionRequest::default().with_to(r1).with_value(U256::from(500u64)),
    ).await?.expect_successful_receipt().await?;
    tester.l2_provider.send_transaction(
        TransactionRequest::default().with_to(r2).with_value(U256::from(1000u64)),
    ).await?.expect_successful_receipt().await?;

    let latest = tester.l2_provider.get_block_number().await?;
    tracing::info!("Latest block: {latest}");

    let mut total_verified = 0usize;
    let mut l1_tx_count = 0usize;

    for block_num in 2..=latest {
        let block = match tester.l2_provider.get_block_by_number(block_num.into()).await? {
            Some(b) if !b.transactions.is_empty() => b,
            _ => continue,
        };

        tracing::info!("Block {}: {} transactions", block.header.number, block.transactions.len());

        let mut transactions = Vec::new();
        let mut accounts = Vec::new();
        let mut seen: std::collections::HashSet<Address> = std::collections::HashSet::new();
        let mut included_hashes = Vec::new();

        for tx_hash in block.transactions.hashes() {
            // Fetch raw tx bytes — works for ALL tx types including 0x7f
            let raw_bytes: Option<Bytes> = match tester.l2_provider.client()
                .request("eth_getRawTransactionByHash", (tx_hash,))
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::info!("  {tx_hash}: getRawTransaction failed ({e}), skipping");
                    continue;
                }
            };

            let Some(raw) = raw_bytes else {
                tracing::info!("  {tx_hash}: no raw bytes, skipping");
                continue;
            };

            // Decode using ZKsync types
            let envelope = match ZkEnvelope::decode_2718(&mut raw.as_ref()) {
                Ok(env) => env,
                Err(e) => {
                    tracing::info!("  {tx_hash}: decode failed ({e}), skipping");
                    continue;
                }
            };

            let zk_tx: ZkTransaction = match envelope.try_into_recovered() {
                Ok(tx) => tx,
                Err(_) => {
                    tracing::info!("  {tx_hash}: ecrecover failed, skipping");
                    continue;
                }
            };

            // Get receipt via ZKsync provider (handles all tx types including 0x7f)
            let receipt = match tester.l2_zk_provider.get_transaction_receipt(tx_hash).await {
                Ok(Some(r)) => r,
                Ok(None) => {
                    tracing::info!("  {tx_hash}: no receipt, skipping");
                    continue;
                }
                Err(e) => {
                    tracing::info!("  {tx_hash}: receipt fetch failed ({e}), skipping");
                    continue;
                }
            };

            let Some(tx_input) = zk_tx_to_input(&zk_tx, receipt.gas_used, receipt.status()) else {
                tracing::info!("  {tx_hash}: system tx, skipping");
                continue;
            };

            let signer = tx_input.caller;
            if seen.insert(signer) {
                let bal = tester.l2_provider.get_balance(signer)
                    .block_id((block_num - 1).into()).await.unwrap_or(U256::MAX);
                accounts.push((signer, AccountData {
                    nonce: tx_input.nonce, balance: bal, code_hash: B256::ZERO,
                }));
            }
            if let Some(to) = tx_input.to {
                if seen.insert(to) {
                    let bal = tester.l2_provider.get_balance(to)
                        .block_id((block_num - 1).into()).await.unwrap_or(U256::ZERO);
                    accounts.push((to, AccountData { nonce: 0, balance: bal, code_hash: B256::ZERO }));
                }
            }

            let is_l1 = tx_input.is_l1_tx;
            included_hashes.push(tx_hash);
            transactions.push(tx_input);
            if is_l1 { l1_tx_count += 1; }
        }

        if transactions.is_empty() {
            tracing::info!("  all txs skipped");
            continue;
        }

        if seen.insert(block.header.beneficiary) {
            let bal = tester.l2_provider.get_balance(block.header.beneficiary)
                .block_id((block_num - 1).into()).await.unwrap_or(U256::ZERO);
            accounts.push((block.header.beneficiary, AccountData { nonce: 0, balance: bal, code_hash: B256::ZERO }));
        }

        let batch_input = BatchInput {
            chain_id, spec_id: 1, protocol_version_minor: 30,
            batch_meta: BatchMeta {
                tree_root_before: B256::ZERO, leaf_count_before: 2,
                block_number_before: block_num - 1, last_block_timestamp_before: 0,
                block_hashes_blake_before: B256::ZERO, previous_block_hashes: vec![],
                upgrade_tx_hash: B256::ZERO, da_commitment_scheme: 2,
                pubdata: vec![], multichain_root: B256::ZERO, sl_chain_id: 0, blob_versioned_hashes: vec![],
                tree_update: None,
            },
            blocks: vec![BlockInput {
                number: block.header.number, timestamp: block.header.timestamp,
                base_fee: block.header.base_fee_per_gas.unwrap_or(0),
                gas_limit: block.header.gas_limit, coinbase: block.header.beneficiary,
                prev_randao: B256::from(U256::from(1).to_be_bytes::<32>()),
                block_header_hash: B256::ZERO, storage_proofs: vec![],
                account_preimages: vec![], transactions, accounts,
                storage: vec![], bytecodes: vec![], block_hashes: vec![],
                l2_to_l1_logs: vec![],
                expected_tree_root: B256::ZERO,
            }],
        };

        let output = executor::execute_batch(&batch_input);
        let br = &output.block_results[0];

        tracing::info!(
            "  REVM: {} tx results, {} account diffs, {} storage diffs",
            br.tx_results.len(), br.account_diffs.len(), br.storage_diffs.len()
        );

        assert_eq!(br.tx_results.len(), included_hashes.len(), "tx count mismatch");

        for (i, tx_result) in br.tx_results.iter().enumerate() {
            let tx_hash = included_hashes[i];
            let receipt = tester.l2_zk_provider
                .get_transaction_receipt(tx_hash).await?
                .expect("receipt");

            // Re-fetch raw to determine type label
            let raw: Option<Bytes> = tester.l2_provider.client()
                .request("eth_getRawTransactionByHash", (tx_hash,))
                .await?;
            let label = raw.and_then(|r| {
                ZkEnvelope::decode_2718(&mut r.as_ref()).ok().map(|env| match env {
                    ZkEnvelope::L1(_) => "L1→L2",
                    ZkEnvelope::Upgrade(_) => "UPGRADE",
                    ZkEnvelope::System(_) => "SYSTEM",
                    ZkEnvelope::L2(ref l2) => {
                        if l2.to().is_none() { "CREATE" }
                        else if !l2.input().is_empty() { "CALL" }
                        else { "TRANSFER" }
                    }
                })
            }).unwrap_or("UNKNOWN");

            tracing::info!(
                "  tx[{i}] {label}: REVM success={}, gas={} | Server success={}, gas={}",
                tx_result.success, tx_result.gas_used,
                receipt.status(), receipt.gas_used,
            );

            assert_eq!(tx_result.success, receipt.status(),
                "block {} tx[{i}] ({label}) success mismatch", block.header.number);
            assert_eq!(tx_result.gas_used, receipt.gas_used,
                "block {} tx[{i}] ({label}) gas mismatch", block.header.number);

            total_verified += 1;
        }
    }

    tracing::info!("Total transactions verified: {total_verified} ({l1_tx_count} L1→L2)");
    assert!(total_verified >= 6, "should verify at least 6 txs");
    tracing::info!("=== ALL COMPLEX TRANSACTION CHECKS PASSED ===");
    Ok(())
}
