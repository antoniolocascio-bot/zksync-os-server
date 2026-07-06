//! Integration test: verifies the ZiSK prover input pipeline produces
//! a BatchInput that the ZiSK REVM executor can successfully execute,
//! matching the server's execution results.

use alloy::consensus::Transaction;
use alloy::eips::{Decodable2718, Encodable2718};
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use zksync_os_integration_tests::assert_traits::ReceiptAssert;
use zksync_os_integration_tests::provider::ZksyncApi;
use zksync_os_integration_tests::{CURRENT_TO_L1, Tester, test_multisetup};
use zksync_os_types::{ZkEnvelope, ZkTransaction};

use zksync_os_zisk_lib::executor;
use zksync_os_zisk_lib::types::*;

/// End-to-end test: send ETH transfer, construct BatchInput from RPC data
/// (same conversion as the server's zisk_input_builder), execute with ZiSK REVM.
#[test_multisetup([CURRENT_TO_L1])]
#[test_runtime(flavor = "multi_thread")]
async fn zisk_pipeline_e2e() -> anyhow::Result<()> {
    let tester = Tester::setup().await?;
    let chain_id = tester.l2_provider.get_chain_id().await?;
    let recipient: Address = "0xdead000000000000000000000000000000000001".parse()?;

    // 1. Send ETH transfer
    let receipt = tester
        .l2_provider
        .send_transaction(
            TransactionRequest::default()
                .with_to(recipient)
                .with_value(U256::from(1_000_000_000_000_000_000u128)),
        )
        .await?
        .expect_successful_receipt()
        .await?;

    let block_number = receipt.block_number.expect("block number");
    tracing::info!("tx in block {block_number}");

    // 2. Wait for batch
    let batch_number = tester
        .l2_zk_provider
        .wait_batch_number_by_block_number(block_number)
        .await?;
    tracing::info!("block {block_number} in batch {batch_number}");

    // 3. Fetch block
    let block = tester
        .l2_provider
        .get_block_by_number(block_number.into())
        .await?
        .expect("block");

    // 4. Build BatchInput from RPC data (same logic as server's zisk_input_builder)
    let mut transactions = Vec::new();
    let mut accounts = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for tx_hash in block.transactions.hashes() {
        // Fetch raw encoded tx bytes
        let raw_bytes: Option<Bytes> = tester
            .l2_provider
            .client()
            .request("eth_getRawTransactionByHash", (tx_hash,))
            .await?;
        let raw = match raw_bytes {
            Some(b) if !b.is_empty() => b,
            _ => continue,
        };

        // Decode and recover signer
        let envelope = match ZkEnvelope::decode_2718(&mut raw.as_ref()) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let zk_tx: ZkTransaction = match envelope.try_into_recovered() {
            Ok(t) => t,
            Err(_) => continue,
        };

        // Fetch receipt for gas_used
        let tx_receipt = tester
            .l2_provider
            .get_transaction_receipt(tx_hash)
            .await?
            .expect("receipt");

        let caller = zk_tx.signer();
        if seen.insert(caller) {
            let bal = tester.l2_provider.get_balance(caller).await.unwrap_or(U256::ZERO);
            accounts.push((caller, AccountData {
                nonce: zk_tx.nonce(),
                balance: bal,
                code_hash: B256::ZERO,
            }));
        }
        if let Some(to) = zk_tx.to() {
            if seen.insert(to) {
                let bal = tester.l2_provider.get_balance(to).await.unwrap_or(U256::ZERO);
                accounts.push((to, AccountData {
                    nonce: 0,
                    balance: bal,
                    code_hash: B256::ZERO,
                }));
            }
        }

        let encoded_bytes = zk_tx.envelope().encoded_2718();
        let (gas_price, gas_priority_fee, value, data, cid, tx_type, mint, rr, is_l1, l1h) =
            match zk_tx.envelope() {
                ZkEnvelope::System(_) => continue,
                ZkEnvelope::L2(l2) => (
                    l2.max_fee_per_gas(), l2.max_priority_fee_per_gas(),
                    l2.value(), l2.input().to_vec(), l2.chain_id(),
                    l2.tx_type() as u8, None, None, false, None,
                ),
                ZkEnvelope::L1(l1) => {
                    let i = &l1.inner;
                    (l1.max_fee_per_gas(), l1.max_priority_fee_per_gas(),
                     i.value(), i.input().to_vec(), None, 0x7f,
                     Some(U256::from_limbs(i.to_mint.into_limbs())),
                     Some(i.refund_recipient), true, Some(i.hash))
                }
                ZkEnvelope::Upgrade(u) => {
                    let i = &u.inner;
                    (0, None, i.value(), i.input().to_vec(), None, 0x7e,
                     Some(U256::from_limbs(i.to_mint.into_limbs())),
                     Some(i.refund_recipient), true, Some(i.hash))
                }
            };

        transactions.push(TxInput {
            caller,
            gas_limit: zk_tx.gas_limit(),
            gas_price,
            gas_priority_fee: gas_priority_fee.or(Some(0)),
            to: zk_tx.to(),
            value, data,
            nonce: zk_tx.nonce(),
            chain_id: cid,
            tx_type,
            gas_used_override: Some(tx_receipt.gas_used),
            force_fail: !tx_receipt.status(),
            mint, refund_recipient: rr,
            is_l1_tx: is_l1,
            l1_tx_hash: l1h,
            signed_tx_bytes: Some(encoded_bytes),
        });
    }

    let coinbase = block.header.beneficiary;
    if seen.insert(coinbase) {
        accounts.push((coinbase, AccountData {
            nonce: 0, balance: U256::ZERO, code_hash: B256::ZERO,
        }));
    }

    let batch_input = BatchInput {
        chain_id,
        spec_id: 1,
        protocol_version_minor: 30,
        batch_meta: BatchMeta {
            tree_root_before: B256::ZERO, leaf_count_before: 0,
            block_number_before: block_number - 1,
            last_block_timestamp_before: 0,
            block_hashes_blake_before: B256::ZERO,
            previous_block_hashes: vec![],
            upgrade_tx_hash: B256::ZERO,
            da_commitment_scheme: 0, pubdata: vec![],
            multichain_root: B256::ZERO, sl_chain_id: 0,
            blob_versioned_hashes: vec![], tree_update: None,
        },
        blocks: vec![BlockInput {
            number: block_number,
            timestamp: block.header.timestamp,
            base_fee: block.header.base_fee_per_gas.unwrap_or(0),
            gas_limit: block.header.gas_limit,
            coinbase,
            prev_randao: B256::from(U256::from(1).to_be_bytes::<32>()),
            block_header_hash: B256::ZERO,
            storage_proofs: vec![], account_preimages: vec![],
            transactions, accounts,
            storage: vec![], bytecodes: vec![],
            block_hashes: vec![], l2_to_l1_logs: vec![],
            expected_tree_root: B256::ZERO,
        }],
    };

    // 5. Execute via ZiSK REVM
    let output = executor::execute_batch(&batch_input);
    assert_eq!(output.block_results.len(), 1);

    let br = &output.block_results[0];
    for (i, tx) in br.tx_results.iter().enumerate() {
        let server_gas = batch_input.blocks[0].transactions[i].gas_used_override.unwrap();
        tracing::info!(
            "tx[{i}]: REVM success={}, gas={} | Server gas={server_gas}",
            tx.success, tx.gas_used,
        );
        assert_eq!(tx.gas_used, server_gas, "gas mismatch for tx[{i}]");
    }

    assert!(
        br.account_diffs.iter().any(|d| d.balance_after < d.balance_before),
        "expected sender balance decrease from ETH transfer"
    );

    tracing::info!("=== ZISK PIPELINE E2E TEST PASSED ===");
    Ok(())
}
