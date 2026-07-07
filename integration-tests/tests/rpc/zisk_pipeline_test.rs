//! End-to-end test of the ZiSK second-proof-system input pipeline.
//!
//! Drives real transactions through the node, then fetches the
//! server-assembled ZiSK `BatchInput` from the prover API's
//! `/ZiSK/{batch}/peek` endpoint — the exact bytes an external ZiSK prover
//! would receive — and re-executes it with the ZiSK REVM executor, checking
//! the execution results against the RPC receipts.
//!
//! Requires prover input generation (the ZiSK `BatchInput` is assembled
//! alongside the Airbender witness); the test skips itself when input
//! generation is disabled (`no-pig` test profile).

use alloy::network::{ReceiptResponse, TransactionBuilder};
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use base64::Engine;
use std::time::Duration;
use zksync_os_alloy_ext::provider::ZksyncApi;
use zksync_os_integration_tests::assert_traits::ReceiptAssert;
use zksync_os_integration_tests::{CURRENT_TO_L1, Tester, test_multisetup};

use zksync_os_zisk_lib::executor;

#[derive(serde::Deserialize)]
struct ZiskBatchDataPayload {
    batch_number: u64,
    #[allow(dead_code)]
    vk_hash: String,
    zisk_data: String,
}

/// Poll the prover API until the batch's ZiSK data is available.
async fn peek_zisk_data(prover_api_url: &str, batch_number: u64) -> anyhow::Result<Vec<u8>> {
    let url = format!("{prover_api_url}/prover-jobs/v1/ZiSK/{batch_number}/peek");
    let client = reqwest::Client::new();
    for _ in 0..120 {
        let response = client.get(&url).send().await?;
        if response.status().is_success() {
            let payload: ZiskBatchDataPayload = response.json().await?;
            anyhow::ensure!(payload.batch_number == batch_number, "batch number mismatch");
            return Ok(base64::engine::general_purpose::STANDARD.decode(payload.zisk_data)?);
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!("timed out waiting for ZiSK data of batch {batch_number} at {url}")
}

#[test_multisetup([CURRENT_TO_L1])]
#[test_runtime(flavor = "multi_thread")]
async fn zisk_pipeline_e2e() -> anyhow::Result<()> {
    let tester = Tester::setup().await?;

    if !tester
        .config()
        .prover_input_generator_config
        .enable_input_generation
    {
        tracing::warn!("prover input generation disabled — skipping ZiSK pipeline test");
        return Ok(());
    }
    let Some(prover_api_url) = tester.prover_api_url() else {
        tracing::warn!("prover API not bound — skipping ZiSK pipeline test");
        return Ok(());
    };

    let recipient: Address = "0xdead000000000000000000000000000000000001".parse()?;

    // 1. Drive real traffic: an ETH transfer and a contract deployment.
    let transfer_receipt = tester
        .l2_provider
        .send_transaction(
            TransactionRequest::default()
                .with_to(recipient)
                .with_value(U256::from(1_000_000_000_000_000_000u128)),
        )
        .await?
        .expect_successful_receipt()
        .await?;

    // Minimal deployment: contract with code `0x00` (STOP).
    // Init code: PUSH1 0x01 PUSH1 0x0c PUSH1 0x00 CODECOPY PUSH1 0x01 PUSH1 0x00 RETURN
    let init_code = alloy::hex::decode("6001600c60003960016000f300")?;
    let deploy_receipt = tester
        .l2_provider
        .send_transaction(TransactionRequest::default().with_deploy_code(init_code))
        .await?
        .expect_successful_receipt()
        .await?;

    // 2. Wait for the blocks to be batched.
    let mut batches = Vec::new();
    for receipt in [&transfer_receipt, &deploy_receipt] {
        let block_number = receipt.block_number().expect("receipt has block number");
        let batch_number = tester
            .l2_zk_provider
            .wait_batch_number_by_block_number(block_number)
            .await?;
        batches.push((batch_number, block_number, receipt));
    }

    // 3. For each touched batch — plus batch 1, which contains the genesis
    //    upgrade block and its mass force-deployments (the upgrade-batch
    //    fidelity case: every force-deployed account's code-derived property
    //    fields are recomputed and asserted by the executor) — fetch the
    //    server-assembled BatchInput and re-execute it with the ZiSK REVM
    //    executor.
    let mut batch_numbers: Vec<u64> = batches.iter().map(|(batch, _, _)| *batch).collect();
    batch_numbers.push(1);
    batch_numbers.sort_unstable();
    batch_numbers.dedup();
    for batch_number in &batch_numbers {
        let zisk_bytes = peek_zisk_data(&prover_api_url, *batch_number).await?;
        let (output, commitment) = executor::execute_and_commit_from_bincode(&zisk_bytes)
            .map_err(|e| anyhow::anyhow!("ZiSK executor failed for batch {batch_number}: {e}"))?;

        assert_ne!(commitment, B256::ZERO, "batch commitment must be non-trivial");
        assert!(
            !output.block_results.is_empty(),
            "batch {batch_number} produced no block results"
        );

        // Cross-check the driven transactions' execution against RPC receipts.
        for (_, block_number, receipt) in batches
            .iter()
            .filter(|(batch, _, _)| batch == batch_number)
        {
            let block_result = output
                .block_results
                .iter()
                .find(|br| br.block_number == *block_number)
                .unwrap_or_else(|| panic!("block {block_number} missing from batch {batch_number}"));
            let tx_index = receipt.transaction_index().expect("receipt has tx index") as usize;
            let tx_result = &block_result.tx_results[tx_index];
            assert!(tx_result.success, "tx must succeed in ZiSK re-execution");
            assert_eq!(
                tx_result.gas_used,
                receipt.gas_used(),
                "gas mismatch for tx {} in block {block_number}",
                receipt.transaction_hash()
            );
        }

        tracing::info!(
            batch_number,
            %commitment,
            blocks = output.block_results.len(),
            "ZiSK executor reproduced the batch"
        );
    }

    Ok(())
}
