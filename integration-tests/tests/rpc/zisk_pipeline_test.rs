//! End-to-end tests of the ZiSK second-proof-system input pipeline.
//!
//! Drives real transactions through the node, then fetches the
//! server-assembled ZiSK `BatchInput` from the prover API's
//! `/ZiSK/{batch}/peek` endpoint — the exact bytes an external ZiSK prover
//! would receive — and re-executes it with the ZiSK REVM executor, checking
//! the execution results against the RPC receipts.
//!
//! Neither test finalizes batches on L1 (that would need SNARK proving), so
//! blocks are located in batches by re-executing the peeked inputs and
//! matching block numbers, not via the batch-by-block RPC (which only serves
//! finalized batches). Under the `no-pig` profile both tests skip themselves.

use alloy::network::{ReceiptResponse, TransactionBuilder};
use alloy::primitives::{Address, B256, U256};
use alloy::providers::Provider;
use alloy::rpc::types::TransactionRequest;
use base64::Engine;
use std::time::Duration;
use zksync_os_integration_tests::CURRENT_TO_L1;
use zksync_os_integration_tests::assert_traits::ReceiptAssert;
use zksync_os_integration_tests::l1_helpers::wait_for_l1_state;
use zksync_os_integration_tests::test_config::make_commit_only_config;
use zksync_os_zisk_lib::executor;
use zksync_os_zisk_lib::types::BatchOutput;

#[derive(serde::Deserialize)]
struct ZiskBatchDataPayload {
    batch_number: u64,
    #[allow(dead_code)]
    vk_hash: String,
    zisk_data: String,
}

/// Single-shot peek: the batch's ZiSK input if it is currently available.
async fn peek_zisk_data_once(
    client: &reqwest::Client,
    prover_api_url: &str,
    batch_number: u64,
) -> anyhow::Result<Option<Vec<u8>>> {
    let url = format!("{prover_api_url}/prover-jobs/v1/ZiSK/{batch_number}/peek");
    let response = client.get(&url).send().await?;
    // Only 200 carries a payload; 204 means the batch is not in the FRI job
    // map (yet), 404 that its ProverInput carries no ZiSK data.
    if response.status() != reqwest::StatusCode::OK {
        return Ok(None);
    }
    let payload: ZiskBatchDataPayload = response.json().await?;
    anyhow::ensure!(payload.batch_number == batch_number, "batch number mismatch");
    Ok(Some(
        base64::engine::general_purpose::STANDARD.decode(payload.zisk_data)?,
    ))
}

/// Poll the prover API until the batch's ZiSK data is available; None on timeout.
async fn try_peek_zisk_data(
    prover_api_url: &str,
    batch_number: u64,
) -> anyhow::Result<Option<Vec<u8>>> {
    let client = reqwest::Client::new();
    for _ in 0..120 {
        if let Some(bytes) = peek_zisk_data_once(&client, prover_api_url, batch_number).await? {
            return Ok(Some(bytes));
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Ok(None)
}

/// Poll the prover API until the batch's ZiSK data is available.
async fn peek_zisk_data(prover_api_url: &str, batch_number: u64) -> anyhow::Result<Vec<u8>> {
    try_peek_zisk_data(prover_api_url, batch_number)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!("timed out waiting for ZiSK data of batch {batch_number}")
        })
}

/// Scan peekable batches until one's re-executed input contains
/// `block_number`; returns its batch number, execution output and commitment.
async fn wait_input_containing_block(
    prover_api_url: &str,
    max_batch: u64,
    block_number: u64,
) -> anyhow::Result<(u64, BatchOutput, B256)> {
    let client = reqwest::Client::new();
    for _ in 0..120 {
        for batch_number in 2..=max_batch {
            let Some(bytes) =
                peek_zisk_data_once(&client, prover_api_url, batch_number).await?
            else {
                continue;
            };
            let (output, commitment) = executor::execute_and_commit_from_bincode(&bytes)
                .map_err(|e| {
                    anyhow::anyhow!("ZiSK executor failed for batch {batch_number}: {e}")
                })?;
            if output
                .block_results
                .iter()
                .any(|br| br.block_number == block_number)
            {
                return Ok((batch_number, output, commitment));
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!("timed out waiting for a ZiSK batch input containing block {block_number}")
}

#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn zisk_pipeline_e2e() -> anyhow::Result<()> {
    // This test drives prover input generation explicitly; honor the
    // profile's intent by skipping.
    if std::env::var("NEXTEST_PROFILE").as_deref() == Ok("no-pig") {
        tracing::warn!("no-pig profile — skipping ZiSK pipeline test");
        return Ok(());
    }

    let env = CURRENT_TO_L1.environment().await?;
    let mut config = env.default_config().await?;
    // Both in-process fake provers off: the harness keeps the prover API
    // bound (it disables the API when both fakes run), and FRI jobs stay in
    // the job map so /ZiSK/{batch}/peek can serve them.
    config.prover_api_config.fake_fri_provers.enabled = false;
    config.prover_api_config.fake_snark_provers.enabled = false;
    let tester = env.launch(config).await?;

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

    // 2. For each driven transaction, find the server-assembled BatchInput
    //    whose ZiSK re-execution contains its block, and cross-check the
    //    execution against the RPC receipt. (No prover consumes jobs in this
    //    config, so every generated batch input stays peekable.)
    for receipt in [&transfer_receipt, &deploy_receipt] {
        let block_number = receipt.block_number().expect("receipt has block number");
        let (batch_number, output, commitment) =
            wait_input_containing_block(&prover_api_url, 8, block_number).await?;

        assert_ne!(commitment, B256::ZERO, "batch commitment must be non-trivial");
        let block_result = output
            .block_results
            .iter()
            .find(|br| br.block_number == block_number)
            .expect("scan matched this block");
        let tx_index = receipt.transaction_index().expect("receipt has tx index") as usize;
        let tx_result = &block_result.tx_results[tx_index];
        assert!(tx_result.success, "tx must succeed in ZiSK re-execution");
        assert_eq!(
            tx_result.gas_used,
            receipt.gas_used(),
            "gas mismatch for tx {} in block {block_number}",
            receipt.transaction_hash()
        );

        tracing::info!(
            batch_number,
            block_number,
            %commitment,
            "ZiSK executor reproduced the batch"
        );
    }

    // 3. Batch 1 contains the genesis upgrade block and its mass
    //    force-deployments (the upgrade-batch fidelity case: every
    //    force-deployed account's code-derived property fields are recomputed
    //    and asserted by the executor).
    let zisk_bytes = peek_zisk_data(&prover_api_url, 1).await?;
    let (output, commitment) = executor::execute_and_commit_from_bincode(&zisk_bytes)
        .map_err(|e| anyhow::anyhow!("ZiSK executor failed for batch 1: {e}"))?;
    assert_ne!(commitment, B256::ZERO, "batch commitment must be non-trivial");
    assert!(
        !output.block_results.is_empty(),
        "batch 1 produced no block results"
    );
    tracing::info!(%commitment, "ZiSK executor reproduced the genesis-upgrade batch");

    Ok(())
}

/// Crash-recovery property of the ZiSK lane: `ZiskDataCache` is in-memory, so
/// a restart between batch commit and SNARK arrival loses the batch's
/// `BatchInput`. Committed-but-unproven batches must regain their ZiSK input
/// on restart by flowing through the batcher's recreation path and the prover
/// input generator again.
#[test_log::test(tokio::test(flavor = "multi_thread"))]
async fn zisk_input_regenerated_after_restart() -> anyhow::Result<()> {
    // This test drives prover input generation explicitly (the commit-only
    // config keeps it on), so honor the profile's intent by skipping.
    if std::env::var("NEXTEST_PROFILE").as_deref() == Ok("no-pig") {
        tracing::warn!("no-pig profile — skipping ZiSK restart test");
        return Ok(());
    }

    let env = CURRENT_TO_L1.environment().await?;
    let mut config = env.default_config().await?;
    // Fake FRI provers on, SNARK provers off: batches commit on L1 and then
    // stay unproven, exactly the window where a restart loses in-memory state.
    make_commit_only_config(&mut config);
    let tester = env.launch(config).await?;
    if tester.prover_api_url().is_none() {
        tracing::warn!("prover API not bound — skipping ZiSK restart test");
        return Ok(());
    }

    // Drive a transaction so batch 2 has real content, then wait for it to be
    // committed (batch 1 is the genesis-upgrade batch; the tx lands in a
    // later batch).
    tester
        .l2_provider
        .send_transaction(
            TransactionRequest::default()
                .with_to(Address::random())
                .with_value(U256::from(1u64)),
        )
        .await?
        .expect_successful_receipt()
        .await?;

    let committed_state = wait_for_l1_state(&tester, "a post-genesis committed batch", |state| {
        state.last_committed_batch >= 2
    })
    .await?;
    assert_eq!(
        committed_state.last_proved_batch, 0,
        "SNARK proving is disabled, so committed batches must stay unproven"
    );

    // Restart with FRI provers disabled: recreated batches enter the FRI job
    // map and stay there, so the regenerated ZiSK input remains peekable.
    let restarted = tester
        .restart_with_overrides(|config| {
            config.prover_api_config.fake_fri_provers.enabled = false;
        })
        .await?;
    let Some(prover_api_url) = restarted.prover_api_url() else {
        tracing::warn!("prover API not bound — skipping ZiSK restart test");
        return Ok(());
    };

    // Every committed-but-unproven batch — the genesis-upgrade batch included
    // — must reappear with a valid, executable BatchInput; committed batches
    // are recreated with their original numbers.
    for batch_number in 1..=committed_state.last_committed_batch {
        let zisk_bytes = peek_zisk_data(&prover_api_url, batch_number).await?;
        let (output, commitment) = executor::execute_and_commit_from_bincode(&zisk_bytes)
            .map_err(|e| {
                anyhow::anyhow!("regenerated input for batch {batch_number} failed: {e}")
            })?;
        assert_ne!(commitment, B256::ZERO, "batch commitment must be non-trivial");
        assert!(
            !output.block_results.is_empty(),
            "batch {batch_number} produced no block results"
        );
        tracing::info!(
            batch_number,
            %commitment,
            "ZiSK input regenerated and re-executed after restart"
        );
    }

    Ok(())
}
