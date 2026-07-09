//! Cross-lane witness consistency through the v30->v31 upgrade — CPU only.
//!
//! The multiprover property, checked without provers: for every batch, the
//! Airbender witness replayed through the matching app binary on the RISC-V
//! simulator must reproduce the same batch public input that the ZiSK/REVM
//! guest computes from its own witness. A mismatch here means one of the
//! lanes (or the batcher) would reject or fail to prove the batch on real
//! hardware — this test surfaces that in minutes, before any GPU time.
//!
//! Runs the same scenario as `real_provers_across_v30_to_v31_upgrade_on_l1`
//! (fake provers instead of real ones): boot v30.2 on L1, force-deploy the
//! v31 SystemContext via the BytecodesSupplier, execute the upgrade, drive
//! v31 traffic, and check every captured batch on both sides of the
//! boundary.

use std::collections::BTreeMap;
use std::time::Duration;

use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, B256, U256, keccak256};
use alloy::providers::Provider;
use alloy::sol_types::SolCall;
use alloy::providers::ext::AnvilApi;
use alloy::rpc::types::TransactionRequest;
use base64::Engine;
use zksync_os_integration_tests::CURRENT_TO_L1;
use zksync_os_integration_tests::contracts::{BytecodesSupplierV31, SystemContextV31};
use zksync_os_integration_tests::provider::ZksyncTestingProvider;
use zksync_os_integration_tests::upgrade::{Action, CommitterFacetV31, FacetCut, UpgradeTester};
use zksync_os_types::ProvingVersion;

/// One batch's captured prover inputs.
struct CapturedBatch {
    vk_hash: String,
    airbender_witness: Vec<u32>,
    zisk_input: Vec<u8>,
}

async fn peek_json(url: String) -> anyhow::Result<Option<serde_json::Value>> {
    let response = reqwest::Client::new().get(url).send().await?;
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        return Ok(None);
    }
    Ok(Some(response.error_for_status()?.json().await?))
}

/// Poll both peek endpoints for `batch` until present (or `deadline`).
async fn capture_batch(
    prover_api_url: &str,
    batch: u64,
    deadline: Duration,
) -> anyhow::Result<Option<CapturedBatch>> {
    let started = std::time::Instant::now();
    loop {
        let fri = peek_json(format!(
            "{prover_api_url}/prover-jobs/v1/FRI/{batch}/peek"
        ))
        .await?;
        let zisk = peek_json(format!(
            "{prover_api_url}/prover-jobs/v1/ZiSK/{batch}/peek"
        ))
        .await?;
        if let (Some(fri), Some(zisk)) = (fri, zisk) {
            let b64 = base64::engine::general_purpose::STANDARD;
            let witness_bytes = b64.decode(
                fri.get("prover_input")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default(),
            )?;
            return Ok(Some(CapturedBatch {
                vk_hash: fri
                    .get("vk_hash")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_owned(),
                airbender_witness: witness_bytes
                    .chunks_exact(4)
                    .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
                    .collect(),
                zisk_input: b64.decode(
                    zisk.get("zisk_data")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default(),
                )?,
            }));
        }
        if started.elapsed() > deadline {
            return Ok(None);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
}

/// The Airbender-formula public input derived from the ZiSK guest's
/// re-execution: keccak(state_before ‖ state_after ‖ batch_output), as LE
/// u32 register values.
fn guest_expected_registers(zisk_input: &[u8]) -> anyhow::Result<[u32; 8]> {
    let input: zksync_os_zisk_lib::types::BatchInput = bincode1::deserialize(zisk_input)?;
    let (_output, _commitment, state_before, state_after, batch_hash) =
        zksync_os_zisk_lib::executor::execute_and_commit_debug(&input);
    let pi: B256 = keccak256([state_before.0, state_after.0, batch_hash.0].concat());
    Ok(pi
        .0
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap())
}

#[test_log::test(tokio::test)]
async fn witness_consistency_across_v30_to_v31_upgrade() -> anyhow::Result<()> {
    if std::env::var("NEXTEST_PROFILE").as_deref() == Ok("no-pig") {
        tracing::warn!("no-pig profile — skipping witness consistency test");
        return Ok(());
    }

    let env = CURRENT_TO_L1.environment().await?;
    let mut config = env.default_config().await?;
    // Fake provers keep finality moving; a raised min_age keeps FRI jobs
    // peekable long enough to capture them before the fakes consume them.
    config.prover_api_config.fake_fri_provers.min_age = Duration::from_secs(10);
    config.prover_api_config.max_fris_per_snark = 1;
    config.prover_input_generator_config.second_proof_system = true;
    let tester = env.launch(config).await?;
    if !tester
        .config()
        .prover_input_generator_config
        .enable_input_generation
    {
        tracing::warn!("prover input generation disabled — skipping");
        return Ok(());
    }
    let Some(prover_api_url) = tester.prover_api_url() else {
        tracing::warn!("prover API not bound — skipping");
        return Ok(());
    };

    // Background capture of every batch's witnesses as they appear.
    let capture_url = prover_api_url.clone();
    let (capture_stop_tx, mut capture_stop_rx) = tokio::sync::oneshot::channel::<()>();
    let capture_task = tokio::spawn(async move {
        let mut captured: BTreeMap<u64, CapturedBatch> = BTreeMap::new();
        let mut next = 1u64;
        loop {
            match capture_batch(&capture_url, next, Duration::from_millis(600)).await {
                Ok(Some(batch)) => {
                    captured.insert(next, batch);
                    next += 1;
                    continue;
                }
                Ok(None) => {}
                Err(err) => tracing::warn!(batch = next, "capture error: {err:#}"),
            }
            if capture_stop_rx.try_recv().is_ok() {
                return captured;
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    });

    // v30 traffic.
    let recipient: Address = "0xdead000000000000000000000000000000000001".parse()?;
    tester
        .l2_provider
        .send_transaction(
            TransactionRequest::default()
                .with_to(recipient)
                .with_value(U256::from(1u64)),
        )
        .await?
        .get_receipt()
        .await?;

    // The upgrade, exactly as in the GPU test: etch the v31 supplier on L1,
    // publish the SystemContext preimage, force-deploy it at 0x800b.
    let supplier_address = tester
        .config()
        .genesis_config
        .bytecode_supplier_address
        .expect("bytecode_supplier_address must be configured");
    tester
        .l1_provider()
        .anvil_set_code(
            supplier_address,
            BytecodesSupplierV31::DEPLOYED_BYTECODE.clone(),
        )
        .await?;
    let system_context_code = SystemContextV31::DEPLOYED_BYTECODE.clone();
    let system_context_address: Address = "0x000000000000000000000000000000000000800b".parse()?;
    let force_deployments: BTreeMap<Address, alloy::primitives::Bytes> =
        [(system_context_address, system_context_code.clone())]
            .into_iter()
            .collect();

    let upgrade_tester = UpgradeTester::for_default_upgrade(&tester).await?;
    upgrade_tester
        .publish_bytecodes_to_l1_supplier([system_context_code])
        .await?;
    let protocol_upgrade = upgrade_tester
        .protocol_upgrade_builder()
        .await?
        .bump_minor(1)
        .with_force_deployments(force_deployments)
        .with_factory_deps()
        .with_timestamp(U256::from(1))
        .build();
    // Every pre-upgrade batch must be finalized before the cut retires the
    // v30 commit encoding.
    let tip = tester.l2_provider.get_block_number().await?;
    tester
        .l2_zk_provider
        .wait_finalized_with_timeout(tip, Duration::from_secs(120))
        .await?;
    let l1_chain_id = tester.l1_provider().get_chain_id().await?;
    let committer_facet =
        CommitterFacetV31::deploy(tester.l1_provider().clone(), U256::from(l1_chain_id)).await?;
    let facet_cut = FacetCut {
        facet: *committer_facet.address(),
        action: Action::Replace,
        isFreezable: true,
        selectors: vec![alloy::primitives::FixedBytes(
            CommitterFacetV31::commitBatchesSharedBridgeCall::SELECTOR,
        )],
    };
    upgrade_tester
        .execute_default_upgrade_cut_first(
            &protocol_upgrade,
            U256::MAX,
            U256::from(1),
            vec![facet_cut],
        )
        .await?;

    // v31 traffic.
    for i in 0..2u64 {
        tester
            .l2_provider
            .send_transaction(
                TransactionRequest::default()
                    .with_to(recipient)
                    .with_value(U256::from(2 + i)),
            )
            .await?
            .get_receipt()
            .await?;
    }
    // The v31 blocks must reach REAL L1 finality (commit accepted with the
    // new encoding + proven + executed) — a commit rejection cannot pass.
    let tip = tester.l2_provider.get_block_number().await?;
    tester
        .l2_zk_provider
        .wait_finalized_with_timeout(tip, Duration::from_secs(180))
        .await?;
    // Let the last batches seal and get captured.
    tokio::time::sleep(Duration::from_secs(8)).await;
    let _ = capture_stop_tx.send(());
    let captured = capture_task.await?;

    anyhow::ensure!(!captured.is_empty(), "no batches captured");
    let mut v6 = 0usize;
    let mut v7 = 0usize;

    for (number, batch) in &captured {
        // CPU-simulate the Airbender witness through the matching binary.
        let binary: &[u8] = if batch.vk_hash == ProvingVersion::V6.vk_hash() {
            v6 += 1;
            zksync_os_multivm::apps::v6::MULTIBLOCK_BATCH
        } else if batch.vk_hash == ProvingVersion::V7.vk_hash() {
            v7 += 1;
            zksync_os_multivm::apps::v7::MULTIBLOCK_BATCH
        } else {
            anyhow::bail!("batch {number}: unexpected vk hash {}", batch.vk_hash);
        };
        let registers =
            execution_utils::run_verifier_binary(binary, batch.airbender_witness.clone())
                .ok_or_else(|| {
                    anyhow::anyhow!("batch {number}: simulation did not reach the exit point")
                })?;

        // The ZiSK guest's independent view of the same batch.
        let expected = guest_expected_registers(&batch.zisk_input)?;

        anyhow::ensure!(
            registers[..8] == expected,
            "batch {number} (vk {}): Airbender-simulated PI {:?} != guest-derived PI {:?}",
            batch.vk_hash,
            &registers[..8],
            expected,
        );
        tracing::info!(batch = number, vk = %batch.vk_hash, "lanes agree");
    }

    anyhow::ensure!(v6 >= 1, "expected at least one pre-upgrade (V6) batch");
    anyhow::ensure!(v7 >= 1, "expected at least one post-upgrade (V7) batch");
    tracing::info!(total = captured.len(), v6, v7, "witness consistency verified");
    Ok(())
}
