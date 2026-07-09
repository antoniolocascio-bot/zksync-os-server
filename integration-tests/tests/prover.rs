#![cfg(feature = "prover-tests")]

use zksync_os_integration_tests::{
    CURRENT_TO_L1, NEXT_TO_GATEWAY, SettlementLayer, TestCase, TestEnvironment, test_multisetup,
};

#[cfg(feature = "gpu-prover-tests")]
mod real_prover_upgrade {
    use alloy::network::TransactionBuilder;
    use alloy::primitives::{Address, U256};
    use alloy::providers::Provider;
    use alloy::rpc::types::TransactionRequest;
    use std::time::Duration;
    use zksync_os_integration_tests::upgrade::UpgradeTester;
    use zksync_os_integration_tests::{CURRENT_TO_L1, run_zisk_gpu_prover, spawn_airbender_prover};
    use zksync_os_server::default_protocol_version::{PROTOCOL_VERSION, PROTOCOL_VERSION_V31_0};
    use zksync_os_types::ProvingVersion;

    /// Peek a batch's FRI job to learn its VK hash. `None` once the batch is
    /// unknown to the job map (not sealed yet, or already consumed).
    async fn peek_fri_vk(prover_api_url: &str, batch: u64) -> anyhow::Result<Option<String>> {
        let response = reqwest::Client::new()
            .get(format!("{prover_api_url}/prover-jobs/v1/FRI/{batch}/peek"))
            .send()
            .await?;
        if response.status() == reqwest::StatusCode::NO_CONTENT {
            return Ok(None);
        }
        let payload: serde_json::Value = response.error_for_status()?.json().await?;
        Ok(payload
            .get("vk_hash")
            .and_then(|v| v.as_str())
            .map(str::to_owned))
    }

    /// The full multi-prover flow with REAL provers across a REAL v30->v31
    /// protocol upgrade on an L1-settling chain (there is no v31-on-L1
    /// fixture — production chains reached v31 exactly this way):
    ///
    /// 1. boot the v30.2 chain with fake provers off and the ZiSK lane on
    ///    (ZiSK jobs are created at batch seal);
    /// 2. drive v30 traffic, execute the minimal v30->v31 upgrade (no force
    ///    deployments), drive v31 traffic;
    /// 3. prove every batch for real: Airbender v6 service, then Airbender
    ///    v7 service, then the ZiSK prover — strictly sequentially, all
    ///    sharing one GPU;
    /// 4. require the last batch verified on L1 (`BlocksVerification`) and
    ///    every batch's ZiSK proof accepted by the server (commitment + VK
    ///    checks at submit; the daemon exits 0 only on acceptance).
    #[test_log::test(tokio::test)]
    async fn real_provers_across_v30_to_v31_upgrade_on_l1() -> anyhow::Result<()> {
        let env = CURRENT_TO_L1.environment().await?;
        let mut config = env.default_config().await?;
        config.prover_api_config.fake_fri_provers.enabled = false;
        config.prover_api_config.fake_snark_provers.enabled = false;
        config.prover_api_config.max_fris_per_snark = 1;
        config.prover_input_generator_config.second_proof_system = true;
        // Arm the VK-drift tripwire when the recorded programVK is provided.
        if let Ok(vk) = std::env::var("ZISK_PROGRAM_VK") {
            config.prover_api_config.zisk_program_vk = Some(vk.parse()?);
        }
        let tester = env.launch_without_provers(config).await?;
        let prover_api_url = tester
            .prover_api_url()
            .expect("prover API must be bound for prover tests");

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

        // The real v30 -> v31 protocol upgrade, minimal shape: version bump +
        // no-op delegate, no force deployments (the supplier path is the v31+
        // flow; a v30 chain must not use the legacy inconsistent payload).
        let upgrade_tester = UpgradeTester::for_default_upgrade(&tester).await?;
        let protocol_upgrade = upgrade_tester
            .protocol_upgrade_builder()
            .await?
            .bump_minor(1)
            .with_timestamp(U256::from(1))
            .build();
        upgrade_tester
            .execute_default_upgrade(
                &protocol_upgrade,
                U256::MAX,
                U256::from(1),
                false,
                vec![],
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

        // Wait for sealing to settle, then split batches by proving version
        // via the FRI job map (jobs are untouched — no prover has run yet).
        let mut vks: Vec<String> = Vec::new();
        let mut quiet_rounds = 0;
        while quiet_rounds < 3 {
            tokio::time::sleep(Duration::from_secs(5)).await;
            match peek_fri_vk(&prover_api_url, vks.len() as u64 + 1).await? {
                Some(vk) => {
                    vks.push(vk);
                    quiet_rounds = 0;
                }
                None => quiet_rounds += 1,
            }
        }
        let total_batches = vks.len() as u64;
        let v6_batches = vks
            .iter()
            .take_while(|vk| vk.as_str() == ProvingVersion::V6.vk_hash())
            .count();
        let v7_batches = vks.len() - v6_batches;
        tracing::info!(total_batches, v6_batches, v7_batches, "batch inventory");
        assert!(v6_batches >= 1, "expected at least one pre-upgrade batch");
        assert!(v7_batches >= 1, "expected at least one post-upgrade batch");
        assert!(
            vks[v6_batches..]
                .iter()
                .all(|vk| vk.as_str() == ProvingVersion::V7.vk_hash()),
            "batches must switch V6 -> V7 exactly once at the upgrade boundary: {vks:?}"
        );

        // Prove everything, strictly sequentially on the single GPU:
        // Airbender v6 -> Airbender v7 -> ZiSK (both versions, one guest).
        let urls = vec![prover_api_url.clone()];
        let status = spawn_airbender_prover(&tester, PROTOCOL_VERSION, &urls, v6_batches)
            .await
            .wait()
            .await?;
        anyhow::ensure!(status.success(), "v6 Airbender prover failed: {status}");
        let status = spawn_airbender_prover(&tester, PROTOCOL_VERSION_V31_0, &urls, v7_batches)
            .await
            .wait()
            .await?;
        anyhow::ensure!(status.success(), "v7 Airbender prover failed: {status}");

        // Real proofs verified on L1 across the upgrade boundary.
        tester
            .prover_tester
            .wait_for_batch_proven(total_batches)
            .await?;

        // ZiSK lane: one guest binary proves both v30 and v31 batches; the
        // daemon exits 0 only after `total_batches` accepted submissions.
        run_zisk_gpu_prover(&prover_api_url, total_batches as usize).await;

        Ok(())
    }
}

#[test_multisetup([CURRENT_TO_L1, NEXT_TO_GATEWAY])]
async fn prover(env: TestEnvironment, test_case: TestCase) -> anyhow::Result<()> {
    // Test that prover can successfully prove at least one batch
    let mut config = env.default_config().await?;
    config.prover_api_config.fake_fri_provers.enabled = false;
    config.prover_api_config.fake_snark_provers.enabled = false;
    config.prover_input_generator_config.logging_enabled = true;
    let tester = env.launch(config).await?;

    if matches!(test_case.settlement_layer, SettlementLayer::Gateway) {
        // Gateway comes with a pre-baked state and some batches are already fake-proven there.
        // So we expect the next batch to be proven with real flow.
        let last_proven_batch = tester.owned_supporting_nodes()[0]
            .prover_tester
            .last_proven_batch()
            .await?;
        // We expect that first supporting node is gateway node.
        // Wait for the first batch to be proven on gateway node as well.
        tester.owned_supporting_nodes()[0]
            .prover_tester
            .wait_for_batch_proven(last_proven_batch + 1)
            .await?;
    }

    // Test environment comes with some L1 transactions by default, so one batch should be provable
    // without any new transactions inside the test.
    tester.prover_tester.wait_for_batch_proven(1).await?;

    // todo: consider expanding this test to prove multiple batches on top of the first batch
    //       also to test L2 transactions are provable too

    Ok(())
}
