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
    use zksync_os_integration_tests::provider::ZksyncTestingProvider;
    use zksync_os_integration_tests::upgrade::UpgradeTester;
    use zksync_os_integration_tests::{CURRENT_TO_L1, run_zisk_gpu_prover, spawn_airbender_prover};
    use zksync_os_server::default_protocol_version::{PROTOCOL_VERSION, PROTOCOL_VERSION_V31_0};

    /// How long to allow a block to reach L1 finality with real (GPU)
    /// proving in the loop: commit + FRI + SNARK wrap + prove tx + execute.
    const REAL_PROOF_FINALITY_TIMEOUT: Duration = Duration::from_secs(900);

    /// The full multi-prover flow with REAL provers across a REAL v30->v31
    /// protocol upgrade on an L1-settling chain (there is no v31-on-L1
    /// fixture — production chains reached v31 exactly this way):
    ///
    /// 1. boot the v30.2 chain with fake provers off and the ZiSK lane on
    ///    (ZiSK jobs are created at batch seal);
    /// 2. run the real Airbender v6 and v7 services in the background — the
    ///    upgrade flow *requires* live finalization before and after the
    ///    boundary, and each service skips batches whose VK it doesn't
    ///    serve (the skipped assignment times out back to pending);
    /// 3. drive v30 traffic, execute the minimal v30->v31 upgrade (no force
    ///    deployments), drive v31 traffic — `execute_default_upgrade`'s
    ///    internal finality waits assert real pre-upgrade (V6) and
    ///    upgrade-batch (V7) proofs verified on L1;
    /// 4. once the last v31 block is finalized on L1, stop the Airbender
    ///    services and run the ZiSK prover over every batch — one guest
    ///    binary proves both v30 and v31 batches; the daemon exits 0 only
    ///    after all submissions were accepted (commitment + VK checks).
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
        let urls = vec![prover_api_url.clone()];

        // Background Airbender services for both protocol versions. Huge
        // iteration budgets — they are killed once everything is finalized.
        let mut airbender_v6 = spawn_airbender_prover(&tester, PROTOCOL_VERSION, &urls, 1000).await;

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

        // The v7 service joins before the upgrade so the upgrade batch (the
        // first V7 batch) can finalize as `execute_default_upgrade` demands.
        let mut airbender_v7 =
            spawn_airbender_prover(&tester, PROTOCOL_VERSION_V31_0, &urls, 1000).await;

        // The real v30 -> v31 protocol upgrade, minimal shape: version bump +
        // no-op delegate, no force deployments (the supplier path is the v31+
        // flow; a v30 chain must not use the legacy inconsistent payload).
        // Its internal waits require — and thereby assert — real finalization
        // on both sides of the upgrade boundary.
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

        // v31 traffic, then require the last block finalized on L1 — i.e.
        // its batch committed, REAL-proven, and executed.
        let mut last_block = 0;
        for i in 0..2u64 {
            let receipt = tester
                .l2_provider
                .send_transaction(
                    TransactionRequest::default()
                        .with_to(recipient)
                        .with_value(U256::from(2 + i)),
                )
                .await?
                .get_receipt()
                .await?;
            last_block = receipt.block_number.unwrap_or(last_block);
        }
        tester
            .l2_zk_provider
            .wait_finalized_with_timeout(last_block, REAL_PROOF_FINALITY_TIMEOUT)
            .await?;

        // Everything is proven and finalized — free the GPU for ZiSK.
        airbender_v6.kill().await.ok();
        airbender_v7.kill().await.ok();

        let total_batches = tester.prover_tester.last_proven_batch().await?;
        anyhow::ensure!(
            total_batches >= 2,
            "expected batches on both sides of the upgrade, got {total_batches}"
        );
        tracing::info!(total_batches, "all batches real-proven on L1 — starting ZiSK lane");

        // ZiSK lane: jobs were created at batch seal and survive the
        // Airbender-only sends; the daemon exits 0 only after `total_batches`
        // accepted submissions (commitment + programVK validated per batch).
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
