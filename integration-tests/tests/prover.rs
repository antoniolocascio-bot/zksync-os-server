#![cfg(feature = "prover-tests")]

use zksync_os_integration_tests::{
    CURRENT_TO_L1, NEXT_TO_GATEWAY, SettlementLayer, TestCase, TestEnvironment, test_multisetup,
};

#[cfg(feature = "gpu-prover-tests")]
mod real_prover_upgrade {
    use alloy::network::TransactionBuilder;
    use alloy::primitives::{Address, U256};
    use alloy::providers::Provider;
    use alloy::sol_types::SolCall;
    use alloy::rpc::types::TransactionRequest;
    use std::time::Duration;
    use zksync_os_integration_tests::provider::ZksyncTestingProvider;
    use zksync_os_integration_tests::upgrade::{Action, CommitterFacetV31, FacetCut, UpgradeTester};
    use zksync_os_integration_tests::{CURRENT_TO_L1, run_zisk_gpu_prover, spawn_airbender_prover};
    use zksync_os_server::default_protocol_version::{PROTOCOL_VERSION, PROTOCOL_VERSION_V31_0};
    use zksync_os_types::ProvingVersion;

    /// How long to allow a block to reach L1 finality with real (GPU)
    /// proving in the loop: prover warmup (one-time SNARK precomputations —
    /// observed up to ~25 minutes) + commit + FRI + SNARK wrap + prove tx +
    /// execute.
    const REAL_PROOF_FINALITY_TIMEOUT: Duration = Duration::from_secs(3600);

    /// Kills the wrapped prover service when dropped, so a failing test does
    /// not leak a GPU-holding orphan process.
    struct KillOnDrop(tokio::process::Child);
    impl Drop for KillOnDrop {
        fn drop(&mut self) {
            let _ = self.0.start_kill();
        }
    }

    /// Peek a batch's FRI job to learn its VK hash. `None` once the batch is
    /// unknown to the job map (not sealed yet, or already proven).
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

        // ONE Airbender service at a time: shivini statically allocates most
        // of the GPU's VRAM per process, so two services cannot coexist (a
        // concurrent warmup dies in the CUDA allocator). Start with v6; huge
        // iteration budget — it is killed at the upgrade boundary.
        let mut airbender_v6 =
            KillOnDrop(spawn_airbender_prover(&tester, PROTOCOL_VERSION, &urls, 1000).await);

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

        // Absorb the v6 warmup here: the first real finalization takes
        // precomputation + FRI + SNARK wrap + prove/execute txs. After this,
        // the UpgradeTester's pre-upgrade finality waits see a warm prover.
        tester
            .l2_zk_provider
            .wait_finalized_with_timeout(1, REAL_PROOF_FINALITY_TIMEOUT)
            .await?;

        // The real v30 -> v31 protocol upgrade. Unlike a bare version bump,
        // it must FORCE-DEPLOY the v31 SystemContext (0x800b): the sequencer
        // appends a `SetSLChainId` system tx to the first v31 block, and
        // without that contract the call no-ops silently — the STF then
        // commits `settlement_layer_chain_id = 0` while the batcher and the
        // L1 Committer (which requires `slChainId == block.chainid`) commit
        // the real one, making every v31 batch unprovable. The payload is
        // the minimal SystemContextV31 test contract (the genesis deploys a
        // proxy + delegate-only implementation with seeded EIP-1967 slots,
        // which force deployments cannot reproduce: code only, no storage)
        // delivered via the L1 BytecodesSupplier, the production v31 path.
        //
        // The upgrade's internal waits require — and thereby assert — real
        // finalization on both sides of the boundary. Run it concurrently
        // with the prover swap: once the upgrade batch (first V7 job)
        // appears and all earlier batches are proven, v6 is retired and v7
        // takes the GPU; the upgrade's post-boundary finality wait rides the
        // v7 warmup (set TEST_FINALITY_TIMEOUT_SECS generously).
        let system_context_code =
            zksync_os_integration_tests::contracts::SystemContextV31::DEPLOYED_BYTECODE.clone();
        let system_context_address: Address =
            "0x000000000000000000000000000000000000800b".parse()?;
        let force_deployments: std::collections::BTreeMap<Address, alloy::primitives::Bytes> =
            [(system_context_address, system_context_code.clone())]
                .into_iter()
                .collect();

        // A v30-era L1 has no functional EVM BytecodesSupplier — production
        // deploys it as part of the v31 ecosystem upgrade (protocol-ops
        // `upgrade-prepare`). Mirror that by etching the event-compatible
        // supplier at the configured address before publishing.
        {
            use alloy::providers::ext::AnvilApi;
            let supplier_address = tester
                .config()
                .genesis_config
                .bytecode_supplier_address
                .expect("bytecode_supplier_address must be configured");
            let code = zksync_os_integration_tests::contracts::BytecodesSupplierV31::DEPLOYED_BYTECODE.clone();
            tester
                .l1_provider()
                .anvil_set_code(supplier_address, code)
                .await?;
        }

        // V7 proofs cannot pass the v30-era verifier; the upgrade switches
        // the chain to the v31 verifier tree etched from the v31 fixture.
        let v31_verifier = zksync_os_integration_tests::etch_v31_verifier_tree(&tester).await?;

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
            .with_verifier(v31_verifier)
            .build();

        // Every pre-upgrade batch must be finalized before the cut retires
        // the v30 commit encoding.
        let tip = tester.l2_provider.get_block_number().await?;
        tester
            .l2_zk_provider
            .wait_finalized_with_timeout(tip, REAL_PROOF_FINALITY_TIMEOUT)
            .await?;
        // The v30-era L1 Executor hard-codes ZKsync OS commits to encoding
        // v3; v31 batches commit with encoding v4, so the upgrade must also
        // replace the committer facet (mirrors `upgrade_to_v31_with_deployments`).
        let l1_chain_id = tester.l1_provider().get_chain_id().await?;
        let committer_facet =
            CommitterFacetV31::deploy(tester.l1_provider().clone(), U256::from(l1_chain_id))
                .await?;
        let facet_cut = FacetCut {
            facet: *committer_facet.address(),
            action: Action::Replace,
            isFreezable: true,
            selectors: vec![alloy::primitives::FixedBytes(
                CommitterFacetV31::commitBatchesSharedBridgeCall::SELECTOR,
            )],
        };

        let upgrade_fut = upgrade_tester.execute_default_upgrade_cut_first(
            &protocol_upgrade,
            U256::MAX,
            U256::from(1),
            vec![facet_cut],
        );
        let swap_fut = async {
            loop {
                tokio::time::sleep(Duration::from_secs(5)).await;
                let mut first_v7_batch = None;
                for batch in 1..=64u64 {
                    match peek_fri_vk(&prover_api_url, batch).await? {
                        Some(vk) if vk == ProvingVersion::V7.vk_hash() => {
                            first_v7_batch = Some(batch);
                            break;
                        }
                        _ => continue,
                    }
                }
                let Some(upgrade_batch) = first_v7_batch else {
                    continue;
                };
                if tester.prover_tester.last_proven_batch().await? >= upgrade_batch - 1 {
                    tracing::info!(
                        upgrade_batch,
                        "all pre-upgrade batches proven — swapping Airbender v6 -> v7"
                    );
                    airbender_v6.0.kill().await.ok();
                    let v7 =
                        spawn_airbender_prover(&tester, PROTOCOL_VERSION_V31_0, &urls, 1000).await;
                    return anyhow::Ok(KillOnDrop(v7));
                }
            }
        };
        let (_, mut airbender_v7) = tokio::try_join!(upgrade_fut, swap_fut)?;

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
        airbender_v7.0.kill().await.ok();

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

    /// ZiSK lane in isolation: boot the chain with all provers off, seal a
    /// couple of batches, and run the real GPU daemon over them — pickup,
    /// prove, proof-file parse, submission, and the server's commitment +
    /// programVK validation, without the ~35-minute Airbender/upgrade flow.
    /// Finality never advances here (nothing serves FRI jobs), which is
    /// fine: batch sealing and ZiSK job creation are upstream of proving.
    #[test_log::test(tokio::test)]
    async fn zisk_lane_on_sealed_batches() -> anyhow::Result<()> {
        let env = CURRENT_TO_L1.environment().await?;
        let mut config = env.default_config().await?;
        // Fakes stay off: a fake FRI/SNARK pass would finalize and discard
        // the sealed batches' ZiSK jobs before the daemon picks them.
        config.prover_api_config.fake_fri_provers.enabled = false;
        config.prover_api_config.fake_snark_provers.enabled = false;
        config.prover_api_config.max_fris_per_snark = 1;
        config.prover_input_generator_config.second_proof_system = true;
        if let Ok(vk) = std::env::var("ZISK_PROGRAM_VK") {
            config.prover_api_config.zisk_program_vk = Some(vk.parse()?);
        }
        let tester = env.launch_without_provers(config).await?;
        let prover_api_url = tester
            .prover_api_url()
            .expect("prover API must be bound for prover tests");

        let recipient: Address = "0xdead000000000000000000000000000000000001".parse()?;
        let batches = 2u64;
        for batch in 1..=batches {
            tester
                .l2_provider
                .send_transaction(
                    TransactionRequest::default()
                        .with_to(recipient)
                        .with_value(U256::from(batch)),
                )
                .await?
                .get_receipt()
                .await?;
            // Wait for the batch to seal: its ZiSK job appears in the map.
            let deadline = std::time::Instant::now() + Duration::from_secs(120);
            loop {
                let status = reqwest::Client::new()
                    .get(format!(
                        "{prover_api_url}/prover-jobs/v1/ZiSK/{batch}/peek"
                    ))
                    .send()
                    .await?
                    .status();
                if status == reqwest::StatusCode::OK {
                    break;
                }
                anyhow::ensure!(
                    std::time::Instant::now() < deadline,
                    "batch {batch} ZiSK job did not appear within 120s (status {status})"
                );
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        }

        // Clean daemon exit == every proof was accepted by the server.
        run_zisk_gpu_prover(&prover_api_url, batches as usize).await;

        Ok(())
    }

    /// Capture N sealed batches' ZiSK `BatchInput`s to disk, without proving.
    /// Feeds offline proving flows (e.g. minting `vadcop_final` proofs for
    /// range aggregation) with a coherent sequence of real chain batches.
    /// Env: `CAPTURE_BATCHES` (default 4), `CAPTURE_DIR` (default
    /// /tmp/zisk-batch-inputs). Writes `batch-N.bin` (raw bincode) and
    /// `batch-N.input.bin` (cargo-zisk framing: [len u64 LE][data][pad→8]).
    #[test_log::test(tokio::test)]
    async fn capture_sealed_batch_inputs() -> anyhow::Result<()> {
        let n: u64 = std::env::var("CAPTURE_BATCHES")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(4);
        let dir = std::env::var("CAPTURE_DIR")
            .unwrap_or_else(|_| "/tmp/zisk-batch-inputs".to_string());
        std::fs::create_dir_all(&dir)?;

        let env = CURRENT_TO_L1.environment().await?;
        let mut config = env.default_config().await?;
        config.prover_api_config.fake_fri_provers.enabled = false;
        config.prover_api_config.fake_snark_provers.enabled = false;
        config.prover_api_config.max_fris_per_snark = 1;
        config.prover_input_generator_config.second_proof_system = true;
        let tester = env.launch_without_provers(config).await?;
        let prover_api_url = tester
            .prover_api_url()
            .expect("prover API must be bound for prover tests");

        let recipient: Address = "0xdead000000000000000000000000000000000001".parse()?;
        for batch in 1..=n {
            tester
                .l2_provider
                .send_transaction(
                    TransactionRequest::default()
                        .with_to(recipient)
                        .with_value(U256::from(batch)),
                )
                .await?
                .get_receipt()
                .await?;
            // Wait for the batch's ZiSK job, then capture its input.
            let deadline = std::time::Instant::now() + Duration::from_secs(120);
            let zisk_data = loop {
                let response = reqwest::Client::new()
                    .get(format!("{prover_api_url}/prover-jobs/v1/ZiSK/{batch}/peek"))
                    .send()
                    .await?;
                if response.status() == reqwest::StatusCode::OK {
                    let payload: serde_json::Value = response.json().await?;
                    let b64 = payload
                        .get("zisk_data")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| anyhow::anyhow!("batch {batch}: no zisk_data"))?
                        .to_owned();
                    use base64::Engine;
                    break base64::engine::general_purpose::STANDARD.decode(b64)?;
                }
                anyhow::ensure!(
                    std::time::Instant::now() < deadline,
                    "batch {batch} ZiSK job did not appear within 120s"
                );
                tokio::time::sleep(Duration::from_millis(300)).await;
            };

            std::fs::write(format!("{dir}/batch-{batch}.bin"), &zisk_data)?;
            let mut framed = (zisk_data.len() as u64).to_le_bytes().to_vec();
            framed.extend_from_slice(&zisk_data);
            while framed.len() % 8 != 0 {
                framed.push(0);
            }
            std::fs::write(format!("{dir}/batch-{batch}.input.bin"), &framed)?;
            tracing::info!(batch, bytes = zisk_data.len(), "captured ZiSK batch input");
        }

        tracing::info!(n, dir = %dir, "all batch inputs captured");
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
