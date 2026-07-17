//! Fleet mechanics of the ZiSK prover HTTP API: multiple daemons
//! picking concurrently against one server, and timeout-based reassignment
//! when a daemon disappears mid-job.
//!
//! Runs the real axum router over a seeded `ZiskJobManager`. This lives here
//! rather than in the full-node integration suite because the fake-SNARK
//! pass discards ZiSK jobs when it consumes their batches, so exercising
//! `/ZiSK/pick` deterministically requires seeding the manager directly.

use std::sync::Arc;
use std::time::Duration;

use smart_config::ByteSize;
use tokio::sync::mpsc;
use zksync_os_batch_types::batcher_model::FriProof;

use super::v1_routes;
use crate::config::ProofStorageConfig;
use crate::prover_api::fri_job_manager::FriJobManager;
use crate::prover_api::proof_storage::ProofStorage;
use crate::prover_api::snark_job_manager::SnarkJobManager;
use crate::prover_api::test_util::create_test_batch_envelope;
use crate::prover_api::zisk_job_manager::{ZiskJobData, ZiskJobManager};

#[derive(serde::Deserialize)]
struct PickResponse {
    batch_number: u64,
    zisk_data: String,
}

async fn pick(client: &reqwest::Client, base: &str, prover_id: &str) -> Option<PickResponse> {
    let response = client
        .post(format!("{base}/prover-jobs/v1/ZiSK/pick"))
        .query(&[("id", prover_id)])
        .send()
        .await
        .expect("pick request");
    match response.status() {
        reqwest::StatusCode::OK => Some(response.json().await.expect("pick payload")),
        reqwest::StatusCode::NO_CONTENT => None,
        other => panic!("unexpected pick status: {other}"),
    }
}

/// Two daemons against one server: concurrent picks hand out distinct work,
/// and a job whose prover vanished is re-offered with the identical prover
/// input after the assignment timeout.
#[tokio::test(flavor = "multi_thread")]
async fn zisk_fleet_pick_and_reassignment_over_http() {
    const ASSIGNMENT_TIMEOUT: Duration = Duration::from_secs(2);

    let (fri_tx, _fri_rx) = mpsc::channel(8);
    let (snark_tx, _snark_rx) = mpsc::channel(8);

    let tmp = tempfile::tempdir().expect("tempdir");
    let proof_storage = ProofStorage::new(ProofStorageConfig {
        path: tmp.path().to_path_buf(),
        batch_with_proof_capacity: ByteSize(1 << 20),
        failed_capacity: ByteSize(1 << 20),
    })
    .await
    .expect("proof storage");

    let fri_job_manager = Arc::new(FriJobManager::new(
        fri_tx,
        proof_storage.clone(),
        Duration::from_secs(60),
        10,
    ));
    let snark_job_manager = Arc::new(SnarkJobManager::new(
        snark_tx,
        1,
        Duration::from_secs(60),
        10,
    ));
    let zisk_job_manager = Arc::new(ZiskJobManager::new(
        ASSIGNMENT_TIMEOUT,
        None,
        270,
        crate::batcher::batch_builder::ZiskChainConfig {
            fri_proof_verification_enabled: false,
            max_tx_gas_limit: 1 << 24,
        },
    ));

    let zisk_data = vec![0xAB; 64];
    zisk_job_manager
        .add_job(
            7,
            ZiskJobData {
                zisk_data: zisk_data.clone(),
                batch_metadata: create_test_batch_envelope(7, FriProof::Fake).batch,
                added_at: std::time::Instant::now(),
            },
        )
        .await
        .unwrap_or_else(|_| panic!("add_job rejected"));

    let app_state = super::AppState {
        fri_job_manager,
        snark_job_manager,
        zisk_job_manager: Some(zisk_job_manager),
        zisk_aggregation_job_manager: None,
        proof_storage,
    };
    let app = axum::Router::new()
        .nest("/prover-jobs/v1", v1_routes())
        .with_state(app_state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });

    let client = reqwest::Client::new();

    // Daemon A picks the only job; daemon B finds the queue empty.
    let picked_a = pick(&client, &base, "gpu-a").await.expect("job for A");
    assert_eq!(picked_a.batch_number, 7);
    assert!(
        pick(&client, &base, "gpu-b").await.is_none(),
        "B must not receive the job while A's assignment is live"
    );

    // A disappears without submitting. Past the assignment timeout the job
    // must be re-offered to the fleet with the identical prover input.
    tokio::time::sleep(ASSIGNMENT_TIMEOUT + Duration::from_millis(500)).await;
    let picked_b = pick(&client, &base, "gpu-b")
        .await
        .expect("job reassigned to B after timeout");
    assert_eq!(picked_b.batch_number, 7);
    assert_eq!(
        picked_b.zisk_data, picked_a.zisk_data,
        "reassigned job must carry the original prover input"
    );
}

/// The aggregated-mode daemon flow over the real HTTP API: per-batch
/// `vadcop_final` streams in via `/ZiSK/submit`, the SNARK range forms the
/// aggregation job, `/ZiSK-AGG/pick` hands the streams out, and a range
/// proof with the correct binding digest is accepted on `/ZiSK-AGG/submit`
/// and parked for the rendezvous.
#[tokio::test(flavor = "multi_thread")]
async fn zisk_aggregated_flow_over_http() {
    use crate::prover_api::zisk_aggregation_job_manager::{
        AggregationInput, ZiskAggregationJobManager, expected_aggregated_public_input,
    };
    use crate::prover_api::zisk_proof_constants::{
        ZISK_PUBLIC_VALUES_BYTES, ZISK_SNARK_PROOF_BYTES,
    };
    use crate::prover_api::zisk_vadcop_stream::test_stream::synthetic_stream;
    use alloy::primitives::B256;
    use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

    let (fri_tx, _fri_rx) = mpsc::channel(8);
    let (snark_tx, _snark_rx) = mpsc::channel(8);

    let tmp = tempfile::tempdir().expect("tempdir");
    let proof_storage = ProofStorage::new(ProofStorageConfig {
        path: tmp.path().to_path_buf(),
        batch_with_proof_capacity: ByteSize(1 << 20),
        failed_capacity: ByteSize(1 << 20),
    })
    .await
    .expect("proof storage");

    let fri_job_manager = Arc::new(FriJobManager::new(
        fri_tx,
        proof_storage.clone(),
        Duration::from_secs(60),
        10,
    ));
    let snark_job_manager = Arc::new(SnarkJobManager::new(
        snark_tx,
        2,
        Duration::from_secs(60),
        10,
    ));
    const TEST_CHAIN_ID: u64 = 270;
    const TEST_CHAIN_CONFIG: crate::batcher::batch_builder::ZiskChainConfig =
        crate::batcher::batch_builder::ZiskChainConfig {
            fri_proof_verification_enabled: false,
            max_tx_gas_limit: 1 << 24,
        };
    let zisk_job_manager = Arc::new(ZiskJobManager::new(
        Duration::from_secs(60),
        None,
        TEST_CHAIN_ID,
        TEST_CHAIN_CONFIG,
    ));
    let aggregation_job_manager = Arc::new(ZiskAggregationJobManager::new(
        2,
        Duration::from_secs(60),
        None,
    ));
    zisk_job_manager.set_aggregation_sink(aggregation_job_manager.clone());

    // Seed per-batch jobs 1..=2 and record their expected commitments.
    let mut commitments = Vec::new();
    for batch in 1..=2u64 {
        let mut envelope = create_test_batch_envelope(batch, FriProof::Fake);
        envelope.batch.batch_info.protocol_version =
            zksync_os_types::ProtocolSemanticVersion::new(0, 31, 0);
        let stored = envelope.batch.batch_info.clone().into_stored();
        let prev = &envelope.batch.previous_stored_batch_info;
        commitments.push(
            crate::prover_api::zisk_proof_verifier::expected_zisk_public_input(
                &prev.state_commitment,
                &stored,
                TEST_CHAIN_ID,
                TEST_CHAIN_CONFIG,
            ),
        );
        zisk_job_manager
            .add_job(
                batch,
                ZiskJobData {
                    zisk_data: vec![batch as u8; 32],
                    batch_metadata: envelope.batch,
                    added_at: std::time::Instant::now(),
                },
            )
            .await
            .unwrap_or_else(|_| panic!("add_job rejected"));
    }
    // The Airbender SNARK lane covers 1..=2 (normally reported at pick).
    aggregation_job_manager.note_snark_range(1, 2).await;

    let app_state = super::AppState {
        fri_job_manager,
        snark_job_manager,
        zisk_job_manager: Some(zisk_job_manager),
        zisk_aggregation_job_manager: Some(aggregation_job_manager.clone()),
        proof_storage,
    };
    let app = axum::Router::new()
        .nest("/prover-jobs/v1", v1_routes())
        .with_state(app_state)
        .layer(axum::extract::DefaultBodyLimit::max(10 * 1024 * 1024));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    let client = reqwest::Client::new();

    // The daemon proves each batch and submits the vadcop_final stream
    // (empty public_values — the stream carries its own publics).
    const PROGRAM_VK: [u64; 4] = [1, 2, 3, 4];
    const VADCOP_VK: [u64; 4] = [5, 6, 7, 8];
    fn vk_be(limbs: [u64; 4]) -> B256 {
        let mut out = [0u8; 32];
        for (i, chunk) in out.chunks_exact_mut(8).enumerate() {
            chunk.copy_from_slice(&limbs[i].to_be_bytes());
        }
        B256::from(out)
    }
    let mut streams = Vec::new();
    for batch in 1..=2u64 {
        let picked = pick(&client, &base, "gpu-a").await.expect("job");
        assert_eq!(picked.batch_number, batch);
        let stream = synthetic_stream(PROGRAM_VK, VADCOP_VK, commitments[batch as usize - 1].0);
        let response = client
            .post(format!("{base}/prover-jobs/v1/ZiSK/submit"))
            .query(&[("id", "gpu-a")])
            .json(&serde_json::json!({
                "batch_number": batch,
                "proof": BASE64.encode(&stream),
                "public_values": "",
            }))
            .send()
            .await
            .expect("submit request");
        assert_eq!(
            response.status(),
            reqwest::StatusCode::NO_CONTENT,
            "{}",
            response.text().await.unwrap_or_default()
        );
        streams.push(stream);
    }

    // The aggregation daemon picks the formed range and gets the streams.
    let response = client
        .post(format!("{base}/prover-jobs/v1/ZiSK-AGG/pick"))
        .query(&[("id", "agg-a")])
        .send()
        .await
        .expect("agg pick request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    let job: serde_json::Value = response.json().await.expect("agg pick payload");
    assert_eq!(job["from_batch_number"], 1);
    assert_eq!(job["to_batch_number"], 2);
    let proofs = job["proofs"].as_array().expect("proofs");
    assert_eq!(proofs.len(), 2);
    for (i, entry) in proofs.iter().enumerate() {
        assert_eq!(entry["batch_number"], i as u64 + 1);
        let bytes = BASE64
            .decode(entry["proof"].as_str().expect("proof"))
            .expect("base64");
        assert_eq!(bytes, streams[i], "the exact buffered stream is handed out");
    }

    // The aggregated range proof with the correct binding digest lands.
    let inputs: Vec<AggregationInput> = commitments
        .iter()
        .map(|&commitment| AggregationInput {
            stream: vec![],
            program_vk: vk_be(PROGRAM_VK),
            vadcop_vk: vk_be(VADCOP_VK),
            commitment,
        })
        .collect();
    let refs: Vec<&AggregationInput> = inputs.iter().collect();
    let digest = expected_aggregated_public_input(&refs).expect("digest");
    let mut public_values = vec![0u8; ZISK_PUBLIC_VALUES_BYTES];
    public_values[32..64].copy_from_slice(digest.as_slice());
    let response = client
        .post(format!("{base}/prover-jobs/v1/ZiSK-AGG/submit"))
        .query(&[("id", "agg-a")])
        .json(&serde_json::json!({
            "from_batch_number": 1,
            "to_batch_number": 2,
            "proof": BASE64.encode(vec![0x77u8; ZISK_SNARK_PROOF_BYTES]),
            "public_values": BASE64.encode(&public_values),
        }))
        .send()
        .await
        .expect("agg submit request");
    assert_eq!(
        response.status(),
        reqwest::StatusCode::NO_CONTENT,
        "{}",
        response.text().await.unwrap_or_default()
    );

    // The range proof is parked for the Airbender rendezvous.
    let parked = aggregation_job_manager
        .take_completed(1, 2)
        .await
        .expect("aggregated proof parked");
    assert_eq!(parked.proof, vec![0x77u8; ZISK_SNARK_PROOF_BYTES]);
    assert_eq!(parked.public_values, public_values);
}
