//! Fleet mechanics of the ZiSK prover HTTP API: multiple daemons
//! picking concurrently against one server, and timeout-based reassignment
//! when a daemon disappears mid-job.
//!
//! Runs the real axum router over a seeded `ZiskJobManager`. This lives here
//! rather than in the full-node integration suite because `/ZiSK/pick` jobs
//! are only created by *real* Airbender SNARK submissions (the fake-SNARK
//! pass bypasses the multi-proof gate), which would require real proving.

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
    let (prove_tx, _prove_rx) = mpsc::channel(8);

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
        prove_tx,
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
                era_proof: vec![0xEE; 8],
                proving_execution_version: 1,
                batches: vec![create_test_batch_envelope(7, FriProof::Fake)],
                added_at: std::time::Instant::now(),
            },
        )
        .await
        .unwrap_or_else(|_| panic!("add_job rejected"));

    let app_state = super::AppState {
        fri_job_manager,
        snark_job_manager,
        zisk_job_manager: Some(zisk_job_manager),
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
