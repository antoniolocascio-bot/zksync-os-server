use axum::{
    Router,
    routing::{get, post},
};

use crate::prover_api::prover_server::{
    AppState,
    v1::handlers::{
        get_failed_fri_proof, peek_fri_job, peek_snark_job, peek_zisk_data, pick_fri_job,
        pick_snark_job, pick_zisk_job, status, submit_fri_proof, submit_snark_proof,
        submit_zisk_proof,
    },
};

pub(in crate::prover_api::prover_server) fn v1_routes() -> Router<AppState> {
    Router::new()
        // Airbender FRI prover routes
        .route("/FRI/pick", post(pick_fri_job))
        .route("/FRI/submit", post(submit_fri_proof))
        // Airbender SNARK prover routes
        .route("/SNARK/pick", post(pick_snark_job))
        .route("/SNARK/submit", post(submit_snark_proof))
        // ZiSK SNARK prover routes
        .route("/ZiSK/pick", post(pick_zisk_job))
        .route("/ZiSK/submit", post(submit_zisk_proof))
        // debugging routes
        .route("/ZiSK/{batch_number}/peek", get(peek_zisk_data))
        .route("/FRI/{id}/peek", get(peek_fri_job))
        .route("/FRI/{id}/failed", get(get_failed_fri_proof))
        .route("/SNARK/{from}/{to}/peek", get(peek_snark_job))
        .route("/status/", get(status))
}
