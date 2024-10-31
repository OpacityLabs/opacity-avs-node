use axum::{
    routing::post,
    Router,
    Json,
    extract::State,
};
use std::sync::Arc;
use elliptic_curve::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use std::{str, time::Duration};
use tlsn_core::proof::{SessionProof, TlsProof};
use crate::{
    bn254::{self, BN254Signature, BN254SigningKey},
    config::{NotaryServerProperties, NotarySigningKeyProperties},
};
use eyre::{eyre, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InfoResponse {
    /// Current version of notary-server
    pub version: String,
    /// Public key of the notary signing key
    pub public_key: String,
    /// Current git commit hash of notary-server
    pub git_commit_hash: String,
    /// Current git commit timestamp of notary-server
    pub git_commit_timestamp: String,
}

#[derive(Clone)]
struct AppState {
    config: &NotaryServerProperties,
}

// New function to handle the verification request
async fn verify_proof(
    State(state): State<Arc<AppState>>,
    Json(proof): Json<TlsProof>,
) -> Result<Json<String>, (axum::http::StatusCode, String)> {
    let notary_public_key_string = std::fs::read_to_string(&state.config.notary_key.public_key_pem_path)
        .map_err(|err| (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to load notary public signing key: {err}")
        ))?;

    let notary_public_key = p256::PublicKey::from_public_key_pem(&notary_public_key_string)
        .map_err(|err| (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to parse notary public key: {err}")
        ))?;

    let TlsProof { session, substrings } = proof;

    // Verify the session proof
    session.verify_with_default_cert_verifier(notary_public_key)
        .map_err(|err| (
            axum::http::StatusCode::BAD_REQUEST,
            format!("Session verification failed: {err}")
        ))?;

    let SessionProof { header, session_info, .. } = session;
    let time = chrono::DateTime::UNIX_EPOCH + Duration::from_secs(header.time());

    // Verify the substrings proof
    let (mut sent, mut recv) = substrings.verify(&header)
        .map_err(|err| (
            axum::http::StatusCode::BAD_REQUEST,
            format!("Substrings verification failed: {err}")
        ))?;

    sent.set_redacted(b'X');
    recv.set_redacted(b'X');

    let response = format!(
        "Verified session with {:?} at {}.\nSent: {}\nReceived: {}",
        session_info.server_name,
        time,
        String::from_utf8_lossy(sent.data()),
        String::from_utf8_lossy(recv.data())
    );

    Ok(Json(response))
}

pub async fn run_verifier(config: &NotaryServerProperties) -> eyre::Result<()> {
    let state = Arc::new(AppState { config: config.to_owned() });
    
    let app = Router::new()
        .route("/verify", post(verify_proof))
        .with_state(state);

    println!("Starting verifier server on port 6074...");
    
    axum::serve(
        tokio::net::TcpListener::bind("0.0.0.0:6074").await?,
        app
    )
    .await
    .map_err(|e| eyre::eyre!("Server error: {}", e))?;

    Ok(())
}
