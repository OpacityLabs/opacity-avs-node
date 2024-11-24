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
    wallet::load_operator_bls_key,
    CliFields,
    OperatorProperties,
    validate_operator_config,
    parse_operator_config_file,
};

use eyre::{eyre, Result};
use tracing::{debug, error, info};
use ark_bn254::G1Affine;
use ark_ec::{AffineRepr, CurveGroup};

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

#[derive(Debug, Serialize, Deserialize)]
pub struct VerificationRequest {
    pub tls_proof: TlsProof,
    pub address: String,
    pub platform: String,
    pub resource: String,
    pub value: String,
    pub threshold: u64,
    pub signature: String,
    pub node_url: String,
    pub timestamp: i32,
    pub node_selector_signature: String,
}

#[derive(Clone)]
struct AppState {
    config: NotaryServerProperties,
}

// New function to handle the verification request
async fn verify_proof(
    State(state): State<Arc<AppState>>,
    Json(request): Json<VerificationRequest>,
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

    let TlsProof { session, substrings } = request.tls_proof;

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

    let signature = sign(&response).unwrap();    
    debug!("Signature: {:?}", signature);

    Ok(Json(response))
}

pub async fn run_verifier(config: &NotaryServerProperties) -> eyre::Result<()> {
    let state = Arc::new(AppState { config: config.to_owned() });
    
    let app = Router::new()
        .route("/verify", post(verify_proof))
        .with_state(state);

    info!("Starting verifier server on port 6074...");
    
    axum::serve(
        tokio::net::TcpListener::bind("0.0.0.0:6074").await?,
        app
    )
    .await
    .map_err(|e| eyre::eyre!("Server error: {}", e))?;

    Ok(())
}

pub fn sign(message: &str) -> Result<BN254Signature> {
    
    let operator_config: OperatorProperties =
        parse_operator_config_file("config/opacity.config.yaml")?; //i sthere a better way than hard coding this?

    validate_operator_config(&operator_config).unwrap_or_else(|err| {
        panic!("Invalid operator config: {}", err);
    });

    let bls_password = std::env::var("OPERATOR_BLS_KEY_PASSWORD").unwrap_or_else(|_| {
        panic!("OPERATOR_BLS_KEY_PASSWORD not set in environment variable");
    });

    let bls_keystore_path = operator_config
        .operator_bls_keystore_path
        .clone()
        .unwrap_or_else(|| {
            panic!("operator_bls_keystore_path not set in operator config file");
        });

    let operator_bls_key: BN254SigningKey =
        load_operator_bls_key(&bls_keystore_path, &bls_password).unwrap_or_else(|err| {
            panic!("Unable to decrypt operator BLS keystore: {:?}", err);
        });
    
    let bn254_public_key_g1 = (G1Affine::generator() * operator_bls_key).into_affine();

    debug!("Signing result with BN254 key");
    let message_bytes = message.as_bytes();
    let signature: BN254Signature = bn254::sign(operator_bls_key, message_bytes.clone())?;

    Ok(signature)
}