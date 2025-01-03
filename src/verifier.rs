// External crates
use axum::{
    extract::State,
    routing::post,
    Json,
    Router,
};
use elliptic_curve::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};
use std::{
    str,
    sync::Arc,
    time::Duration,
};
use tlsn_core::proof::{SessionProof, TlsProof};

// Internal crates
use crate::{
    bn254::{
        self,
        BN254Signature,
        BN254SigningKey,
    },
    commitment_parser::Commitment,
    config::NotaryServerProperties,
    wallet::load_operator_bls_key,
    OperatorProperties,
    parse_operator_config_file,
    validate_operator_config,
};
use crate::remote_bls_signer::get_signature;
use eyre::Result;
use tracing::{debug, info};
use ark_bn254::g1::G1Affine;
use ark_ec::{AffineRepr, CurveGroup};
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

    // Create commitment from request fields
    let commitment = Commitment {
        signature: request.signature,
        address: request.address,
        platform: request.platform,
        resource: request.resource,
        value: request.value,
        threshold: request.threshold,  // Convert u64 to i32
    };

    let message = format!("{}{}{}{}", commitment.platform, commitment.resource, commitment.value, commitment.threshold);

    // Verify the commitment signature
    if !commitment.verify_signature(&message, &commitment.signature, &commitment.address).map_err(|err| (
        axum::http::StatusCode::BAD_REQUEST,
        format!("Commitment signature verification failed: {err}")
    ))? {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "Invalid commitment signature".to_string()
        ));
    }
    let commitment_hash = commitment.hash();
    let operator_config: OperatorProperties =
    parse_operator_config_file("config/opacity.config.yaml").map_err(|err| (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        format!("Failed to parse operator config: {err}")
    ))?;

    validate_operator_config(&operator_config).map_err(|err| (
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        format!("Failed to validate operator config: {err}")
    ))?;
    let opacity_node_selector_address = operator_config.opacity_node_selector_address;
    let node_selector_message = format!("{},{},{}", request.node_url, hex::encode(commitment_hash), request.timestamp);
    if !commitment.verify_signature(&node_selector_message, &request.node_selector_signature, &opacity_node_selector_address).map_err(|err| (
        axum::http::StatusCode::BAD_REQUEST,
        format!("Node selector signature verification failed: {err}")
    ))? {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "Invalid node selector signature".to_string()
        ));
    }
    // Check if the commitment timestamp is within 5 minutes
    let current_timestamp = chrono::Utc::now().timestamp();
    let time_diff = current_timestamp - request.timestamp as i64;
    let max_time_diff = std::env::var("MAX_TIME_DIFF_SECONDS")
        .map(|v| v.parse::<i64>().unwrap_or(60))
        .unwrap_or(60); // Default to 60 seconds (1 minute) if env var not set
    if time_diff > max_time_diff {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            format!("Commitment timestamp is too old (more than {} seconds)", max_time_diff)
        ));
    }
    let signature = sign(commitment_hash).await.unwrap();
    let operator_id = operator_config.operator_id;
    debug!("Operator ID: {:?}", operator_id);


    let mut response = format!(
        "Verified session with {:?} at {}.\nSent: {}\nReceived: {} \nSignature: {:?} \nOperatorID: {:?} \nCommitmentHash: {:?}",
        session_info.server_name,
        time,
        String::from_utf8_lossy(sent.data()),
        String::from_utf8_lossy(recv.data()),
        signature,
        operator_id,
        hex::encode(commitment_hash)
    );

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

pub async fn sign(message: [u8; 32]) -> Result<BN254Signature> {
    
    let bls_password = std::env::var("OPERATOR_BLS_KEY_PASSWORD").unwrap_or_else(|_| {
        panic!("OPERATOR_BLS_KEY_PASSWORD not set in environment variable");
    });
    let signer_endpoint = std::env::var("SIGNER_ENDPOINT").unwrap_or_else(|_| {
        panic!("SIGNER_ENDPOINT not set in environment variable");
    });
    let bls_identifier = std::fs::read_to_string("config/remote.bls.identifier")
        .map_err(|e| eyre::eyre!("Failed to read BLS identifier file: {}", e))?;
    println!("BLS identifier: {:?}", bls_identifier);
    let signature: BN254Signature = get_signature(&bls_identifier, message, &bls_password, signer_endpoint).await?;

    debug!("Signature: {:?}", signature);
    Ok(signature)
}