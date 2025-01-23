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
    pub task_index: u64,
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
        signature: request.signature.clone(),
        address: request.address.clone(),
        platform: request.platform.clone(),
        resource: request.resource.clone(),
        value: request.value.clone(),
        threshold: request.threshold,  // No need to clone as u64 implements Copy
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
    let operator_address = operator_config.operator_address;
    debug!("Operator ID: {:?}", operator_id);
    debug!("Operator Address: {:?}", operator_address);

    // check that server == platform
    if session_info.server_name != tlsn_core::ServerName::Dns(request.platform.clone()) {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "Server name does not match platform".to_string()
        ));
    }

    // check that resource:value from request can be found in recv.data
    let recv_data = String::from_utf8_lossy(recv.data());
    let resource_value = format!("{}:{}", request.resource, request.value);
    
    // Split the response into headers and body
    let parts: Vec<&str> = recv_data.split("\r\n\r\n").collect();
    if parts.len() < 2 {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "Invalid HTTP response format".to_string()
        ));
    }

    // Parse the chunked body
    let body = parts[1..].join("\r\n\r\n");
    // Remove chunk size indicators and trailing zeros
    let cleaned_body: String = body
        .lines()
        .filter(|line| !line.chars().all(|c| c.is_digit(16)) && !line.is_empty())
        .collect::<Vec<&str>>()
        .join("\n");

    // Parse the JSON
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&cleaned_body) {
        // Check if model exists in the result object
        if let Some(result) = json.get("result") {
            if let Some(model) = result.get("model") {
                if let Some(model_str) = model.as_str() {
                    // Check if the model string starts with the value we're looking for
                    // This handles cases where the model might have additional version info
                    if model_str.starts_with(&request.value) {
                        // Found a match, continue with the rest of the code
                    } else {
                        return Err((
                            axum::http::StatusCode::BAD_REQUEST,
                            format!("Model value '{}' not found in response", request.value)
                        ));
                    }
                }
            }
        }
    } else {
        return Err((
            axum::http::StatusCode::BAD_REQUEST,
            "Failed to parse JSON response".to_string()
        ));
    }

    let response = serde_json::json!({
        "task_index": request.task_index,
        "server_name": session_info.server_name,
        "time": current_timestamp.to_string(),
        "sent": String::from_utf8_lossy(sent.data()),
        "received": recv_data,
        "signature": signature.to_string(),
        "operator_id": operator_id,
        "operator_address": operator_address,
        "commitment_hash": hex::encode(commitment_hash)
    }).to_string();

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
    let signature: BN254Signature = get_signature(&bls_identifier, message, &bls_password, signer_endpoint).await?;

    debug!("Signature: {:?}", signature);
    Ok(signature)
}
