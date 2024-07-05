use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
};
use eyre::Report;
use std::{error::Error, fmt};

use tlsn_verifier::tls::{VerifierConfigBuilderError, VerifierError};

#[derive(Debug, thiserror::Error)]
pub enum NotaryServerError {
    #[error(transparent)]
    Unexpected(#[from] Report),
    #[error("Failed to connect to prover: {0}")]
    Connection(String),
    #[error("Error occurred during notarization: {0}")]
    Notarization(Box<dyn Error + Send + 'static>),
    #[error("Invalid request from prover: {0}")]
    BadProverRequest(String),
    #[error("Unauthorized request from prover: {0}")]
    UnauthorizedProverRequest(String),
}

impl From<VerifierError> for NotaryServerError {
    fn from(error: VerifierError) -> Self {
        Self::Notarization(Box::new(error))
    }
}

impl From<VerifierConfigBuilderError> for NotaryServerError {
    fn from(error: VerifierConfigBuilderError) -> Self {
        Self::Notarization(Box::new(error))
    }
}

/// Trait implementation to convert this error into an axum http response
impl IntoResponse for NotaryServerError {
    fn into_response(self) -> Response {
        match self {
            bad_request_error @ NotaryServerError::BadProverRequest(_) => {
                (StatusCode::BAD_REQUEST, bad_request_error.to_string()).into_response()
            }
            unauthorized_request_error @ NotaryServerError::UnauthorizedProverRequest(_) => (
                StatusCode::UNAUTHORIZED,
                unauthorized_request_error.to_string(),
            )
                .into_response(),
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Something wrong happened.",
            )
                .into_response(),
        }
    }
}

#[derive(Debug)]
pub enum BLSError {
    SignatureNotInSubgroup,
    SignatureListEmpty,
    PublicKeyNotInSubgroup,
    PublicKeyListEmpty,
}

impl Error for BLSError {}

impl fmt::Display for BLSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            BLSError::SignatureNotInSubgroup => write!(f, "Signature not in subgroup"),
            BLSError::PublicKeyNotInSubgroup => write!(f, "Public key not in subgroup"),
            BLSError::SignatureListEmpty => write!(f, "Signature array is empty"),
            BLSError::PublicKeyListEmpty => write!(f, "The public key list is empty"),
        }
    }
}
