pub mod auth;
pub mod cli;
pub mod notary;

use serde::{Deserialize, Serialize};

/// Response object of the /info API
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InfoResponse {
    /// Current version of opacity-node
    pub version: String,
    /// Public key of the notary signing key
    pub public_key: String,
    /// Current git commit hash of opacity-node
    pub git_commit_hash: String,
    /// Current git commit timestamp of opacity-node
    pub git_commit_timestamp: String,
    /// Current git commit timestamp of opacity-node
    pub git_origin_remote: String,
    /// Address of the opacity-node
    pub operator_address: String,
}
