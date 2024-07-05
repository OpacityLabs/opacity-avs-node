use serde::Deserialize;

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct NotaryServerProperties {
    /// Name and address of the notary server
    pub server: ServerProperties,
    /// Setting for notarization
    pub notarization: NotarizationProperties,
    /// Setting for TLS connection between prover and notary
    pub tls: TLSProperties,
    /// File path of private key (in PEM format) used to sign the notarization
    pub notary_key: NotarySigningKeyProperties,
    /// Setting for logging
    pub logging: LoggingProperties,
    /// Setting for authorization
    pub authorization: AuthorizationProperties,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct AuthorizationProperties {
    /// Switch to turn on or off auth middleware
    pub enabled: bool,
    /// File path of the whitelist API key csv
    pub whitelist_csv_path: String,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct NotarizationProperties {
    /// Global limit for maximum transcript size in bytes
    pub max_transcript_size: usize,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct ServerProperties {
    /// Used for testing purpose
    pub name: String,
    pub host: String,
    pub port: u16,
    /// Static html response returned from API root endpoint "/". Default html response contains
    /// placeholder strings that will be replaced with actual values in server.rs, e.g. {version}, {public_key}
    pub html_info: String,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct TLSProperties {
    /// Flag to turn on/off TLS between prover and notary (should always be turned on unless TLS is handled by external setup e.g. reverse proxy, cloud)
    pub enabled: bool,
    pub private_key_pem_path: Option<String>,
    pub certificate_pem_path: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct NotarySigningKeyProperties {
    pub private_key_pem_path: String,
    pub public_key_pem_path: String,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct LoggingProperties {
    /// Log verbosity level of the default filtering logic, which is notary_server=<level>,tlsn_verifier=<level>,tls_mpc=<level>
    /// Must be either of <https://docs.rs/tracing/latest/tracing/struct.Level.html#implementations>
    pub level: String,
    /// Custom filtering logic, refer to the syntax here https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#example-syntax
    /// This will override the default filtering logic above
    pub filter: Option<String>,
}

/// EigenLayer Operator Configuration
#[derive(Clone, Debug, Deserialize, Default)]
pub struct OperatorProperties {
    pub production: bool,
    pub registry_coordinator_address: String,
    pub opacity_avs_address: String,
    pub avs_directory_address: String,
    pub eigenlayer_delegation_manager: String,
    pub chain_id: u32,
    pub eth_rpc_url: String,
    pub node_public_ip: String,
    pub operator_address: String,
    //pub operator_ecdsa_keystore_path: Option<String>,
    pub operator_bls_keystore_path: Option<String>,
}

// [
//     {
//         "result": {
//             "data": {
//                 "json": {
//                     "name": "EulerLagrange",
//                     "website": "https://warpcast.com/eulerlagrange.eth",
//                     "description": "EulerLagrange's node",
//                     "logo": "https://prod-usea1-mainnet-operator-metadata.s3.amazonaws.com/0xaa280fdb50391fb63458fee1b484be2f36ce990b/logo.png",
//                     "twitter": "https://twitter.com/Euler__Lagrange",
//                     "address": "0xaa280fdb50391fb63458fee1b484be2f36ce990b",
//                     "numStakers": 2,
//                     "shares": [
//                         {
//                             "0x93c4b944d05dfe6df7645a86cd2206016c51564d": "96040946218139731"
//                         }
//                     ]
//                 }
//             }
//         }
//     }
// ]
#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Shares {
    pub address: String,
    pub amount: String,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub name: String,
    pub website: String,
    pub description: String,
    pub logo: String,
    pub twitter: String,
    pub address: String,
    pub num_stakes: u32,
    pub shares: Vec<Shares>,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResultData {
    pub data: Metadata,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OperatorMetadataResult {
    pub result: ResultData,
}
