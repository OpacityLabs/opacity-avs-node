//! register operator in quorum with avs registry coordinator
use alloy::primitives::{Bytes, FixedBytes};

use alloy::primitives::Address;
use alloy::providers::{Provider, WalletProvider};
use alloy_primitives::U256;
use alloy_signer_local::PrivateKeySigner;
use eigensdk::client_avsregistry::reader::AvsRegistryChainReader;
use eigensdk::crypto_bls::BlsKeyPair;
use eigensdk::logging::get_test_logger;
use eigen_common::{get_provider, get_signer};
use std::{fs,env,path::Path};
use eth_keystore::decrypt_key;
use hex;
use eth_bn254_keystore;
use num_bigint::BigUint;
use opacity_avs_node::OperatorProperties;
use tracing::{debug, info, error};
use eigensdk::client_avsregistry::writer::AvsRegistryChainWriter;


fn get_etherscan_uri(chain_id: u32, tx_hash: &str) -> String {
    let etherscan_url = if chain_id == 1 {
        "https://etherscan.io/tx/"
    } else {
        "https://holesky.etherscan.io/tx/"
    };
    format!("{}{}", etherscan_url, tx_hash)
}

use eyre::Result;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

#[tokio::main]
#[allow(clippy::expect_used)]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Err(eyre::eyre!("Invalid number of arguments"));
    }
    let config_path = &args[1];
    let yaml_content = fs::read_to_string(config_path)?;
    let mut config: OperatorProperties = serde_yaml::from_str(&yaml_content)?;
    let ecdsa_private_keystore_path  =  "/opacity-avs-node/config/opacity.ecdsa.key.json";
    let bls_private_keystore_path = config.operator_bls_keystore_path.clone().expect("BLS keystore path not found");
    info!("Starting with config: {:?}", config);
    let test_logger = get_test_logger();

    let provider = get_provider(&config.eth_rpc_url);
    let chain_id = provider.get_chain_id().await? as u32;
    if chain_id != config.chain_id {
        return Err(eyre::eyre!("Chain id mismatch, please check the rpc url"));
    }

    let ecdsa_key_password: String = env::var("OPERATOR_ECDSA_KEY_PASSWORD").map_err(|_| eyre::eyre!("ECDSA key password env var not set"))?;
    let ecdsa_keypath = Path::new(&ecdsa_private_keystore_path);
    let private_key = decrypt_key(ecdsa_keypath, ecdsa_key_password)?;
    let wallet = PrivateKeySigner::from_slice(&private_key)?;
    let private_key_string = hex::encode(wallet.credential().to_bytes());
    let rpc_url_registry_reader = config.eth_rpc_url.clone();
    let operator_state_retriever_address = if config.chain_id == 1 {
        Address::from_str("D5D7fB4647cE79740E6e83819EFDf43fa74F8C31")?
    } else {
        Address::from_str("B4baAfee917fb4449f5ec64804217bccE9f46C67")?
    };
    let opacity_registry_coordinator_address = Address::from_str(&config.registry_coordinator_address)?;
    let signer = get_signer(&private_key_string, &config.eth_rpc_url);
    let test_logger = get_test_logger();

    let avs_registry_writer = AvsRegistryChainWriter::build_avs_registry_chain_writer(
        test_logger.clone(),
        config.eth_rpc_url.clone(),
        private_key_string.clone(),
        opacity_registry_coordinator_address.clone(),
        Address::ZERO,
    )
    .await
    .expect("avs writer build fail ");
    let avs_registry_reader = AvsRegistryChainReader::new(
        test_logger.clone(),
        opacity_registry_coordinator_address,
        operator_state_retriever_address,
        rpc_url_registry_reader,
    ).await?;
    
    let is_operator_registered_in_avs = avs_registry_reader.is_operator_registered(signer.default_signer_address()).await?;
    if is_operator_registered_in_avs {
        return Err(eyre::eyre!("Operator {} already registered in AVS", signer.default_signer_address()));
    }
    
    let bls_key_password: String = env::var("OPERATOR_BLS_KEY_PASSWORD").map_err(|_| eyre::eyre!("BLS key password env var not set"))?;
    let decrypted_key_vector = eth_bn254_keystore::decrypt_key(bls_private_keystore_path, bls_key_password)?;
    let fr = BigUint::from_bytes_be(&decrypted_key_vector).to_string();
    let bls_key_pair = BlsKeyPair::new(fr)?;
    let digest_hash: FixedBytes<32> = FixedBytes::from([0x02; 32]);
    let signature_expiry: U256 = U256::from(86400);
    // Get the current SystemTime
    let now = SystemTime::now();
    let mut sig_expiry: U256 = U256::from(0);
    // Convert SystemTime to a Duration since the UNIX epoch
    if let Ok(duration_since_epoch) = now.duration_since(UNIX_EPOCH) {
        // Convert the duration to seconds
        let seconds = duration_since_epoch.as_secs(); // Returns a u64

        // Convert seconds to U256
        sig_expiry = U256::from(seconds) + signature_expiry;
    } else {
        println!("System time seems to be before the UNIX epoch.");
    }
    let quorum_nums = Bytes::from([0x00]);
    // Register the operator in registry coordinator
    let tx = avs_registry_writer
        .register_operator_in_quorum_with_avs_registry_coordinator(
            bls_key_pair,
            digest_hash,
            sig_expiry,
            quorum_nums,
            "65.109.158.181:33078;31078".to_string(), // socket
        )
        .await?;

    info!("Register operator to AVS TX broadcasted!");
    info!("Transaction etherscan URI: {}", get_etherscan_uri(config.chain_id, &tx.to_string()));

    let mut receipt_received = false;
    let mut attempts = 0;
    const MAX_ATTEMPTS: u32 = 30; // Maximum number of attempts (1 minute with 2-second intervals)

    while !receipt_received && attempts < MAX_ATTEMPTS {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        attempts += 1;

        match provider.get_transaction_receipt(tx.clone()).await {
            Ok(Some(receipt)) => {
                receipt_received = true;
                if receipt.status() {
                    info!("Transaction succeeded! Block number: {:?}", receipt.block_number);
                } else {
                    error!("Transaction failed!, transaction receipt details: {:?}", receipt);
                }
            }
            Ok(None) => {
                debug!("Waiting for transaction receipt... (Attempt {}/{})", attempts, MAX_ATTEMPTS);
            }
            Err(e) => {
                error!("Error fetching transaction receipt: {:?}", e);
                if attempts == MAX_ATTEMPTS {
                    return Err(eyre::eyre!("Failed to get transaction receipt after {} attempts", MAX_ATTEMPTS));
                }
            }
        }
    }

    let operator_id = avs_registry_reader.get_operator_id(signer.default_signer_address()).await?;
    debug!("Operator ID: {:?}", operator_id);
    config.operator_id = operator_id.to_string();
    let yaml_content = serde_yaml::to_string(&config)?;
    fs::write(config_path, yaml_content)?;
    info!("Operator ID added to config file");

    if !receipt_received {
        return Err(eyre::eyre!("Transaction receipt not received after {} attempts", MAX_ATTEMPTS));
    }

    Ok(())
}
