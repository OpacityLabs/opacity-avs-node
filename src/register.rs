//! register operator in quorum with avs registry coordinator
use alloy_primitives::U256;
use alloy_primitives::{Bytes, FixedBytes,Address};
use alloy_provider::Provider;
use alloy_signer_local::PrivateKeySigner;
use eigen_client_avsregistry::writer::AvsRegistryChainWriter;
use eigen_client_avsregistry::reader::AvsRegistryChainReader;
use eigen_client_elcontracts::reader::ELChainReader;
use eigen_crypto_bls::BlsKeyPair;
use eigen_logging::get_test_logger;
use eigen_utils::get_provider;
use serde::Deserialize;
use std::{fs,env,path::Path};
use eth_keystore::decrypt_key;
use hex;
use rand::Rng;        
use eth_bn254_keystore;
use num_bigint::BigUint;

fn generate_random_bytes() -> FixedBytes<32> {
    let mut rng = rand::thread_rng();
    let mut random_bytes = [0u8; 32];  // A 32-byte array initialized to zeros
    rng.fill(&mut random_bytes);       // Fill the array with random bytes
    FixedBytes::from(random_bytes)     // Convert to FixedBytes<32>
}

fn get_etherscan_uri(chain_id: u64, tx_hash: &str) -> String {
    let etherscan_url = if chain_id == 1 {
        "https://etherscan.io/tx/"
    } else {
        "https://holesky.etherscan.io/tx/"
    };
    format!("{}{}", etherscan_url, tx_hash)
}

#[derive(Debug, Deserialize)]
struct Config {
    production: bool,
    registry_coordinator_address: String,
    opacity_avs_address: String,
    avs_directory_address: String,
    eigenlayer_delegation_manager: String,
    chain_id: u64,
    operator_address: String,
    eth_rpc_url: String,
    node_public_ip: String,
}

use eyre::Result;
use lazy_static::lazy_static;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

lazy_static! {
    /// 1 day
    static ref SIGNATURE_EXPIRY: U256 = U256::from(86400);
}
#[tokio::main]
#[allow(clippy::expect_used)]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        return Err(eyre::eyre!("Invalid number of arguments"));
    }

    let config_path = &args[1];
    let yaml_content = fs::read_to_string(config_path)?;
    let config: Config = serde_yaml::from_str(&yaml_content)?;
    let ecdsa_private_keystore_path  =  "/opacity-avs-node/config/opacity.ecdsa.key.json";
    let bls_private_keystore_path = "/opacity-avs-node/config/opacity.bls.key.json";
    println!("Starting with config: {:?}", config);

    let provider = get_provider(&config.eth_rpc_url);
    let chain_id = provider.get_chain_id().await?;
    if chain_id != config.chain_id {
        return Err(eyre::eyre!("Chain id mismatch, please check the rpc url"));
    }

    let ecdsa_key_password: String = env::var("OPERATOR_ECDSA_KEY_PASSWORD").map_err(|_| eyre::eyre!("ECDSA key password env var not set"))?;
    let ecdsa_keypath = Path::new(&ecdsa_private_keystore_path);
    let private_key = decrypt_key(ecdsa_keypath, ecdsa_key_password)?;
    let wallet = PrivateKeySigner::from_slice(&private_key)?;
    let private_key_string = hex::encode(wallet.credential().to_bytes());
    let rpc_url_chain_reader = config.eth_rpc_url.clone();
    let rpc_url_registry_reader = config.eth_rpc_url.clone();
    let rpc_url_registry_writer = config.eth_rpc_url.clone();
    let avs_directory_address = Address::from_str(&config.avs_directory_address)?;
    let delegation_manager_address = Address::from_str(&config.eigenlayer_delegation_manager)?;
    let operator_state_retriever_address = if config.chain_id == 1 {
        Address::from_str("D5D7fB4647cE79740E6e83819EFDf43fa74F8C31")?
    } else {
        Address::from_str("B4baAfee917fb4449f5ec64804217bccE9f46C67")?
    };
    let slasher_address = if config.chain_id == 1 {
        Address::from_str("D92145c07f8Ed1D392c1B88017934E301CC1c3Cd")?
    } else {
        Address::from_str("cAe751b75833ef09627549868A04E32679386e7C")?
    };
    let opacity_registry_coordinator_address = alloy_primitives::Address::from_str(&config.registry_coordinator_address).unwrap();
    
    let el_chain_reader = ELChainReader::new(
        get_test_logger().clone(),
        slasher_address,
        delegation_manager_address,
        avs_directory_address,
        rpc_url_chain_reader,
    );
    let operator_address = wallet.address();
    let is_operator_registered = el_chain_reader.is_operator_registered(operator_address).await?;
    if !is_operator_registered {
        return Err(eyre::eyre!("Operator not registered to EigenLayer"));
    }
    let test_logger = get_test_logger();
    let avs_registry_reader = AvsRegistryChainReader::new(
        test_logger.clone(),
        opacity_registry_coordinator_address,
        operator_state_retriever_address,
        rpc_url_registry_reader,
    ).await?;
    
    let is_operator_registered_in_avs = avs_registry_reader.is_operator_registered(operator_address).await?;
    if is_operator_registered_in_avs {
        return Err(eyre::eyre!("Operator not registered in AVS"));
    }
    let avs_registry_writer = AvsRegistryChainWriter::build_avs_registry_chain_writer(
        test_logger.clone(),
        rpc_url_registry_writer,
        private_key_string,
        opacity_registry_coordinator_address,
        operator_state_retriever_address,
    )
    .await
    .expect("avs writer build fail ");
    
    let bls_key_password: String = env::var("OPERATOR_BLS_KEY_PASSWORD").map_err(|_| eyre::eyre!("BLS key password env var not set"))?;
    let decrypted_key_vector = eth_bn254_keystore::decrypt_key(bls_private_keystore_path, bls_key_password)?;
    let fr = BigUint::from_bytes_be(&decrypted_key_vector).to_string();
    let bls_key_pair = BlsKeyPair::new(fr)?;


    let salt: FixedBytes<32> = generate_random_bytes();
    // Get the current SystemTime
    let now = SystemTime::now();
    let mut sig_expiry: U256 = U256::from(0);
    // Convert SystemTime to a Duration since the UNIX epoch
    if let Ok(duration_since_epoch) = now.duration_since(UNIX_EPOCH) {
        // Convert the duration to seconds
        let seconds = duration_since_epoch.as_secs(); // Returns a u64

        // Convert seconds to U256
        sig_expiry = U256::from(seconds) + *SIGNATURE_EXPIRY;
    } else {
        println!("System time seems to be before the UNIX epoch.");
    }



    let digest_hash: FixedBytes<32> = el_chain_reader
    .calculate_operator_avs_registration_digest_hash(
        operator_address,
        opacity_registry_coordinator_address,
        salt,
        sig_expiry,
    )
    .await?;
    // print!("digest_hash: {:?}", digest_hash);
    let quorum_nums = Bytes::from([0x00]);

    // Register the operator in registry coordinator
    let tx_hash = avs_registry_writer
        .register_operator_in_quorum_with_avs_registry_coordinator(
            bls_key_pair,
            digest_hash,
            sig_expiry,
            quorum_nums,
            config.node_public_ip, // socket
        )
        .await?;
    
    println!("Register operator to AVS TX broadcasted!");
    println!("Transaction etherscan URI: {}", get_etherscan_uri(config.chain_id, &tx_hash.to_string()));

    let mut receipt_received = false;
    let mut attempts = 0;
    const MAX_ATTEMPTS: u32 = 30; // Maximum number of attempts (1 minute with 2-second intervals)

    while !receipt_received && attempts < MAX_ATTEMPTS {
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        attempts += 1;

        match provider.get_transaction_receipt(tx_hash.clone()).await {
            Ok(Some(receipt)) => {
                receipt_received = true;
                if receipt.status() {
                    println!("Transaction succeeded! Block number: {:?}", receipt.block_number);
                } else {
                    println!("Transaction failed!, transaction receipt details: {:?}", receipt);
                }
            }
            Ok(None) => {
                println!("Waiting for transaction receipt... (Attempt {}/{})", attempts, MAX_ATTEMPTS);
            }
            Err(e) => {
                println!("Error fetching transaction receipt: {:?}", e);
                if attempts == MAX_ATTEMPTS {
                    return Err(eyre::eyre!("Failed to get transaction receipt after {} attempts", MAX_ATTEMPTS));
                }
            }
        }
    }

    if !receipt_received {
        return Err(eyre::eyre!("Transaction receipt not received after {} attempts", MAX_ATTEMPTS));
    }

    Ok(())
}
