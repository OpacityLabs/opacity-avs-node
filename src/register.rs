//! register operator in quorum with avs registry coordinator
use alloy_primitives::U256;
use alloy_primitives::{Bytes, FixedBytes};
use alloy_provider::Provider;
use alloy_signer_local::PrivateKeySigner;
use eigen_client_avsregistry::writer::AvsRegistryChainWriter;
use eigen_client_avsregistry::reader::AvsRegistryChainReader;
use eigen_client_elcontracts::reader::ELChainReader;
use eigen_crypto_bls::BlsKeyPair;
use eigen_logging::get_test_logger;
use eigen_testing_utils::m2_holesky_constants::{
    AVS_DIRECTORY_ADDRESS, DELEGATION_MANAGER_ADDRESS, OPERATOR_STATE_RETRIEVER,
    SLASHER_ADDRESS
};
use eigen_utils::get_provider;
use serde::Deserialize;
use std::{fs,env,path::Path,collections::HashMap};
use rust_bls_bn254::keystores::base_keystore::Keystore;
use eth_keystore::decrypt_key;
use hex;
use rand::Rng;        

fn generate_random_bytes() -> FixedBytes<32> {
    let mut rng = rand::thread_rng();
    let mut random_bytes = [0u8; 32];  // A 32-byte array initialized to zeros
    rng.fill(&mut random_bytes);       // Fill the array with random bytes
    FixedBytes::from(random_bytes)     // Convert to FixedBytes<32>
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
    let mut config: Config = serde_yaml::from_str(&yaml_content)?;
    let ecdsa_private_keystore_path  =  "/opacity-avs-node/config/opacity.ecdsa.key.json";
    let bls_private_keystore_path = "/opacity-avs-node/config/opacity.bls.key.json";
    println!("config: {:?}", config);

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

    let el_chain_reader = ELChainReader::new(
        get_test_logger().clone(),
        SLASHER_ADDRESS,
        DELEGATION_MANAGER_ADDRESS,
        AVS_DIRECTORY_ADDRESS,
        rpc_url_chain_reader,
    );
    let operator_address = wallet.address();
    let is_operator_registered = el_chain_reader.is_operator_registered(operator_address).await?;
    if !is_operator_registered {
        return Err(eyre::eyre!("Operator not registered to EigenLayer"));
    }
    let opacity_registry_coordinator_address = alloy_primitives::Address::from_str(&config.registry_coordinator_address).unwrap();
    let test_logger = get_test_logger();
    let avs_registry_reader = AvsRegistryChainReader::new(
        test_logger.clone(),
        opacity_registry_coordinator_address,
        OPERATOR_STATE_RETRIEVER,
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
        OPERATOR_STATE_RETRIEVER,
    )
    .await
    .expect("avs writer build fail ");
    
    let bls_private_keystore_path = "~/.eigenlayer/operator_keys/holesky_op_2.bls.key.json";
    let bls_key_password: String = env::var("OPERATOR_BLS_KEY_PASSWORD").map_err(|_| eyre::eyre!("BLS key password env var not set"))?;
    let file_content = fs::read_to_string(bls_private_keystore_path)?;
    println!("file_content: {:?}", file_content);
    let json_dict: HashMap<String, serde_json::Value> = serde_json::from_str(&file_content)?;
    let keystore_instance = Keystore::from_file(bls_private_keystore_path).unwrap();
    let decrypted_key = keystore_instance.decrypt(&bls_key_password).unwrap();
    let fr_key: String = decrypted_key.iter().map(|&value| value as char).collect();
    println!("fr_key: {:?}", fr_key);
    let bls_key_pair = BlsKeyPair::new(fr_key)?;



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
    avs_registry_writer
        .register_operator_in_quorum_with_avs_registry_coordinator(
            bls_key_pair,
            digest_hash,
            sig_expiry,
            quorum_nums,
            config.node_public_ip, // socket
        )
        .await?;
    Ok(())
}
