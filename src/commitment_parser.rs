use clap::Parser;
use ethers::types::{Signature, H160};
use ethers::utils::hash_message;
use serde::{Deserialize, Serialize};
use serde_json::{Value, Map, json};
use std::str::FromStr;
use eyre::Error;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the JSON file containing the commitment
    #[arg(short, long)]
    input: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Commitment {
    pub signature: String,
    pub address: String,
    pub platform: String,
    pub resource: String,
    pub value: String,
    pub threshold: u64,
}

impl Commitment {
    pub fn to_dict(&self) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("address".to_string(), json!(self.address));
        map.insert("platform".to_string(), json!(self.platform));
        map.insert("resource".to_string(), json!(self.resource));
        map.insert("signature".to_string(), json!(self.signature));
        map.insert("threshold".to_string(), json!(self.threshold));
        map.insert("value".to_string(), json!(self.value));
        map
    }

    pub fn verify_signature(&self, message: &str, signature: &str, address: &str) -> Result<bool, Error> {
        // Parse signature
        let signature = Signature::from_str(signature)?;
        
        // Parse address
        let address = H160::from_str(address)?;
        
        // Hash the message (this includes the Ethereum prefix internally)
        let message_hash = hash_message(message);
        
        // Recover the signer and verify it matches
        let recovered = signature.recover(message_hash)?;
        
        Ok(recovered == address)
    }

    pub fn hash(&self) -> String {
        // Create a dictionary of the commitment data
        let commitment_dict = self.to_dict();
        
        // Format JSON string exactly like Python's json.dumps(sort_keys=True)
        let mut json_str = String::new();
        json_str.push('{');
        
        let mut first = true;
        for (key, value) in commitment_dict.iter() {
            if !first {
                json_str.push_str(", ");
            }
            first = false;
            json_str.push_str(&format!("\"{}\": {}", key, value));
        }
        json_str.push('}');
        
        let commitment_bytes = json_str.as_bytes();
        
        // Calculate keccak256 hash
        let hash = ethers::utils::keccak256(commitment_bytes);
        hex::encode(hash)
    }
}


