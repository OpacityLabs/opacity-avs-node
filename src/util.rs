use eyre::{eyre, Result};
use serde::de::DeserializeOwned;
use serde_json;
use urlencoding::encode;

use crate::{Metadata, OperatorMetadataResult, OperatorProperties};

pub fn parse_operator_config_file(location: &str) -> Result<OperatorProperties> {
    let mut operator_config: OperatorProperties = parse_config_file(location)?;
    if operator_config.operator_bls_keystore_path.is_none() {
        operator_config.operator_bls_keystore_path =
            Some(String::from("config/opacity.bls.key.json"));
    }
    Ok(operator_config)
}

pub fn validate_operator_config(operator_config: &OperatorProperties) -> Result<()> {
    if !(operator_config.chain_id == 1 || operator_config.chain_id == 17000) {
        return Err(eyre!("ChainID is not supported"));
    }
    Ok(())
}

/// Parse a yaml configuration file into a struct
pub fn parse_config_file<T: DeserializeOwned>(location: &str) -> Result<T> {
    let file = std::fs::File::open(location)?;
    let config: T = serde_yaml::from_reader(file)?;
    Ok(config)
}

/// Parse a csv file into a vec of structs
pub fn parse_csv_file<T: DeserializeOwned>(location: &str) -> Result<Vec<T>> {
    let file = std::fs::File::open(location)?;
    let mut reader = csv::Reader::from_reader(file);
    let mut table: Vec<T> = Vec::new();
    for result in reader.deserialize() {
        let record: T = result?;
        table.push(record);
    }
    Ok(table)
}

fn get_operator_metadata_url(address: String, chain_id: u32) -> String {
    let json_string =
        "{\"0\":{\"json\":{\"address\":\"0x0000000000000000000000000000000000000000\"}}}"
            .replace("0x0000000000000000000000000000000000000000", &address);
    let encoded = encode(&json_string).to_string();
    let host = if chain_id == 1 {
        "https://app.eigenlayer.xyz"
    } else {
        "https://holesky.eigenlayer.xyz"
    };
    format!(
        "{host}/api/trpc/operator.getOperatorSummary?batch=1&input={query}",
        host = host,
        query = encoded
    )
}

pub async fn fetch_operator_metadata(address: String, chain_id: u32) -> Result<Metadata> {
    let url = get_operator_metadata_url(address, chain_id);
    let response = reqwest::get(url).await?.text().await?;
    let metadata: Vec<OperatorMetadataResult> = serde_json::from_str(&response)?;
    let metadata = metadata.get(0).unwrap();
    Ok(metadata.result.data.json.clone())
}

#[cfg(test)]
mod test {

    use crate::{
        config::NotaryServerProperties, domain::auth::AuthorizationWhitelistRecord,
        util::parse_csv_file,
    };

    use super::{parse_config_file, Result};

    #[test]
    fn test_parse_config_file() {
        let location = "./config/config.yaml";
        let config: Result<NotaryServerProperties> = parse_config_file(location);
        assert!(
            config.is_ok(),
            "Could not open file or read the file's values."
        );
    }

    #[test]
    fn test_parse_csv_file() {
        let location = "./fixture/auth/whitelist.csv";
        let table: Result<Vec<AuthorizationWhitelistRecord>> = parse_csv_file(location);
        assert!(
            table.is_ok(),
            "Could not open csv or read the csv's values."
        );
    }
}

#[tokio::test]
async fn test_get_operator_metadata_holesky() {
    let address = "0x53091dfa16b9206a282cd618a45691db8220c2f9";
    let metadata = crate::util::fetch_operator_metadata(address.to_string(), 17000).await;
    assert!(metadata.is_ok());
    let metadata = metadata.unwrap();
    assert_eq!(metadata.address, address);
}

#[tokio::test]
async fn test_get_operator_metadata_mainnet() {
    let address = "0xe743b96d0c9b50a0d902a93c95ccb4ac8749a8c5";
    let metadata = crate::util::fetch_operator_metadata(address.to_string(), 1).await;
    assert!(metadata.is_ok());
    let metadata = metadata.unwrap();
    assert_eq!(metadata.address, address);
}
