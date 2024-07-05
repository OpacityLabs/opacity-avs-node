use eyre::Result;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json;

use crate::{Metadata, OperatorMetadataResult, OperatorProperties};

pub fn parse_operator_config_file(location: &str) -> Result<OperatorProperties> {
    let mut operator_config: OperatorProperties = parse_config_file(location)?;
    // if operator_config.operator_ecdsa_keystore_path.is_none() {
    //     operator_config.operator_ecdsa_keystore_path =
    //         Some(String::from("/opacity-avs-node/opacity.ecdsa.key.json"));
    // }
    if operator_config.operator_bls_keystore_path.is_none() {
        operator_config.operator_bls_keystore_path =
            Some(String::from("config/opacity.bls.key.json"));
    }
    Ok(operator_config)
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

pub async fn fetch_operator_metadata(address: String) -> Result<Metadata> {
    let response = reqwest::get(format!("https://app.eigenlayer.xyz/api/trpc/operator.getOperatorSummary?batch=1&input=%7B%220%22%3A%7B%22json%22%3A%7B%22address%22%3A%22{address}%22%7D%7D%7D"))
        .await?
        .text()
        .await?;
    let metadata: Vec<OperatorMetadataResult> = serde_json::from_str(&response)?;
    let metadata = metadata.get(0).unwrap();
    println!("{:?}", metadata.result.data.clone());
    Ok(metadata.result.data.clone())
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
