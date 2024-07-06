use eyre::{eyre, Result};
use structopt::StructOpt;
use tracing::debug;

use opacity_avs_node::{
    init_tracing, parse_config_file, parse_operator_config_file, run_server,
    validate_operator_config, CliFields, NotaryServerError, NotaryServerProperties,
    OperatorProperties,
};

#[tokio::main]
async fn main() -> Result<(), NotaryServerError> {
    // Load command line arguments which contains the config file location
    let cli_fields: CliFields = CliFields::from_args();
    let notary_config: NotaryServerProperties = parse_config_file(&cli_fields.config_file)?;
    let operator_config: OperatorProperties =
        parse_operator_config_file(&cli_fields.operator_config_file)?;

    validate_operator_config(&operator_config).unwrap_or_else(|err| {
        panic!("Invalid operator config: {}", err);
    });
    // Set up tracing for logging
    init_tracing(&notary_config).map_err(|err| eyre!("Failed to set up tracing: {err}"))?;
    debug!("Opacity node config loaded");
    // Run the server
    run_server(&notary_config, &operator_config).await?;
    Ok(())
}
