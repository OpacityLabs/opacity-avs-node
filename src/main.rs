use eyre::{eyre, Result};
use structopt::StructOpt;
use tracing::info;

use opacity_avs_node::{
    init_tracing, parse_config_file, run_server, CliFields, NotaryServerError,
    NotaryServerProperties,
};

#[tokio::main]
async fn main() -> Result<(), NotaryServerError> {
    // Load command line arguments which contains the config file location
    let cli_fields: CliFields = CliFields::from_args();
    let config: NotaryServerProperties = parse_config_file(&cli_fields.config_file)?;

    // Set up tracing for logging
    init_tracing(&config).map_err(|err| eyre!("Failed to set up tracing: {err}"))?;

    info!(?config, "Opacity node config loaded");

    info!(?config, "Starting opacity node on port 7047");
    // Run the server
    run_server(&config).await?;

    Ok(())
}
