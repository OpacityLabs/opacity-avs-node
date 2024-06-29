use structopt::StructOpt;

/// Fields loaded from the command line when launching this server.
#[derive(Clone, Debug, StructOpt)]
#[structopt(name = "Opacity node")]
pub struct CliFields {
    /// Configuration file location
    #[structopt(long)]
    pub config_file: String,
}
