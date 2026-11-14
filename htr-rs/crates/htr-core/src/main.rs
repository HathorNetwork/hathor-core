// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use clap_verbosity_flag::{InfoLevel, Verbosity};
use htr_core::*;
use std::path::PathBuf;
use thiserror::Error;
use tracing::*;
use tracing_subscriber::filter::LevelFilter;

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("error installing color-eyre")]
    ColorEyre(#[from] color_eyre::Report),
    #[error("p2p-server error")]
    P2p(#[from] p2p::Error),
    #[error("config error")]
    Config(#[from] config::ConfigError),
    #[error("{0}")]
    Cli(String),
}

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    #[arg(long = "config-dir")]
    config_dir: Option<PathBuf>,
    #[arg(long)]
    chain: Option<String>,
    #[arg(long)]
    mainnet: bool,
    #[arg(long)]
    testnet: bool,
    #[arg(long = "testnet-india")]
    testnet_india: bool,
    #[arg(long, value_delimiter = ',', num_args = 1..)]
    listen: Option<Vec<htr_core::peer::PeerAddress>>,
    #[arg(long, value_delimiter = ',', num_args = 1.., alias = "connect-to")]
    connect: Option<Vec<htr_core::peer::PeerAddress>>,
    /// Exit automatically after this many seconds (for quick manual tests)
    #[arg(long, value_name = "SECS")]
    timeout: Option<u64>,
    #[command(flatten)]
    verbosity: Verbosity<InfoLevel>,
}

fn main() -> Result<(), Error> {
    color_eyre::install()?;

    let cli = Cli::parse();

    let chain_override = select_chain_override(&cli)?;
    let runtime = config::load_runtime(
        cli.config_dir.clone(),
        chain_override,
        cli.listen.clone(),
        cli.connect.clone(),
    )?;

    let cli_level = cli.verbosity.tracing_level();
    let log_level = cli_level
        .map(level_to_filter)
        .or(runtime.log.level)
        .unwrap_or(LevelFilter::INFO);

    std::fs::create_dir_all(&runtime.paths.data_dir)?;
    let _log_guard = htr_core::logging::setup_logging_with_level_and_filters(
        &runtime.paths.logs_dir,
        log_level,
        &runtime.log.filters,
    )
    .expect("failed to setup logging");

    // Install the preferred rustls crypto provider globally (idempotent).
    htr_core::crypto::install_default_crypto_provider();
    trace!("opts: {:?}", cli);
    debug!("logging to {}", runtime.paths.logs_dir.display());
    debug!("data dir {}", runtime.paths.data_dir.display());
    let timeout = cli.timeout.map(std::time::Duration::from_secs);
    p2p::run_server_main(
        runtime.peer,
        runtime.net.connect,
        runtime.net.listen_tcp,
        runtime.net.listen_quic,
        runtime.chain.network,
        timeout,
    )?;
    Ok(())
}

fn select_chain_override(cli: &Cli) -> Result<Option<String>, Error> {
    let mut chosen = Vec::new();
    if cli.mainnet {
        chosen.push("mainnet".to_string());
    }
    if cli.testnet {
        chosen.push("testnet".to_string());
    }
    if cli.testnet_india {
        chosen.push("testnet-india".to_string());
    }
    if let Some(chain) = &cli.chain {
        chosen.push(chain.clone());
    }

    if chosen.len() > 1 {
        return Err(Error::Cli(
            "only one of --mainnet, --testnet, --testnet-india, or --chain may be provided"
                .to_string(),
        ));
    }

    Ok(chosen.into_iter().next())
}

fn level_to_filter(level: Level) -> LevelFilter {
    match level {
        Level::ERROR => LevelFilter::ERROR,
        Level::WARN => LevelFilter::WARN,
        Level::INFO => LevelFilter::INFO,
        Level::DEBUG => LevelFilter::DEBUG,
        Level::TRACE => LevelFilter::TRACE,
    }
}
