// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use clap_verbosity_flag::{InfoLevel, Verbosity};
use hathor_next::{discovery, logging, utils};
use thiserror::Error;
use tracing::*;
use tracing_subscriber::filter::LevelFilter;

#[derive(Error, Debug)]
enum CliError {
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("error installing color-eyre")]
    ColorEyre(#[from] color_eyre::Report),
    #[error("discovery error")]
    Discovery(#[from] discovery::Error),
}

#[derive(Debug, Parser)]
#[command(
    name = "dnsdiscover",
    version,
    about = "Discover peers via DNS TXT records"
)]
struct Cli {
    /// Domain to query for TXT records (each TXT is a PeerEndpoint)
    domain: Option<String>,
    /// Select mainnet bootstrap domain (mainnet.hathor.network)
    #[arg(long)]
    mainnet: bool,
    /// Select testnet (alias for --testnet-india)
    #[arg(long)]
    testnet: bool,
    /// Select testnet-golf bootstrap domain (golf.testnet.hathor.network)
    #[arg(long)]
    testnet_golf: bool,
    /// Select testnet-hotel bootstrap domain (hotel.testnet.hathor.network)
    #[arg(long)]
    testnet_hotel: bool,
    /// Select testnet-india bootstrap domain (india.testnet.hathor.network)
    #[arg(long)]
    testnet_india: bool,
    /// Enable DNS-over-TLS (DoT) lookup (Cloudflare) in addition to UDP/TCP
    /// Note: requires building with the `crypto-aws-lc` feature
    #[arg(long)]
    dot: bool,
    /// Enable DNS-over-HTTPS (DoH) lookup (Cloudflare) in addition to UDP/TCP
    /// Note: requires building with the `crypto-aws-lc` feature
    #[arg(long)]
    doh: bool,
    /// Output as JSON array instead of plain lines
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    verbosity: Verbosity<InfoLevel>,
}

fn main() -> Result<(), CliError> {
    color_eyre::install()?;

    let cli = Cli::parse();

    // Map CLI verbosity to fallback LevelFilter for setup_logging
    let max_level = cli.verbosity.tracing_level().unwrap_or(Level::INFO);
    let fallback_level = match max_level {
        Level::ERROR => LevelFilter::ERROR,
        Level::WARN => LevelFilter::WARN,
        Level::INFO => LevelFilter::INFO,
        Level::DEBUG => LevelFilter::DEBUG,
        Level::TRACE => LevelFilter::TRACE,
    };

    // Prepare logs directory and initialize logging via helper
    let logs_dir = utils::project_dir()
        .unwrap_or_else(|| std::env::current_dir().expect("cwd"))
        .join("logs");
    std::fs::create_dir_all(&logs_dir)?;
    let _log_guard = logging::setup_logging_with_level(&logs_dir, fallback_level)
        .expect("failed to setup logging");

    hathor_next::ensure_default_crypto_provider();
    trace!("opts: {:?}", cli);

    // Validate selection: either domain or one network flag; not both; not multiple networks
    let net_flags = [
        cli.mainnet,
        cli.testnet,
        cli.testnet_golf,
        cli.testnet_hotel,
        cli.testnet_india,
    ];
    let net_count = net_flags.iter().filter(|&&b| b).count();
    if cli.domain.is_some() && net_count > 0 {
        eprintln!("error: can't use positional domain together with network flags; choose one\n");
        std::process::exit(2);
    }
    if cli.domain.is_none() && net_count > 1 {
        eprintln!(
            "error: multiple networks selected; choose only one of --mainnet, --testnet(-india), --testnet-golf, --testnet-hotel\n"
        );
        std::process::exit(2);
    }

    // Determine target domain based on flags or positional argument
    let domain = if let Some(d) = &cli.domain {
        d.clone()
    } else if cli.mainnet {
        hathor_next::network_info::NETWORK_INFO_MAINNET
            .bootstrap_txt_domain
            .as_deref()
            .unwrap()
            .to_string()
    } else if cli.testnet_golf {
        hathor_next::network_info::NETWORK_INFO_TESTNET_GOLF
            .bootstrap_txt_domain
            .as_deref()
            .unwrap()
            .to_string()
    } else if cli.testnet_hotel {
        hathor_next::network_info::NETWORK_INFO_TESTNET_HOTEL
            .bootstrap_txt_domain
            .as_deref()
            .unwrap()
            .to_string()
    } else if cli.testnet_india || cli.testnet {
        hathor_next::network_info::NETWORK_INFO_TESTNET_INDIA
            .bootstrap_txt_domain
            .as_deref()
            .unwrap()
            .to_string()
    } else {
        // No domain or network selected
        eprintln!("error: provide a domain or one network flag (e.g., --mainnet)\n");
        std::process::exit(2);
    };

    debug!(%domain, "resolving bootstrap TXT domain");
    let endpoints =
        utils::build_tokio_runtime()?.block_on(discovery::discover_from_dns_txt_with_opts(
            &domain,
            discovery::DiscoveryOptions {
                udp: true,
                tcp: true,
                dot: cli.dot,
                doh: cli.doh,
            },
        ))?;

    if cli.json {
        // Serialize as an array of strings (PeerEndpoint implements Serialize to string)
        println!("{}", serde_json::to_string_pretty(&endpoints).unwrap());
    } else {
        for ep in &endpoints {
            println!("{}", ep);
        }
    }

    Ok(())
}
