// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use clap_verbosity_flag::{InfoLevel, Verbosity};
use hathor_next::{
    discovery::{self, crawler},
    logging, network_info, peer, stun, utils,
};
use indicatif::ProgressStyle;
use serde::Serialize;
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use thiserror::Error;
use tokio::{net::TcpListener, signal, sync::watch};
use tracing::*;
use tracing_indicatif::span_ext::IndicatifSpanExt;
use tracing_subscriber::filter::LevelFilter;

#[derive(Error, Debug)]
enum CliError {
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("error installing color-eyre")]
    ColorEyre(#[from] color_eyre::Report),
    #[error("peer error")]
    Peer(#[from] peer::Error),
    #[error("discovery error")]
    Discovery(#[from] discovery::Error),
    #[error("crawler error")]
    Crawler(#[from] crawler::CrawlError),
    #[error("stun error")]
    Stun(#[from] stun::Error),
    #[error("serialization error")]
    Json(#[from] serde_json::Error),
    #[error("unknown network '{0}', provide --genesis (and optionally --bootstrap)")]
    UnknownNetwork(String),
    #[error("at least one discovery channel must be enabled")]
    NoDiscoveryChannel,
    #[error("no seeds available; provide --seed or set --bootstrap/--network with DNS support")]
    NoSeeds,
}

#[derive(Debug, Parser)]
#[command(
    name = "peer-crawl-nc",
    version,
    about = "Crawl peers and query BEST-BLOCKCHAIN + BLOCK-NC-ROOT-ID for each peer"
)]
struct Cli {
    /// Network to crawl (e.g. mainnet, testnet, testnet-india)
    #[arg(long)]
    network: String,
    /// Optional genesis short hash override (required for unknown networks)
    #[arg(long)]
    genesis: Option<String>,
    /// Override bootstrap TXT domain used for seeding
    #[arg(long)]
    bootstrap: Option<String>,
    /// Local private peer JSON (default: ./peer.json)
    #[arg(long, default_value = "peer.json")]
    peer: PathBuf,
    /// Seed entrypoint to enqueue (may be repeated)
    #[arg(long = "seed", value_parser = parse_peer_endpoint, value_name = "ENDPOINT")]
    seeds: Vec<peer::PeerEndpoint>,
    /// Disable UDP DNS lookups when seeding
    #[arg(long)]
    no_udp: bool,
    /// Disable TCP DNS lookups when seeding
    #[arg(long)]
    no_tcp: bool,
    /// Enable DNS over TLS (Cloudflare) when seeding
    #[arg(long)]
    dot: bool,
    /// Enable DNS over HTTPS (Cloudflare) when seeding
    #[arg(long)]
    doh: bool,
    /// Override TCP connect timeout (e.g. 5s, 1m)
    #[arg(long, value_parser = humantime::parse_duration, value_name = "DURATION")]
    connect_timeout: Option<Duration>,
    /// Override readiness timeout (time waiting for READY state)
    #[arg(long, value_parser = humantime::parse_duration, value_name = "DURATION")]
    ready_timeout: Option<Duration>,
    /// Override GET-PEERS inactivity timeout
    #[arg(long, value_parser = humantime::parse_duration, value_name = "DURATION")]
    peers_timeout: Option<Duration>,
    /// Override DNS resolution timeout
    #[arg(long, value_parser = humantime::parse_duration, value_name = "DURATION")]
    dns_timeout: Option<Duration>,
    /// Override BEST-BLOCKCHAIN response timeout
    #[arg(long, value_parser = humantime::parse_duration, value_name = "DURATION")]
    best_blockchain_timeout: Option<Duration>,
    /// Override BLOCK-NC-ROOT-ID response timeout
    #[arg(long, value_parser = humantime::parse_duration, value_name = "DURATION")]
    block_nc_root_timeout: Option<Duration>,
    /// Maximum number of concurrent outbound connections
    #[arg(long, value_name = "N")]
    concurrency: Option<usize>,
    /// Listen for inbound peer connections (may be repeated)
    #[arg(long, value_name = "ADDR")]
    listen: Vec<SocketAddr>,
    /// Extra time to keep the listener active after crawling completes
    #[arg(long, value_parser = humantime::parse_duration, value_name = "DURATION")]
    listen_grace: Option<Duration>,
    /// Use STUN to discover how the listen port is exposed publicly
    #[arg(long)]
    discover_entrypoint_stun: bool,
    /// STUN server address (host:port) used for entrypoint discovery
    #[arg(long, value_name = "ADDR", default_value = "stun.cloudflare.com:3478")]
    discover_entrypoint_stun_server: String,
    /// Override the STUN discovery timeout (defaults to 3 seconds)
    #[arg(long, value_parser = humantime::parse_duration, value_name = "DURATION")]
    discover_entrypoint_stun_timeout: Option<Duration>,
    /// Emit JSON instead of human-oriented output
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    verbosity: Verbosity<InfoLevel>,
}

fn main() -> Result<(), CliError> {
    color_eyre::install()?;

    let cli = Cli::parse();
    let max_level = cli.verbosity.tracing_level().unwrap_or(Level::INFO);
    let fallback_level = match max_level {
        Level::ERROR => LevelFilter::ERROR,
        Level::WARN => LevelFilter::WARN,
        Level::INFO => LevelFilter::INFO,
        Level::DEBUG => LevelFilter::DEBUG,
        Level::TRACE => LevelFilter::TRACE,
    };

    let logs_dir = utils::project_dir()
        .unwrap_or_else(|| std::env::current_dir().expect("cwd"))
        .join("logs");
    std::fs::create_dir_all(&logs_dir)?;
    let _log_guard = logging::setup_logging_with_level(&logs_dir, fallback_level)
        .expect("failed to setup logging");

    hathor_next::ensure_default_crypto_provider();
    trace!(?cli, "cli options");

    let mut private_peer = peer::PrivatePeer::load_file(&cli.peer)?;
    let network = resolve_network(
        &cli.network,
        cli.genesis.as_deref(),
        cli.bootstrap.as_deref(),
    )?;

    let discovery_options = discovery::DiscoveryOptions {
        udp: !cli.no_udp,
        tcp: !cli.no_tcp,
        dot: cli.dot,
        doh: cli.doh,
    };
    if !discovery_options.udp
        && !discovery_options.tcp
        && !discovery_options.dot
        && !discovery_options.doh
    {
        return Err(CliError::NoDiscoveryChannel);
    }

    let runtime = utils::build_tokio_runtime()?;
    let mut seeds = cli.seeds.clone();
    if seeds.is_empty() {
        let Some(domain) = network.bootstrap_txt_domain.as_deref() else {
            return Err(CliError::NoSeeds);
        };
        debug!(domain, "resolving bootstrap TXT records");
        seeds = runtime.block_on(discovery::discover_from_dns_txt_with_opts(
            domain,
            discovery_options,
        ))?;
    }
    if seeds.is_empty() {
        return Err(CliError::NoSeeds);
    }

    let mut crawl_cfg = crawler::CrawlConfig::default();
    if let Some(d) = cli.connect_timeout {
        crawl_cfg.connect_timeout = d;
    }
    if let Some(d) = cli.ready_timeout {
        crawl_cfg.ready_timeout = d;
    }
    if let Some(d) = cli.peers_timeout {
        crawl_cfg.peers_timeout = d;
    }
    if let Some(d) = cli.dns_timeout {
        crawl_cfg.dns_timeout = d;
    }
    if let Some(n) = cli.concurrency {
        crawl_cfg.concurrency = n.max(1);
    }
    if let Some(d) = cli.listen_grace {
        crawl_cfg.listener_grace = d;
    } else if !cli.listen.is_empty() {
        crawl_cfg.listener_grace = Duration::from_secs(30);
    }

    let mut probe_cfg = crawler::ProbeConfig::default();
    if let Some(d) = cli.best_blockchain_timeout {
        probe_cfg.best_blockchain_timeout = d;
    }
    if let Some(d) = cli.block_nc_root_timeout {
        probe_cfg.block_nc_root_timeout = d;
    }
    crawl_cfg.probe = Some(probe_cfg);

    let listeners = if cli.listen.is_empty() {
        Vec::new()
    } else {
        runtime.block_on(async {
            let mut sockets = Vec::new();
            for addr in &cli.listen {
                let listener = TcpListener::bind(addr).await.map_err(CliError::Io)?;
                sockets.push(listener);
            }
            Ok::<_, CliError>(sockets)
        })?
    };

    if cli.discover_entrypoint_stun {
        if listeners.is_empty() {
            warn!(
                "--discover-entrypoint-stun requires at least one --listen address; skipping STUN discovery"
            );
        } else {
            let bound_local_addrs = listeners
                .iter()
                .map(|listener| listener.local_addr())
                .collect::<Result<Vec<_>, _>>()
                .map_err(CliError::Io)?;
            let mut stun_targets = Vec::new();
            for &listen_addr in &bound_local_addrs {
                match listen_addr {
                    SocketAddr::V4(_) => stun_targets.push((listen_addr, listen_addr)),
                    SocketAddr::V6(v6) => {
                        stun_targets.push((listen_addr, listen_addr));
                        if v6.ip().is_unspecified() {
                            let ipv4_bind =
                                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), v6.port());
                            stun_targets.push((listen_addr, ipv4_bind));
                        }
                    }
                }
            }
            let stun_server = cli.discover_entrypoint_stun_server.clone();
            let stun_timeout = cli
                .discover_entrypoint_stun_timeout
                .unwrap_or_else(|| Duration::from_secs(3));
            let discovered_addrs = runtime.block_on(async move {
                let mut results = Vec::new();
                for (listen_addr, bind_addr) in &stun_targets {
                    match stun::discover_public_addr(stun_server.as_str(), *bind_addr, stun_timeout)
                        .await
                    {
                        Ok(public_addr) => {
                            info!(
                                ?listen_addr,
                                ?bind_addr,
                                %public_addr,
                                server = %stun_server,
                                "STUN discovered public entrypoint"
                            );
                            results.push(public_addr);
                        }
                        Err(err) => {
                            warn!(
                                ?err,
                                ?listen_addr,
                                ?bind_addr,
                                server = %stun_server,
                                "STUN entrypoint discovery failed"
                            );
                        }
                    }
                }
                results
            });
            for public_addr in discovered_addrs {
                let endpoint: peer::PeerEndpoint =
                    peer::PeerAddress::from_socket_tcp(public_addr).into();
                if private_peer.endpoints.contains(&endpoint) {
                    debug!(%endpoint, "STUN-discovered entrypoint already present; skipping");
                } else {
                    debug!(%endpoint, "adding STUN-discovered entrypoint");
                    private_peer.endpoints.push(endpoint);
                }
            }
        }
    }

    let crawler = crawler::PeerCrawler::new(network.clone(), private_peer, crawl_cfg)?;
    let stats = Arc::new(Mutex::new(crawler::CrawlStats::default()));
    let progress_span = info_span!(
        "peer_crawl_nc_progress",
        indicatif.pb_show = tracing::field::Empty
    );
    let progress_style = ProgressStyle::with_template("{spinner} {msg}")
        .unwrap_or_else(|_| ProgressStyle::default_spinner());
    progress_span.pb_set_style(&progress_style);
    let progress_guard = progress_span.enter();
    progress_span.pb_set_message("starting crawl...");
    let stats_for_thread = Arc::clone(&stats);
    let span_for_thread = progress_span.clone();
    let progress_handle = thread::spawn(move || {
        loop {
            thread::sleep(Duration::from_millis(200));
            let snapshot = match stats_for_thread.lock() {
                Ok(guard) => guard.clone(),
                Err(_) => break,
            };
            let message = format!(
                "queued:{:<4} in-flight:{:<3} visited:{:<3} failures:{:<3} attempts:{:<4}",
                snapshot.queued,
                snapshot.in_flight,
                snapshot.visited,
                snapshot.failures,
                snapshot.attempted,
            );
            span_for_thread.pb_set_message(&message);
            if snapshot.is_done {
                break;
            }
        }
    });

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut crawl_fut =
        Box::pin(crawler.crawl(seeds, listeners, Some(stats.clone()), Some(shutdown_rx)));
    let report = runtime.block_on(async {
        tokio::select! {
            report = &mut crawl_fut => report,
            ctrl = signal::ctrl_c() => {
                match ctrl {
                    Ok(()) => info!("SIGINT received; shutting down crawl"),
                    Err(err) => warn!(?err, "failed to install ctrl_c handler"),
                }
                let _ = shutdown_tx.send(true);
                crawl_fut.await
            }
        }
    });
    mark_stats_done(&stats);
    let _ = progress_handle.join();
    drop(progress_guard);
    drop(progress_span);

    if cli.json {
        let serializable = JsonReport::from_report(&network, &report);
        println!("{}", serde_json::to_string_pretty(&serializable)?);
        return Ok(());
    }

    println!(
        "Network: {} (genesis {})",
        network.name, network.genesis_short_hash
    );
    println!(
        "Discovered {} peers ({} failures)",
        report.peers.len(),
        report.failures.len()
    );

    for peer_id in report.peers.keys() {
        println!("peer {}", peer_id);
        if let Some(result) = report.probe_results.get(peer_id) {
            if result.entries.is_empty() {
                println!("  (no blocks returned)");
            } else {
                for entry in &result.entries {
                    match entry.nc_root_id {
                        Some(node_id) => println!("  {} {}", entry.block_id, node_id),
                        None => println!("  {} -", entry.block_id),
                    }
                }
            }
        } else {
            println!("  (probe skipped)");
        }
    }

    if !report.failures.is_empty() {
        println!();
        println!("Failures:");
        for failure in &report.failures {
            println!(
                "  {} (advertised by {:?}): {}",
                failure.endpoint, failure.advertised_by, failure.error
            );
        }
    }

    Ok(())
}

fn mark_stats_done(stats: &Arc<Mutex<crawler::CrawlStats>>) {
    if let Ok(mut guard) = stats.lock() {
        guard.is_done = true;
    }
}

fn resolve_network(
    name: &str,
    genesis_override: Option<&str>,
    bootstrap_override: Option<&str>,
) -> Result<network_info::NetworkInfo<'static>, CliError> {
    let lower = name.to_ascii_lowercase();
    let mut info = match lower.as_str() {
        "mainnet" => network_info::NETWORK_INFO_MAINNET.clone(),
        "testnet" => network_info::NETWORK_INFO_TESTNET_INDIA.clone(),
        "testnet-india" => network_info::NETWORK_INFO_TESTNET_INDIA.clone(),
        "testnet-golf" => network_info::NETWORK_INFO_TESTNET_GOLF.clone(),
        "testnet-hotel" => network_info::NETWORK_INFO_TESTNET_HOTEL.clone(),
        other => {
            let genesis =
                genesis_override.ok_or_else(|| CliError::UnknownNetwork(other.to_string()))?;
            return Ok(network_info::NetworkInfo {
                name: Cow::Owned(other.to_string()),
                genesis_short_hash: Cow::Owned(genesis.to_string()),
                bootstrap_txt_domain: bootstrap_override.map(|b| Cow::Owned(b.to_string())),
            });
        }
    };

    if let Some(genesis) = genesis_override {
        info.genesis_short_hash = Cow::Owned(genesis.to_string());
    }
    if let Some(bootstrap) = bootstrap_override {
        info.bootstrap_txt_domain = Some(Cow::Owned(bootstrap.to_string()));
    }
    Ok(info)
}

fn parse_peer_endpoint(s: &str) -> Result<peer::PeerEndpoint, String> {
    s.parse()
        .map_err(|e| format!("invalid peer endpoint '{}': {}", s, e))
}

#[derive(Serialize)]
struct JsonReport {
    network: String,
    genesis_short_hash: String,
    peer_count: usize,
    failure_count: usize,
    peers: Vec<JsonPeer>,
    failures: Vec<JsonFailure>,
}

#[derive(Serialize)]
struct JsonPeer {
    peer_id: peer::PeerId,
    blocks: Vec<JsonBlock>,
}

#[derive(Serialize)]
struct JsonBlock {
    block_id: hathor_next::vertex::BlockId,
    nc_root_id: Option<hathor_next::nano::NodeId>,
}

#[derive(Serialize)]
struct JsonFailure {
    endpoint: peer::PeerEndpoint,
    advertised_by: Option<peer::PeerId>,
    error: String,
}

impl JsonReport {
    fn from_report(
        network: &network_info::NetworkInfo<'static>,
        report: &crawler::CrawlReport,
    ) -> Self {
        let peers = report
            .peers
            .keys()
            .map(|peer_id| {
                let blocks = report
                    .probe_results
                    .get(peer_id)
                    .map(|probe| {
                        probe
                            .entries
                            .iter()
                            .map(|entry| JsonBlock {
                                block_id: entry.block_id,
                                nc_root_id: entry.nc_root_id,
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                JsonPeer {
                    peer_id: *peer_id,
                    blocks,
                }
            })
            .collect();

        let failures = report
            .failures
            .iter()
            .map(|failure| JsonFailure {
                endpoint: failure.endpoint.clone(),
                advertised_by: failure.advertised_by,
                error: failure.error.to_string(),
            })
            .collect();

        Self {
            network: network.name.to_string(),
            genesis_short_hash: network.genesis_short_hash.to_string(),
            peer_count: report.peers.len(),
            failure_count: report.failures.len(),
            peers,
            failures,
        }
    }
}
