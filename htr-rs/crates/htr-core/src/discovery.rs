// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use crate::peer::PeerEndpoint;
use futures::stream::{FuturesUnordered, StreamExt};
use hickory_resolver::TokioResolver;
#[cfg(feature = "crypto-aws-lc")]
use hickory_resolver::config::CLOUDFLARE;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::{NetError, runtime::TokioRuntimeProvider};
use hickory_resolver::proto::{ProtoError, rr::RData};
use hickory_resolver::system_conf;
use std::borrow::Cow;
use thiserror::Error;
use tracing::*;

#[derive(Error, Debug)]
pub enum Error {
    #[error("DNS resolve error")]
    Resolve(#[from] NetError),
    #[error("DNS system configuration error")]
    SystemConfig(#[from] ProtoError),
    #[error("no resolver channels configured")]
    NoResolverChannels,
    #[error("TXT record is not valid UTF-8")]
    InvalidUtf8(#[from] std::str::Utf8Error),
    // Endpoint parse errors are logged and skipped; not returned.
}

/// Channel selection for discovery. By default, UDP+TCP are enabled; DoT/DoH are off.
#[derive(Clone, Copy, Debug)]
pub struct DiscoveryOptions {
    pub udp: bool,
    pub tcp: bool,
    pub dot: bool,
    pub doh: bool,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            udp: true,
            tcp: true,
            dot: false,
            doh: false,
        }
    }
}

/// Query DNS TXT records from `domain` and parse each TXT RR as a `PeerEndpoint`.
///
/// - Uses the system DNS configuration via hickory-resolver.
/// - Each TXT RR may be split across multiple character-strings; they are concatenated
///   and interpreted as a UTF-8 string.
/// - Each resulting string is parsed using `PeerEndpoint::from_str`.
#[instrument(level = "debug", skip_all, fields(domain = %domain))]
pub async fn discover_from_dns_txt(domain: &str) -> Result<Vec<PeerEndpoint>, Error> {
    crate::ensure_default_crypto_provider();
    discover_from_dns_txt_with_opts(domain, DiscoveryOptions::default()).await
}

/// Like `discover_from_dns_txt` but allows selecting channels via options.
#[instrument(level = "debug", skip_all, fields(domain = %domain, udp = opts.udp, tcp = opts.tcp, dot = opts.dot, doh = opts.doh))]
pub async fn discover_from_dns_txt_with_opts(
    domain: &str,
    opts: DiscoveryOptions,
) -> Result<Vec<PeerEndpoint>, Error> {
    crate::ensure_default_crypto_provider();
    // Initialize resolvers from the system configuration (e.g., /etc/resolv.conf).
    let (sys_config, sys_opts): (ResolverConfig, ResolverOpts) = system_conf::read_system_conf()?;
    let tcp_servers: Vec<NameServerConfig> = sys_config
        .name_servers()
        .iter()
        .map(|ns| {
            NameServerConfig::new(
                ns.ip,
                ns.trust_negative_responses,
                vec![ConnectionConfig::tcp()],
            )
        })
        .collect();
    let udp_servers: Vec<NameServerConfig> = sys_config
        .name_servers()
        .iter()
        .map(|ns| {
            NameServerConfig::new(
                ns.ip,
                ns.trust_negative_responses,
                vec![ConnectionConfig::udp()],
            )
        })
        .collect();

    // Build per-channel resolvers as requested
    let mut resolvers: Vec<(Cow<'static, str>, TokioResolver)> = Vec::new();
    if opts.tcp && !tcp_servers.is_empty() {
        let cfg_tcp = ResolverConfig::from_parts(
            sys_config.domain().cloned(),
            sys_config.search().to_vec(),
            tcp_servers.clone(),
        );
        let mut o = sys_opts.clone();
        o.try_tcp_on_error = true;
        let r = TokioResolver::builder_with_config(cfg_tcp, TokioRuntimeProvider::default())
            .with_options(o)
            .build()?;
        resolvers.push((Cow::Borrowed("tcp"), r));
    }
    if opts.udp && !udp_servers.is_empty() {
        let cfg_udp = ResolverConfig::from_parts(
            sys_config.domain().cloned(),
            sys_config.search().to_vec(),
            udp_servers.clone(),
        );
        let mut o = sys_opts.clone();
        o.try_tcp_on_error = false; // pure UDP path
        o.edns0 = true; // allow larger payloads
        let r = TokioResolver::builder_with_config(cfg_udp, TokioRuntimeProvider::default())
            .with_options(o)
            .build()?;
        resolvers.push((Cow::Borrowed("udp"), r));
    }
    if opts.dot {
        #[cfg(feature = "crypto-aws-lc")]
        {
            // Use Cloudflare DoT as default.
            let cfg = ResolverConfig::tls(&CLOUDFLARE);
            let r =
                TokioResolver::builder_with_config(cfg, TokioRuntimeProvider::default()).build()?;
            resolvers.push((Cow::Borrowed("dot"), r));
        }
        #[cfg(not(feature = "crypto-aws-lc"))]
        warn!("DNS-over-TLS discovery requires the crypto-aws-lc feature");
    }
    if opts.doh {
        #[cfg(feature = "crypto-aws-lc")]
        {
            // Use Cloudflare DoH as default.
            let cfg = ResolverConfig::https(&CLOUDFLARE);
            let r =
                TokioResolver::builder_with_config(cfg, TokioRuntimeProvider::default()).build()?;
            resolvers.push((Cow::Borrowed("doh"), r));
        }
        #[cfg(not(feature = "crypto-aws-lc"))]
        warn!("DNS-over-HTTPS discovery requires the crypto-aws-lc feature");
    }

    // Ensure FQDN to bypass system search domains (e.g., avoid appending `.local.`)
    let fqdn = if domain.ends_with('.') {
        domain.to_string()
    } else {
        let mut s = String::with_capacity(domain.len() + 1);
        s.push_str(domain);
        s.push('.');
        s
    };

    // Perform TXT lookups in parallel across selected channels; take the first success.
    let mut tasks = FuturesUnordered::new();
    for (label, r) in resolvers.into_iter() {
        let fqdn_cloned = fqdn.clone();
        let label_cloned = label.clone();
        tasks.push(Box::pin(async move {
            (label_cloned, r.txt_lookup(&fqdn_cloned).await)
        }));
    }

    let mut first_err: Option<(String, NetError)> = None;
    let txt_lookup = loop {
        match tasks.next().await {
            None => {
                if let Some((label, err)) = first_err {
                    warn!(method = %label, error=?err, "all DNS TXT lookups failed");
                    return Err(Error::Resolve(err));
                } else {
                    return Err(Error::NoResolverChannels);
                }
            }
            Some((label, Ok(lookup))) => {
                debug!(method = %label, "dns TXT lookup succeeded");
                break lookup;
            }
            Some((label, Err(err))) => {
                warn!(method = %label, error=?err, "DNS TXT lookup failed on channel");
                if first_err.is_none() {
                    first_err = Some((label.into_owned(), err));
                }
            }
        }
    };

    let mut endpoints = Vec::new();

    for record in txt_lookup.answers() {
        let RData::TXT(txt) = &record.data else {
            continue;
        };
        // Join all character-strings from this TXT RR into a single string.
        // DNS TXT records can be split into multiple 255-byte chunks; concatenate them.
        let mut buf = String::new();
        for chunk in txt.txt_data.iter() {
            let s = std::str::from_utf8(chunk.as_ref())?;
            buf.push_str(s);
        }

        match buf.parse::<PeerEndpoint>() {
            Ok(endpoint) => {
                debug!(endpoint = %endpoint, "parsed peer endpoint from TXT");
                endpoints.push(endpoint);
            }
            Err(e) => {
                // Log invalid records but continue with other entries.
                warn!(txt = %buf, error = ?e, "invalid peer endpoint in TXT record; skipping");
            }
        }
    }

    Ok(endpoints)
}

pub mod crawler {
    use crate::nano::NodeId as NcNodeId;
    use crate::network_info::NetworkInfo;
    use crate::peer::{self, PeerAddress, PeerEndpoint, PeerId, PublicPeer, UnverifiedPeer};
    use crate::protocol::drivers::IoDriver;
    use crate::protocol::engine::{self, ProtocolCommand, ProtocolEvent, ProtocolHandle};
    use crate::protocol::message::{Capability, ControlMessage, HelloData, ReadyMessage};
    use crate::vertex::BlockId;
    use futures::future::OptionFuture;
    use futures::stream::{FuturesUnordered, StreamExt};
    use rustls::{ClientConfig, ServerConfig};
    use rustls_pki_types::ServerName;
    use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
    use std::net::SocketAddr;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;
    use thiserror::Error;
    use tokio::net::{TcpListener, TcpStream, lookup_host};
    use tokio::sync::{mpsc, watch};
    use tokio::time::{self, Instant};
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    use tracing::*;

    #[derive(Debug, Error, Clone)]
    pub enum CrawlError {
        #[error("address resolution failed: {details}")]
        Resolve { details: Arc<str> },
        #[error("no addresses resolved for endpoint")]
        NoAddresses,
        #[error("connection failed: {details}")]
        Connect { details: Arc<str> },
        #[error("protocol error: {details}")]
        Protocol { details: Arc<str> },
        #[error("unexpected peer-id: expected {expected}, got {got}")]
        PeerIdMismatch { expected: PeerId, got: PeerId },
        #[error("ready state timeout")]
        ReadyTimeout,
        #[error("connection closed before ready")]
        ConnectionClosed,
        #[error("remote error: {details}")]
        RemoteError { details: Arc<str> },
    }

    #[derive(Clone, Debug)]
    pub struct CrawlConfig {
        pub connect_timeout: Duration,
        pub ready_timeout: Duration,
        pub peers_timeout: Duration,
        pub dns_timeout: Duration,
        pub concurrency: usize,
        pub listener_grace: Duration,
        pub probe: Option<ProbeConfig>,
    }

    impl Default for CrawlConfig {
        fn default() -> Self {
            Self {
                connect_timeout: Duration::from_secs(3),
                ready_timeout: Duration::from_secs(5),
                peers_timeout: Duration::from_secs(5),
                dns_timeout: Duration::from_secs(10),
                concurrency: 100,
                listener_grace: Duration::from_secs(0),
                probe: None,
            }
        }
    }

    #[derive(Clone, Debug)]
    pub struct ProbeConfig {
        pub best_blockchain_len: u8,
        pub best_blockchain_timeout: Duration,
        pub block_nc_root_timeout: Duration,
    }

    impl Default for ProbeConfig {
        fn default() -> Self {
            Self {
                best_blockchain_len: 5,
                best_blockchain_timeout: Duration::from_secs(5),
                block_nc_root_timeout: Duration::from_secs(5),
            }
        }
    }

    #[derive(Clone, Debug, Default)]
    pub struct CrawlStats {
        pub queued: usize,
        pub in_flight: usize,
        pub attempted: usize,
        pub visited: usize,
        pub failures: usize,
        pub is_done: bool,
    }

    #[derive(Debug, Default)]
    pub struct CrawlReport {
        pub peers: BTreeMap<PeerId, PeerGraphNode>,
        pub failures: Vec<FailedEndpoint>,
        pub probe_results: BTreeMap<PeerId, ProbeResult>,
    }

    #[derive(Debug, Default)]
    pub struct PeerGraphNode {
        pub public_peer: Option<PublicPeer>,
        pub hello: Option<HelloData>,
        pub advertises: BTreeSet<PeerId>,
        pub advertised_by: BTreeSet<PeerId>,
        pub observed_endpoints: BTreeSet<PeerEndpoint>,
        pub inbound_peers: BTreeSet<PeerId>,
        pub relayed_endpoints: BTreeSet<PeerEndpoint>,
        pub peers_timeout: bool,
    }

    #[derive(Clone, Debug)]
    pub struct ProbeEntry {
        pub block_id: BlockId,
        pub nc_root_id: Option<NcNodeId>,
    }

    #[derive(Clone, Debug, Default)]
    pub struct ProbeResult {
        pub entries: Vec<ProbeEntry>,
    }

    #[derive(Debug)]
    pub struct FailedEndpoint {
        pub endpoint: PeerEndpoint,
        pub advertised_by: Option<PeerId>,
        pub error: CrawlError,
    }

    #[derive(Clone)]
    pub struct PeerCrawler {
        network: NetworkInfo<'static>,
        my_peer: PublicPeer,
        client_config: Arc<ClientConfig>,
        server_config: Arc<ServerConfig>,
        config: CrawlConfig,
    }

    impl PeerCrawler {
        pub fn new(
            network: NetworkInfo<'static>,
            private_peer: peer::PrivatePeer,
            config: CrawlConfig,
        ) -> Result<Self, peer::Error> {
            let client_config = private_peer.gen_client_config()?;
            let server_config = private_peer.gen_server_config()?;
            let my_peer: PublicPeer = private_peer.clone().into();
            Ok(Self {
                network,
                my_peer,
                client_config,
                server_config,
                config,
            })
        }

        pub async fn crawl(
            &self,
            seeds: Vec<PeerEndpoint>,
            listeners: Vec<TcpListener>,
            stats: Option<Arc<Mutex<CrawlStats>>>,
            shutdown: Option<watch::Receiver<bool>>,
        ) -> CrawlReport {
            let mut report = CrawlReport::default();
            let mut queue: VecDeque<(Option<PeerId>, PeerEndpoint)> = VecDeque::new();
            let mut queued_addresses: HashSet<PeerAddress> = HashSet::new();
            let mut visited_peers: HashSet<PeerId> = HashSet::new();
            let mut visited_addresses: HashSet<PeerAddress> = HashSet::new();
            let mut in_flight_addresses: HashSet<PeerAddress> = HashSet::new();
            let mut in_flight_peer_ids: HashSet<PeerId> = HashSet::new();

            for seed in seeds {
                let addr = seed.address().clone();
                if queued_addresses.insert(addr) {
                    queue.push_back((None, seed));
                }
            }

            update_stats(&stats, |s| {
                s.queued = queue.len();
                s.in_flight = 0;
                s.attempted = 0;
                s.visited = 0;
                s.failures = 0;
                s.is_done = false;
            });

            let max_concurrency = self.config.concurrency.max(1);
            let mut in_progress: FuturesUnordered<_> = FuturesUnordered::new();
            let mut active = 0usize;

            let (adv_tx, mut adv_rx) = mpsc::unbounded_channel::<PeerAdvertisement>();

            let server_enabled = !listeners.is_empty();
            let inbound_active = Arc::new(AtomicUsize::new(0));
            let (inbound_tx, mut inbound_rx) = mpsc::unbounded_channel::<InboundEvent>();
            let mut listener_handles = Vec::new();
            let mut shutdown_tx: Option<watch::Sender<bool>> = None;
            let mut shutdown_rx = shutdown;
            let mut shutdown_requested = false;

            if server_enabled {
                let (sender, receiver) = watch::channel(false);
                shutdown_tx = Some(sender.clone());

                for listener in listeners {
                    let mut shutdown_rx = receiver.clone();
                    let inbound_tx = inbound_tx.clone();
                    let acceptor = TlsAcceptor::from(self.server_config.clone());
                    let adv_tx_clone = adv_tx.clone();
                    let crawler = self.clone();
                    let inbound_active = inbound_active.clone();

                    listener_handles.push(tokio::spawn(async move {
                        loop {
                            tokio::select! {
                                res = shutdown_rx.changed() => {
                                    match res {
                                        Ok(_) if *shutdown_rx.borrow() => break,
                                        Err(_) => break,
                                        _ => {}
                                    }
                                }
                                res = listener.accept() => {
                                    match res {
                                        Ok((stream, _addr)) => {
                                            let observed_addr = stream.peer_addr().ok().map(PeerAddress::from_socket_tcp);
                                            inbound_active.fetch_add(1, Ordering::SeqCst);
                                            let acceptor = acceptor.clone();
                                            let adv_tx = adv_tx_clone.clone();
                                            let inbound_tx = inbound_tx.clone();
                                            let crawler = crawler.clone();
                                            let inbound_active = inbound_active.clone();
                                            tokio::spawn(async move {
                                                let result = match acceptor.accept(stream).await {
                                                    Ok(tls_stream) => {
                                                        crawler.run_stream(tls_stream, None, Some(adv_tx)).await
                                                    }
                                                    Err(err) => Err(CrawlError::Connect {
                                                        details: arcstr(err.to_string()),
                                                    }),
                                                };
                                                let _ = inbound_tx.send(InboundEvent::Finished {
                                                    result,
                                                    observed_addr,
                                                });
                                                inbound_active.fetch_sub(1, Ordering::SeqCst);
                                            });
                                        }
                                        Err(err) => {
                                            warn!(?err, "listener accept error");
                                            time::sleep(Duration::from_millis(200)).await;
                                        }
                                    }
                                }
                            }
                        }
                    }));
                }
            }

            drop(inbound_tx);

            let mut grace_sleep: Option<std::pin::Pin<Box<time::Sleep>>> = None;
            let mut grace_elapsed = self.config.listener_grace.is_zero();
            let mut grace_started = false;

            loop {
                while active < max_concurrency && !shutdown_requested {
                    let Some((announcer, endpoint)) = queue.pop_front() else {
                        break;
                    };
                    let addr = endpoint.address().clone();
                    queued_addresses.remove(&addr);

                    if visited_addresses.contains(&addr) || in_flight_addresses.contains(&addr) {
                        update_stats(&stats, |s| s.queued = queue.len());
                        continue;
                    }

                    if let Some(peer_id) = endpoint.peer_id()
                        && (visited_peers.contains(peer_id) || in_flight_peer_ids.contains(peer_id))
                    {
                        update_stats(&stats, |s| s.queued = queue.len());
                        continue;
                    }

                    let running_endpoint = endpoint.clone();
                    let running_addr = addr.clone();
                    let advertiser_tx = Some(adv_tx.clone());
                    let fut = self.crawl_endpoint(running_endpoint.clone(), advertiser_tx);
                    in_progress.push(async move {
                        let outcome = fut.await;
                        (announcer, running_endpoint, running_addr, outcome)
                    });
                    in_flight_addresses.insert(addr.clone());
                    if let Some(peer_id) = endpoint.peer_id() {
                        in_flight_peer_ids.insert(*peer_id);
                    }

                    active += 1;
                    update_stats(&stats, |s| {
                        s.in_flight = active;
                        s.attempted += 1;
                        s.queued = queue.len();
                    });
                }

                let outbound_idle = queue.is_empty() && active == 0 && in_progress.is_empty();
                if outbound_idle {
                    if server_enabled {
                        if !grace_elapsed && !grace_started && !self.config.listener_grace.is_zero()
                        {
                            grace_sleep = Some(Box::pin(time::sleep(self.config.listener_grace)));
                            grace_started = true;
                        }

                        let inbound_pending = inbound_active.load(Ordering::SeqCst) > 0;
                        if (self.config.listener_grace.is_zero() || grace_elapsed)
                            && !inbound_pending
                        {
                            break;
                        }
                    } else {
                        break;
                    }
                }

                tokio::select! {
                    Some(advertisement) = adv_rx.recv() => {
                        process_advertisement(
                            advertisement,
                            &mut queue,
                            &mut queued_addresses,
                            &visited_peers,
                            &visited_addresses,
                            &in_flight_addresses,
                            &in_flight_peer_ids,
                            &mut report,
                            &stats,
                        );
                    }
                    Some((announcer, endpoint, addr, outcome)) = in_progress.next(), if active > 0 => {
                        active = active.saturating_sub(1);
                        in_flight_addresses.remove(&addr);
                        if let Some(peer_id) = endpoint.peer_id() {
                            in_flight_peer_ids.remove(peer_id);
                        }
                        update_stats(&stats, |s| s.in_flight = active);

                        match outcome {
                            Ok(session) => {
                                handle_session(
                                    session,
                                    announcer,
                                    Some(endpoint.clone()),
                                    None,
                                    &mut report,
                                    &mut queue,
                                    &mut queued_addresses,
                                    &mut visited_peers,
                                    &mut visited_addresses,
                                    &mut in_flight_addresses,
                                    &mut in_flight_peer_ids,
                                );
                            }
                            Err(error) => {
                                report.failures.push(FailedEndpoint {
                                    endpoint: endpoint.clone(),
                                    advertised_by: announcer,
                                    error,
                                });
                                visited_addresses.insert(addr.clone());
                            }
                        }

                        update_stats(&stats, |s| {
                            s.queued = queue.len();
                            s.visited = visited_peers.len();
                            s.failures = report.failures.len();
                        });
                    }
                    Some(event) = inbound_rx.recv(), if server_enabled => {
                        match event {
                            InboundEvent::Finished { result, observed_addr } => {
                                match result {
                                    Ok(session) => {
                                        handle_session(
                                            session,
                                            None,
                                            None,
                                            observed_addr,
                                            &mut report,
                                            &mut queue,
                                            &mut queued_addresses,
                                            &mut visited_peers,
                                            &mut visited_addresses,
                                            &mut in_flight_addresses,
                                            &mut in_flight_peer_ids,
                                        );
                                        update_stats(&stats, |s| {
                                            s.queued = queue.len();
                                            s.visited = visited_peers.len();
                                        });
                                    }
                                    Err(err) => {
                                        warn!(?err, "inbound session failed");
                                    }
                                }
                            }
                        }
                    }
                    res = OptionFuture::from(shutdown_rx.as_mut().map(|rx| rx.changed())), if !shutdown_requested && shutdown_rx.is_some() => {
                        match res {
                            Some(Ok(())) => {
                                if let Some(rx) = shutdown_rx.as_ref()
                                    && *rx.borrow() {
                                        shutdown_requested = true;
                                        grace_elapsed = true;
                                        grace_sleep = None;
                                        queue.clear();
                                        queued_addresses.clear();
                                        update_stats(&stats, |s| s.queued = 0);
                                        if let Some(tx) = shutdown_tx.as_ref() {
                                            let _ = tx.send(true);
                                        }
                                        shutdown_rx = None;
                                    }
                            }
                            Some(Err(_)) => {
                                shutdown_requested = true;
                                grace_elapsed = true;
                                grace_sleep = None;
                                queue.clear();
                                queued_addresses.clear();
                                update_stats(&stats, |s| s.queued = 0);
                                if let Some(tx) = shutdown_tx.as_ref() {
                                    let _ = tx.send(true);
                                }
                                shutdown_rx = None;
                            }
                            None => {}
                        }
                    }
                    _ = async {
                        if let Some(sleep) = &mut grace_sleep {
                            sleep.as_mut().await;
                        }
                    }, if server_enabled && grace_sleep.is_some() => {
                        grace_sleep = None;
                        grace_elapsed = true;
                    }
                    else => {
                        break;
                    }
                }
            }

            if let Some(tx) = shutdown_tx {
                let _ = tx.send(true);
            }
            for handle in listener_handles {
                if let Err(err) = handle.await {
                    warn!(?err, "listener task terminated unexpectedly");
                }
            }

            update_stats(&stats, |s| {
                s.queued = 0;
                s.in_flight = 0;
                s.visited = visited_peers.len();
                s.failures = report.failures.len();
                s.is_done = true;
            });

            report
        }

        async fn crawl_endpoint(
            &self,
            endpoint: PeerEndpoint,
            advertisement_tx: Option<mpsc::UnboundedSender<PeerAdvertisement>>,
        ) -> Result<SessionReport, CrawlError> {
            let addresses = self.resolve_addresses(&endpoint).await?;
            let expected_peer_id = endpoint.peer_id().copied();
            let mut last_err: Option<CrawlError> = None;

            for addr in addresses {
                match self
                    .run_session(addr, expected_peer_id, advertisement_tx.clone())
                    .await
                {
                    Ok(session) => {
                        return Ok(session);
                    }
                    Err(err) => {
                        last_err = Some(err);
                    }
                }
            }

            Err(last_err.unwrap_or(CrawlError::Connect {
                details: arcstr("all connection attempts failed"),
            }))
        }

        async fn resolve_addresses(
            &self,
            endpoint: &PeerEndpoint,
        ) -> Result<Vec<SocketAddr>, CrawlError> {
            let address = endpoint.address().clone();
            if let Some(sock) = address.to_socket_addr() {
                return Ok(vec![sock]);
            }

            let authority = address.authority();
            let lookup = lookup_host(authority.clone());
            let resolved = match time::timeout(self.config.dns_timeout, lookup).await {
                Ok(Ok(iter)) => iter.collect::<Vec<_>>(),
                Ok(Err(err)) => {
                    return Err(CrawlError::Resolve {
                        details: arcstr(format!("{}: {}", authority, err)),
                    });
                }
                Err(_) => {
                    return Err(CrawlError::Resolve {
                        details: arcstr(format!("{}: timeout", authority)),
                    });
                }
            };

            if resolved.is_empty() {
                Err(CrawlError::NoAddresses)
            } else {
                Ok(resolved)
            }
        }

        async fn run_session(
            &self,
            addr: SocketAddr,
            expected_peer_id: Option<PeerId>,
            advertisement_tx: Option<mpsc::UnboundedSender<PeerAdvertisement>>,
        ) -> Result<SessionReport, CrawlError> {
            let tcp =
                match time::timeout(self.config.connect_timeout, TcpStream::connect(addr)).await {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(err)) => {
                        return Err(CrawlError::Connect {
                            details: arcstr(err.to_string()),
                        });
                    }
                    Err(_) => {
                        return Err(CrawlError::Connect {
                            details: arcstr(format!("connect timeout to {}", addr)),
                        });
                    }
                };

            let connector = TlsConnector::from(self.client_config.clone());
            let server_name = ServerName::IpAddress(addr.ip().into());
            let tls_stream =
                connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(|err| CrawlError::Connect {
                        details: arcstr(err.to_string()),
                    })?;

            self.run_stream(tls_stream, expected_peer_id, advertisement_tx)
                .await
        }

        async fn run_stream<S>(
            &self,
            stream: S,
            expected_peer_id: Option<PeerId>,
            advertisement_tx: Option<mpsc::UnboundedSender<PeerAdvertisement>>,
        ) -> Result<SessionReport, CrawlError>
        where
            S: std::fmt::Debug
                + tokio::io::AsyncWrite
                + tokio::io::AsyncRead
                + std::marker::Unpin
                + crate::protocol::TlsStreamExt,
        {
            let (event_tx, mut event_rx) = mpsc::unbounded_channel();
            let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
            let handle = ProtocolHandle::with_channels(event_tx, cmd_rx);

            let driver = IoDriver::new(self.network.clone(), self.my_peer.clone());
            let mut run_fut = Box::pin(engine::run_with_handle(driver, stream, handle));

            let ready_sleep = time::sleep(self.config.ready_timeout);
            let peers_sleep = time::sleep(Duration::from_secs(0));
            tokio::pin!(ready_sleep);
            tokio::pin!(peers_sleep);

            let mut peers_sleep_active = false;
            let mut ready_timed_out = false;
            let mut peers_timeout = false;
            let mut remote_error: Option<Arc<str>> = None;
            let mut hello: Option<HelloData> = None;
            let mut remote_peer: Option<PublicPeer> = None;
            let mut advertised: BTreeMap<PeerId, UnverifiedPeer> = BTreeMap::new();
            let mut peer_id_mismatch: Option<(PeerId, PeerId)> = None;
            let mut get_peers_sent = false;
            #[derive(Copy, Clone, Debug, PartialEq, Eq)]
            enum ProbeState {
                Disabled,
                Pending,
                WaitingForScan,
                WaitingBestBlockchain,
                WaitingBlockNcRoot,
                Done,
                Failed,
                Skipped,
            }
            let probe_cfg = self.config.probe.clone();
            let mut probe_state = if probe_cfg.is_some() {
                ProbeState::Pending
            } else {
                ProbeState::Disabled
            };
            let mut probe_entries: Vec<ProbeEntry> = Vec::new();
            let mut probe_expected_index: usize = 0;
            let mut probe_expected_block: Option<BlockId> = None;
            let mut probe_attempted = false;
            let mut scan_done = false;
            let probe_sleep = time::sleep(Duration::from_secs(0));
            tokio::pin!(probe_sleep);
            let mut probe_sleep_active = false;

            let run_result = loop {
                tokio::select! {
                    res = &mut run_fut => {
                        break res;
                    }
                    Some(event) = event_rx.recv() => {
                        match event {
                            ProtocolEvent::HelloReceived(data) => {
                                hello = Some(data);
                            }
                            ProtocolEvent::PeerIdentified(peer) => {
                                if let Some(expected) = expected_peer_id
                                    && peer.peer_id != expected && peer_id_mismatch.is_none() {
                                        peer_id_mismatch = Some((expected, peer.peer_id));
                                        let _ = cmd_tx.send(ProtocolCommand::Close);
                                    }
                                remote_peer = Some(peer);
                            }
                            ProtocolEvent::ReadyEntered { remote } => {
                                if let Some(expected) = expected_peer_id
                                    && remote.peer_id != expected && peer_id_mismatch.is_none() {
                                        peer_id_mismatch = Some((expected, remote.peer_id));
                                        let _ = cmd_tx.send(ProtocolCommand::Close);
                                    }

                                remote_peer = Some(remote.clone());
                                ready_sleep.as_mut().reset(
                                    Instant::now() + Duration::from_secs(365 * 24 * 60 * 60),
                                );

                                if !get_peers_sent
                                    && cmd_tx
                                        .send(ProtocolCommand::SendReady(ReadyMessage::GetPeers))
                                        .is_ok()
                                    {
                                        peers_sleep.as_mut().reset(
                                            Instant::now() + self.config.peers_timeout,
                                        );
                                        peers_sleep_active = true;
                                        get_peers_sent = true;
                                    }

                                if let ProbeState::Pending = probe_state {
                                    let caps = hello.as_ref().map(|h| &h.capabilities);
                                    let has_nano = caps.is_some_and(|list| {
                                        list.iter()
                                            .any(|cap| matches!(cap, Capability::NanoState))
                                    });
                                    let has_best = caps.is_some_and(|list| {
                                        list.iter().any(|cap| {
                                            matches!(cap, Capability::GetBestBlockchain)
                                        })
                                    });
                                    if !has_nano {
                                        warn!(
                                            peer = %remote.peer_id,
                                            "peer missing nano-state capability; skipping probe"
                                        );
                                        probe_state = ProbeState::Skipped;
                                    } else if !has_best {
                                        warn!(
                                            peer = %remote.peer_id,
                                            "peer missing get-best-blockchain capability; skipping probe"
                                        );
                                        probe_state = ProbeState::Skipped;
                                    } else {
                                        probe_state = ProbeState::WaitingForScan;
                                    }
                                }
                            }
                            ProtocolEvent::ReadyMessage { message, .. } => {
                                match message {
                                    ReadyMessage::Peers(list) => {
                                        if let (Some(tx), Some(remote)) =
                                            (&advertisement_tx, &remote_peer)
                                        {
                                            let advertised_list: Vec<UnverifiedPeer> =
                                                list.iter().cloned().collect();
                                            if !advertised_list.is_empty() {
                                                let _ = tx.send(PeerAdvertisement {
                                                    advertiser: remote.peer_id,
                                                    advertised: advertised_list,
                                                });
                                            }
                                        }
                                        for peer in list {
                                            advertised
                                                .entry(peer.peer_id)
                                                .and_modify(|existing| {
                                                    merge_unverified_peer(existing, &peer)
                                                })
                                                .or_insert(peer);
                                        }
                                        if !scan_done {
                                            peers_sleep.as_mut().reset(
                                                Instant::now() + self.config.peers_timeout,
                                            );
                                            peers_sleep_active = true;
                                        }
                                    }
                                    ReadyMessage::BestBlockchain(list)
                                        if probe_state == ProbeState::WaitingBestBlockchain =>
                                    {
                                        probe_sleep_active = false;
                                        probe_entries = list
                                            .iter()
                                            .map(|info| ProbeEntry {
                                                block_id: info.block_id(),
                                                nc_root_id: None,
                                            })
                                            .collect();
                                        if probe_entries.is_empty() {
                                            probe_state = ProbeState::Done;
                                            if scan_done {
                                                let _ = cmd_tx.send(ProtocolCommand::Close);
                                            }
                                        } else {
                                            probe_expected_index = 0;
                                            let block_id = probe_entries[0].block_id;
                                            probe_expected_block = Some(block_id);
                                            let send_result = cmd_tx.send(
                                                ProtocolCommand::SendReady(
                                                    ReadyMessage::GetBlockNcRootId(block_id),
                                                ),
                                            );
                                            if send_result.is_ok() {
                                                if let Some(cfg) = &probe_cfg {
                                                    probe_sleep.as_mut().reset(
                                                        Instant::now()
                                                            + cfg.block_nc_root_timeout,
                                                    );
                                                    probe_sleep_active = true;
                                                }
                                                probe_state = ProbeState::WaitingBlockNcRoot;
                                            } else {
                                                if let Some(remote) = &remote_peer {
                                                    warn!(
                                                        peer = %remote.peer_id,
                                                        "failed to send get-block-nc-root-id; stopping probe"
                                                    );
                                                } else {
                                                    warn!(
                                                        "failed to send get-block-nc-root-id; stopping probe"
                                                    );
                                                }
                                                probe_state = ProbeState::Failed;
                                                if scan_done {
                                                    let _ = cmd_tx.send(ProtocolCommand::Close);
                                                }
                                            }
                                        }
                                    }
                                    ReadyMessage::BlockNcRootId(block_id, node_id)
                                        if probe_state == ProbeState::WaitingBlockNcRoot =>
                                    {
                                        match probe_expected_block {
                                                Some(expected) if expected == block_id => {
                                                    if let Some(entry) =
                                                        probe_entries.get_mut(probe_expected_index)
                                                    {
                                                        entry.nc_root_id = Some(node_id);
                                                    } else {
                                                        if let Some(remote) = &remote_peer {
                                                            warn!(
                                                                peer = %remote.peer_id,
                                                                "probe state out of range; stopping probe"
                                                            );
                                                        } else {
                                                            warn!(
                                                                "probe state out of range; stopping probe"
                                                            );
                                                        }
                                                        probe_state = ProbeState::Failed;
                                                        probe_sleep_active = false;
                                                        if scan_done {
                                                            let _ = cmd_tx
                                                                .send(ProtocolCommand::Close);
                                                        }
                                                    }

                                                    if probe_state != ProbeState::Failed {
                                                        probe_expected_index += 1;
                                                        if probe_expected_index >= probe_entries.len() {
                                                            probe_state = ProbeState::Done;
                                                            probe_sleep_active = false;
                                                            if scan_done {
                                                                let _ = cmd_tx
                                                                    .send(ProtocolCommand::Close);
                                                            }
                                                        } else {
                                                            let next_block =
                                                                probe_entries[probe_expected_index]
                                                                    .block_id;
                                                            probe_expected_block = Some(next_block);
                                                            let send_result = cmd_tx.send(
                                                                ProtocolCommand::SendReady(
                                                                    ReadyMessage::GetBlockNcRootId(
                                                                        next_block,
                                                                    ),
                                                                ),
                                                            );
                                                            if send_result.is_ok() {
                                                                if let Some(cfg) = &probe_cfg {
                                                                    probe_sleep.as_mut().reset(
                                                                        Instant::now()
                                                                            + cfg
                                                                                .block_nc_root_timeout,
                                                                    );
                                                                    probe_sleep_active = true;
                                                                }
                                                            } else {
                                                                if let Some(remote) = &remote_peer {
                                                                    warn!(
                                                                        peer = %remote.peer_id,
                                                                        "failed to send get-block-nc-root-id; stopping probe"
                                                                    );
                                                                } else {
                                                                    warn!(
                                                                        "failed to send get-block-nc-root-id; stopping probe"
                                                                    );
                                                                }
                                                                probe_state = ProbeState::Failed;
                                                                probe_sleep_active = false;
                                                                if scan_done {
                                                                    let _ = cmd_tx.send(
                                                                        ProtocolCommand::Close,
                                                                    );
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                                _ => {
                                                    if let Some(remote) = &remote_peer {
                                                        warn!(
                                                            peer = %remote.peer_id,
                                                            expected = ?probe_expected_block,
                                                            got = %block_id,
                                                            "unexpected block-nc-root-id; stopping probe"
                                                        );
                                                    } else {
                                                        warn!(
                                                            expected = ?probe_expected_block,
                                                            got = %block_id,
                                                            "unexpected block-nc-root-id; stopping probe"
                                                        );
                                                    }
                                                    probe_state = ProbeState::Failed;
                                                    probe_sleep_active = false;
                                                    if scan_done {
                                                        let _ =
                                                            cmd_tx.send(ProtocolCommand::Close);
                                                    }
                                                }
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            ProtocolEvent::Control { message, .. } => {
                                if let ControlMessage::Error(reason) = message {
                                    if matches!(
                                        probe_state,
                                        ProbeState::WaitingBestBlockchain
                                            | ProbeState::WaitingBlockNcRoot
                                    ) {
                                        if let Some(remote) = &remote_peer {
                                            warn!(
                                                peer = %remote.peer_id,
                                                error = %reason,
                                                "probe failed with remote error"
                                            );
                                        } else {
                                            warn!(
                                                error = %reason,
                                                "probe failed with remote error"
                                            );
                                        }
                                        probe_state = ProbeState::Failed;
                                        probe_sleep_active = false;
                                        let _ = cmd_tx.send(ProtocolCommand::Close);
                                    } else {
                                        remote_error = Some(arcstr(reason));
                                    }
                                }
                            }
                            ProtocolEvent::Disconnected { .. } => {}
                            ProtocolEvent::SyncMessage { .. } => {}
                        }
                    }
                    _ = &mut ready_sleep => {
                        ready_timed_out = true;
                        let _ = cmd_tx.send(ProtocolCommand::Close);
                    }
                    _ = &mut probe_sleep, if probe_sleep_active => {
                        probe_sleep_active = false;
                        match probe_state {
                            ProbeState::WaitingBestBlockchain => {
                                if let Some(remote) = &remote_peer {
                                    warn!(
                                        peer = %remote.peer_id,
                                        "timed out waiting for best-blockchain"
                                    );
                                } else {
                                    warn!("timed out waiting for best-blockchain");
                                }
                            }
                            ProbeState::WaitingBlockNcRoot => {
                                if let Some(remote) = &remote_peer {
                                    warn!(
                                        peer = %remote.peer_id,
                                        expected = ?probe_expected_block,
                                        "timed out waiting for block-nc-root-id"
                                    );
                                } else {
                                    warn!(
                                        expected = ?probe_expected_block,
                                        "timed out waiting for block-nc-root-id"
                                    );
                                }
                            }
                            _ => {}
                        }
                        if matches!(
                            probe_state,
                            ProbeState::WaitingBestBlockchain | ProbeState::WaitingBlockNcRoot
                        ) {
                            probe_state = ProbeState::Failed;
                            let _ = cmd_tx.send(ProtocolCommand::Close);
                        }
                    }
                    _ = &mut peers_sleep, if peers_sleep_active => {
                        peers_timeout = true;
                        peers_sleep_active = false;
                        scan_done = true;
                        if probe_state == ProbeState::WaitingForScan {
                            if let Some(cfg) = &probe_cfg {
                                probe_attempted = true;
                                probe_entries.clear();
                                probe_expected_index = 0;
                                probe_expected_block = None;
                                if cmd_tx
                                    .send(ProtocolCommand::SendReady(
                                        ReadyMessage::GetBestBlockchain(Some(
                                            cfg.best_blockchain_len,
                                        )),
                                    ))
                                    .is_ok()
                                {
                                    probe_sleep.as_mut().reset(
                                        Instant::now() + cfg.best_blockchain_timeout,
                                    );
                                    probe_sleep_active = true;
                                    probe_state = ProbeState::WaitingBestBlockchain;
                                } else {
                                    if let Some(remote) = &remote_peer {
                                        warn!(
                                            peer = %remote.peer_id,
                                            "failed to send get-best-blockchain; skipping probe"
                                        );
                                    } else {
                                        warn!(
                                            "failed to send get-best-blockchain; skipping probe"
                                        );
                                    }
                                    probe_state = ProbeState::Failed;
                                    let _ = cmd_tx.send(ProtocolCommand::Close);
                                }
                            }
                        } else if matches!(
                            probe_state,
                            ProbeState::Disabled
                                | ProbeState::Pending
                                | ProbeState::Skipped
                                | ProbeState::Done
                                | ProbeState::Failed
                        ) {
                            let _ = cmd_tx.send(ProtocolCommand::Close);
                        }
                    }
                }
            };

            match run_result {
                Ok(()) => {}
                Err(err) => {
                    return Err(CrawlError::Protocol {
                        details: arcstr(err.to_string()),
                    });
                }
            }

            if let Some((expected, got)) = peer_id_mismatch {
                return Err(CrawlError::PeerIdMismatch { expected, got });
            }

            if ready_timed_out {
                return Err(CrawlError::ReadyTimeout);
            }

            if let Some(reason) = remote_error {
                return Err(CrawlError::RemoteError { details: reason });
            }

            if matches!(
                probe_state,
                ProbeState::WaitingBestBlockchain | ProbeState::WaitingBlockNcRoot
            ) {
                if let Some(remote) = &remote_peer {
                    warn!(
                        peer = %remote.peer_id,
                        "probe interrupted before completion"
                    );
                } else {
                    warn!("probe interrupted before completion");
                }
            }

            let remote_peer = remote_peer.ok_or(CrawlError::ConnectionClosed)?;
            let probe_result = if probe_attempted {
                Some(ProbeResult {
                    entries: probe_entries,
                })
            } else {
                None
            };

            Ok(SessionReport {
                hello,
                remote_peer,
                advertised: advertised.into_values().collect(),
                peers_timeout,
                probe_result,
            })
        }
    }

    #[derive(Debug)]
    struct SessionReport {
        hello: Option<HelloData>,
        remote_peer: PublicPeer,
        advertised: Vec<UnverifiedPeer>,
        peers_timeout: bool,
        probe_result: Option<ProbeResult>,
    }

    #[derive(Clone, Debug)]
    struct PeerAdvertisement {
        advertiser: PeerId,
        advertised: Vec<UnverifiedPeer>,
    }

    #[derive(Debug)]
    enum InboundEvent {
        Finished {
            result: Result<SessionReport, CrawlError>,
            observed_addr: Option<PeerAddress>,
        },
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_session(
        session: SessionReport,
        announcer: Option<PeerId>,
        observed_endpoint: Option<PeerEndpoint>,
        inbound_addr: Option<PeerAddress>,
        report: &mut CrawlReport,
        queue: &mut VecDeque<(Option<PeerId>, PeerEndpoint)>,
        queued_addresses: &mut HashSet<PeerAddress>,
        visited_peers: &mut HashSet<PeerId>,
        visited_addresses: &mut HashSet<PeerAddress>,
        in_flight_addresses: &mut HashSet<PeerAddress>,
        in_flight_peer_ids: &mut HashSet<PeerId>,
    ) {
        let mut session = session;
        let peer_id = session.remote_peer.peer_id;
        visited_peers.insert(peer_id);

        if let Some(endpoint) = observed_endpoint.as_ref() {
            visited_addresses.insert(endpoint.address().clone());
        }

        if let Some(addr) = &inbound_addr {
            visited_addresses.insert(addr.clone());
        }

        {
            let node = report.peers.entry(peer_id).or_default();

            node.public_peer
                .get_or_insert_with(|| session.remote_peer.clone());
            if let Some(ref mut stored) = node.public_peer {
                merge_public_peer(stored, &session.remote_peer);
            }

            if let Some(hello) = session.hello.take() {
                node.hello = Some(hello);
            }

            if let Some(endpoint) = observed_endpoint {
                node.observed_endpoints.insert(endpoint);
            }

            if inbound_addr.is_some() {
                node.inbound_peers.insert(peer_id);
            }

            node.peers_timeout |= session.peers_timeout;

            if let Some(probe) = session.probe_result.take() {
                match report.probe_results.get_mut(&peer_id) {
                    Some(existing) => {
                        if existing.entries.len() < probe.entries.len() {
                            *existing = probe;
                        }
                    }
                    None => {
                        report.probe_results.insert(peer_id, probe);
                    }
                }
            }

            if let Some(ann) = announcer {
                node.advertised_by.insert(ann);
            }

            for advertised_peer in &session.advertised {
                node.advertises.insert(advertised_peer.peer_id);
            }
        }

        if let Some(ann) = announcer {
            let ann_node = report.peers.entry(ann).or_default();
            ann_node.advertises.insert(peer_id);
        }

        for ep in &session.remote_peer.endpoints {
            visited_addresses.insert(ep.address().clone());
        }

        for advertised_peer in &session.advertised {
            let adv_id = advertised_peer.peer_id;
            let adv_node = report.peers.entry(adv_id).or_default();
            adv_node.advertised_by.insert(peer_id);

            for ep in &advertised_peer.endpoints {
                let normalized = endpoint_with_id(ep, adv_id);
                let addr = normalized.address().clone();
                adv_node.relayed_endpoints.insert(normalized.clone());

                if visited_peers.contains(&adv_id)
                    || visited_addresses.contains(&addr)
                    || in_flight_addresses.contains(&addr)
                    || in_flight_peer_ids.contains(&adv_id)
                {
                    continue;
                }

                if queued_addresses.insert(addr.clone()) {
                    queue.push_back((Some(peer_id), normalized));
                }
            }
        }
    }

    fn arcstr<S: Into<String>>(s: S) -> Arc<str> {
        Arc::<str>::from(s.into().into_boxed_str())
    }

    fn endpoint_with_id(endpoint: &PeerEndpoint, peer_id: PeerId) -> PeerEndpoint {
        match endpoint.peer_id() {
            Some(existing) if *existing == peer_id => endpoint.clone(),
            _ => endpoint.address().clone().with_id(peer_id),
        }
    }

    fn merge_public_peer(base: &mut PublicPeer, update: &PublicPeer) {
        if base.pub_key != update.pub_key {
            warn!(
                peer = %base.peer_id,
                "conflicting pub_key observed for peer"
            );
        }
        for ep in &update.endpoints {
            if !base.endpoints.contains(ep) {
                base.endpoints.push(ep.clone());
            }
        }
    }

    fn merge_unverified_peer(base: &mut UnverifiedPeer, update: &UnverifiedPeer) {
        for ep in &update.endpoints {
            if !base.endpoints.contains(ep) {
                base.endpoints.push(ep.clone());
            }
        }
    }

    fn update_stats(stats: &Option<Arc<Mutex<CrawlStats>>>, f: impl FnOnce(&mut CrawlStats)) {
        if let Some(stats) = stats
            && let Ok(mut guard) = stats.lock()
        {
            f(&mut guard);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn process_advertisement(
        advertisement: PeerAdvertisement,
        queue: &mut VecDeque<(Option<PeerId>, PeerEndpoint)>,
        queued_addresses: &mut HashSet<PeerAddress>,
        visited_peers: &HashSet<PeerId>,
        visited_addresses: &HashSet<PeerAddress>,
        in_flight_addresses: &HashSet<PeerAddress>,
        in_flight_peer_ids: &HashSet<PeerId>,
        report: &mut CrawlReport,
        stats: &Option<Arc<Mutex<CrawlStats>>>,
    ) {
        let advertiser = advertisement.advertiser;

        for unverified in advertisement.advertised {
            {
                let advertiser_node = report.peers.entry(advertiser).or_default();
                advertiser_node.advertises.insert(unverified.peer_id);
            }
            let remote_node = report.peers.entry(unverified.peer_id).or_default();
            remote_node.advertised_by.insert(advertiser);

            for ep in unverified.endpoints {
                let normalized = endpoint_with_id(&ep, unverified.peer_id);
                let addr = normalized.address().clone();
                remote_node.relayed_endpoints.insert(normalized.clone());

                if visited_peers.contains(&unverified.peer_id)
                    || visited_addresses.contains(&addr)
                    || in_flight_addresses.contains(&addr)
                    || in_flight_peer_ids.contains(&unverified.peer_id)
                {
                    continue;
                }

                if queued_addresses.insert(addr.clone()) {
                    queue.push_back((Some(advertiser), normalized));
                }
            }
        }

        update_stats(stats, |s| s.queued = queue.len());
    }
}

#[cfg(test)]
mod tests {
    use crate::peer::PeerEndpoint as PE;

    #[test]
    fn parse_endpoint_from_str() {
        // sanity check the expected PeerEndpoint format used by TXT entries
        let s = "tcp://example.com:9000/?id=c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696";
        let _ep: PE = s.parse().expect("should parse PeerEndpoint string");
    }
}
