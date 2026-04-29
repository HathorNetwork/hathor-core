// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use crate::network_info;
use crate::{peer, protocol, utils};
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use std::net::SocketAddr;
use std::sync::Arc;
use thiserror::Error;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector, client};
use tracing::*;

#[cfg(feature = "transport-quic")]
mod quic;

#[derive(Error, Debug)]
pub enum Error {
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("error installing color-eyre")]
    ColorEyre(#[from] color_eyre::Report),
    #[error("peer error")]
    Peer(#[from] crate::peer::Error),
    #[error("peer address must resolve to an IP socket: {0}")]
    AddressRequiresSocket(String),
    #[cfg(feature = "transport-quic")]
    #[error("QUIC config error")]
    QuicConfig(#[from] quinn::ConfigError),
    #[cfg(feature = "transport-quic")]
    #[error("QUIC connection failed")]
    QuicConnect(#[from] quinn::ConnectError),
    #[cfg(feature = "transport-quic")]
    #[error("QUIC connection error")]
    QuicConnection(#[from] quinn::ConnectionError),
    #[cfg(feature = "transport-quic")]
    #[error("QUIC peer did not present a valid identity")]
    QuicPeerIdentity,
    #[cfg(feature = "transport-quic")]
    #[error("QUIC TLS configuration error")]
    QuicTlsConfig(#[from] quinn::crypto::rustls::NoInitialCipherSuite),
}

/// Establish a TLS connection.
async fn connect_tls(
    client_config: Arc<ClientConfig>,
    sock_addr: SocketAddr,
) -> Result<client::TlsStream<TcpStream>, std::io::Error> {
    let connector = TlsConnector::from(client_config);
    let tcp_stream = TcpStream::connect(sock_addr).await?;
    let domain = ServerName::IpAddress(sock_addr.ip().into());
    connector.connect(domain, tcp_stream).await
}

async fn run_tcp_listener(
    listen_socket: SocketAddr,
    peer: peer::PrivatePeer,
    network_info: network_info::NetworkInfo<'static>,
    timeout: Option<std::time::Duration>,
) -> Result<(), Error> {
    let server_config = peer.gen_server_config()?;
    let listener = TcpListener::bind(listen_socket).await?;
    let local_addr = listener.local_addr()?;
    info!("TCP server listening on {}", local_addr);
    let acceptor = TlsAcceptor::from(server_config);

    let accept_loop = |stream: TcpStream, client_addr: SocketAddr| {
        info!("Client connected: {}", client_addr);
        let acceptor = acceptor.clone();
        let peer = peer.clone();
        let network_info = network_info.clone();
        tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let driver = protocol::drivers::IoDriver::new(network_info, peer.into());
                    if let Err(e) = driver.handle(tls_stream).await {
                        warn!(?e, "connection error");
                    }
                }
                Err(e) => error!("TLS handshake failed: {}", e),
            }
        });
    };

    if let Some(d) = timeout {
        let deadline = tokio::time::Instant::now() + d;
        let sleep = tokio::time::sleep_until(deadline);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                biased;
                _ = &mut sleep => {
                    info!("TCP timeout reached; stopping accept loop");
                    break;
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, client_addr)) => accept_loop(stream, client_addr),
                        Err(e) => error!("Failed to accept connection: {}", e),
                    }
                }
            }
        }
    } else {
        loop {
            match listener.accept().await {
                Ok((stream, client_addr)) => accept_loop(stream, client_addr),
                Err(e) => error!("Failed to accept connection: {}", e),
            }
        }
    }

    Ok(())
}

fn require_socket(address: &peer::PeerAddress) -> Result<SocketAddr, Error> {
    address
        .to_socket_addr()
        .ok_or_else(|| Error::AddressRequiresSocket(address.to_string()))
}

#[instrument]
pub async fn start(
    peer: peer::PrivatePeer,
    connect_to: Vec<peer::PeerAddress>,
    listen_tcp: Vec<SocketAddr>,
    listen_quic: Vec<SocketAddr>,
    network_info: network_info::NetworkInfo<'static>,
    timeout: Option<std::time::Duration>,
) -> Result<(), Error> {
    trace!(peer = %peer.peer_id, "starting with peer");

    for connect_address in connect_to {
        let socket = require_socket(&connect_address)?;
        match connect_address.protocol() {
            peer::Protocol::Tcp => {
                let peer = peer.clone();
                let network_info = network_info.clone();
                let client_config = peer.gen_client_config()?;
                let public_self: peer::PublicPeer = peer.into();
                tokio::spawn(async move {
                    trace!(addr = %connect_address, "connect tcp");
                    match connect_tls(client_config, socket).await {
                        Ok(stream) => {
                            trace!("start protocol on {:?}", socket);
                            let driver =
                                protocol::drivers::IoDriver::new(network_info, public_self);
                            if let Err(e) = driver.handle(stream).await {
                                warn!(?e, "connection error");
                            }
                        }
                        Err(e) => warn!(error = %e, addr = %connect_address, "tcp dial failed"),
                    }
                });
            }
            #[cfg(feature = "transport-quic")]
            peer::Protocol::Quic => {
                let peer = peer.clone();
                let network_info = network_info.clone();
                let public_self: peer::PublicPeer = peer.clone().into();
                tokio::spawn(async move {
                    trace!(addr = %connect_address, "connect quic");
                    match quic::connect(&peer, socket).await {
                        Ok(stream) => {
                            let driver =
                                protocol::drivers::IoDriver::new(network_info, public_self);
                            if let Err(e) = driver.handle(stream).await {
                                warn!(?e, "connection error");
                            }
                        }
                        Err(e) => warn!(error = %e, addr = %connect_address, "quic dial failed"),
                    }
                });
            }
        }
    }

    let mut listener_handles = Vec::new();
    for socket in listen_tcp {
        let peer = peer.clone();
        let network_info = network_info.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = run_tcp_listener(socket, peer, network_info, timeout).await {
                error!(?e, "tcp listener exited with error");
            }
        });
        listener_handles.push(handle);
    }
    #[cfg(feature = "transport-quic")]
    for socket in listen_quic {
        let peer = peer.clone();
        let network_info = network_info.clone();
        let handle = tokio::spawn(async move {
            if let Err(e) = quic::run_listener(peer, socket, network_info, timeout).await {
                error!(?e, "quic listener exited with error");
            }
        });
        listener_handles.push(handle);
    }

    if listener_handles.is_empty() {
        debug!("finished");
        Ok(())
    } else {
        for handle in listener_handles {
            let _ = handle.await;
        }
        Ok(())
    }
}

pub fn run_server_main(
    peer: peer::PrivatePeer,
    connect_to: Vec<peer::PeerAddress>,
    listen_tcp: Vec<SocketAddr>,
    listen_quic: Vec<SocketAddr>,
    network_info: network_info::NetworkInfo<'static>,
    timeout: Option<std::time::Duration>,
) -> Result<(), Error> {
    let runtime = utils::build_tokio_runtime()?;

    #[cfg(unix)]
    if let Some(handle) = crate::logging::current_log_handle() {
        runtime.spawn(async move {
            crate::logging::watch_for_log_reopen_signals(handle).await;
        });
    }

    runtime.block_on(start(
        peer,
        connect_to,
        listen_tcp,
        listen_quic,
        network_info,
        timeout,
    ))
}
