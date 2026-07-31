// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "transport-quic")]

use super::Error;
use crate::network_info::NetworkInfo;
use crate::peer::{PeerId, PrivatePeer, PublicPeer};
use crate::protocol::drivers::IoDriver;
use crate::protocol::{TlsStreamExt, peer_id_from_rustls_chain};
use pin_project::pin_project;
use quinn::{
    ClientConfig as QuicClientConfig, Connection, Endpoint, EndpointConfig, Incoming, RecvStream,
    SendStream, ServerConfig as QuicServerConfig, TransportConfig,
};
use rustls::{ClientConfig, ServerConfig};
use rustls_pki_types::CertificateDer;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{info, trace, warn};

#[pin_project]
pub(super) struct QuicStream {
    connection: Connection,
    #[pin]
    recv: RecvStream,
    #[pin]
    send: SendStream,
    peer_id: PeerId,
}

impl QuicStream {
    fn new(connection: Connection, recv: RecvStream, send: SendStream, peer_id: PeerId) -> Self {
        Self {
            connection,
            recv,
            send,
            peer_id,
        }
    }
}

impl fmt::Debug for QuicStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuicStream")
            .field("remote", &self.connection.remote_address())
            .field("stable_id", &self.connection.stable_id())
            .finish()
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.project();
        match this.recv.as_mut().poll_read(cx, buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut this = self.project();
        match this.send.as_mut().poll_write(cx, buf) {
            Poll::Ready(Ok(len)) => Poll::Ready(Ok(len)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut this = self.project();
        match this.send.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(e))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let mut this = self.project();
        this.send.finish().map_err(std::io::Error::other)?;
        Poll::Ready(Ok(()))
    }
}

impl TlsStreamExt for QuicStream {
    fn gen_peer_id_from_conn_cert(&self) -> Option<PeerId> {
        Some(self.peer_id)
    }
}

pub(super) async fn connect(peer: &PrivatePeer, addr: SocketAddr) -> Result<QuicStream, Error> {
    let client_config = peer.gen_client_config()?;
    let mut endpoint = build_client_endpoint().map_err(Error::from)?;
    let mut quic_config = quic_client_config(client_config)?;
    quic_config.transport_config(Arc::new(default_transport_config()));
    endpoint.set_default_client_config(quic_config);

    let server_name = server_name_for_addr(addr);
    let connecting = endpoint.connect(addr, &server_name)?;
    let connection = connecting.await?;
    trace!(remote = ?connection.remote_address(), "QUIC dial established");
    let peer_id = peer_id_from_connection(&connection)?;
    let (send, recv) = connection.open_bi().await?;
    Ok(QuicStream::new(connection, recv, send, peer_id))
}

pub(super) async fn run_listener(
    peer: PrivatePeer,
    listen_socket: SocketAddr,
    network_info: NetworkInfo<'static>,
    timeout: Option<std::time::Duration>,
) -> Result<(), Error> {
    let server_config = peer.gen_server_config()?;
    let endpoint = build_server_endpoint(listen_socket, server_config)?;
    info!(
        "QUIC server listening on {}",
        endpoint.local_addr().unwrap_or(listen_socket)
    );

    if let Some(d) = timeout {
        let deadline = tokio::time::Instant::now() + d;
        let sleep = tokio::time::sleep_until(deadline);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => {
                    info!("QUIC timeout reached; stopping accept loop");
                    break;
                }
                incoming = endpoint.accept() => {
                    if let Some(incoming) = incoming {
                        spawn_connection(incoming, peer.clone(), network_info.clone());
                    } else {
                        break;
                    }
                }
            }
        }
    } else {
        while let Some(incoming) = endpoint.accept().await {
            spawn_connection(incoming, peer.clone(), network_info.clone());
        }
    }

    endpoint.wait_idle().await;
    Ok(())
}

fn spawn_connection(incoming: Incoming, peer: PrivatePeer, network_info: NetworkInfo<'static>) {
    tokio::spawn(async move {
        match incoming.accept() {
            Ok(connecting) => match connecting.await {
                Ok(connection) => {
                    trace!(remote = ?connection.remote_address(), "QUIC inbound connection");
                    if let Err(e) = handle_incoming_connection(connection, peer, network_info).await
                    {
                        warn!(?e, "failed to service QUIC stream");
                    }
                }
                Err(e) => warn!(?e, "incoming QUIC handshake failed"),
            },
            Err(e) => {
                warn!(?e, "failed to accept incoming QUIC connection");
            }
        }
    });
}

async fn handle_incoming_connection(
    connection: Connection,
    peer: PrivatePeer,
    network_info: NetworkInfo<'static>,
) -> Result<(), Error> {
    let peer_id = peer_id_from_connection(&connection)?;
    let (send, recv) = connection.accept_bi().await?;
    let stream = QuicStream::new(connection, recv, send, peer_id);
    let public_peer: PublicPeer = peer.into();
    let driver = IoDriver::new(network_info, public_peer);
    if let Err(e) = driver.handle(stream).await {
        warn!(?e, "QUIC server driver error");
    }
    Ok(())
}

fn build_client_endpoint() -> Result<Endpoint, std::io::Error> {
    let addr = SocketAddr::from((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    build_endpoint(EndpointConfig::default(), None, addr)
}

fn build_server_endpoint(
    addr: SocketAddr,
    server_config: Arc<ServerConfig>,
) -> Result<Endpoint, Error> {
    let quic_config = quic_server_config(server_config)?;
    build_endpoint(EndpointConfig::default(), Some(quic_config), addr).map_err(Error::from)
}

fn build_endpoint(
    config: EndpointConfig,
    server_config: Option<QuicServerConfig>,
    addr: SocketAddr,
) -> Result<Endpoint, std::io::Error> {
    let socket = std::net::UdpSocket::bind(addr)?;
    socket.set_nonblocking(true)?;
    Endpoint::new(config, server_config, socket, Arc::new(quinn::TokioRuntime))
}

fn quic_client_config(client: Arc<ClientConfig>) -> Result<QuicClientConfig, Error> {
    let rustls_config = (*client).clone();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)?;
    Ok(QuicClientConfig::new(Arc::new(crypto)))
}

fn quic_server_config(server: Arc<ServerConfig>) -> Result<QuicServerConfig, Error> {
    let rustls_config = (*server).clone();
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(rustls_config)?;
    let mut config = QuicServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(default_transport_config()));
    Ok(config)
}

fn default_transport_config() -> TransportConfig {
    let mut cfg = TransportConfig::default();
    cfg.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    cfg
}

fn server_name_for_addr(addr: SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => ip.to_string(),
    }
}

fn peer_id_from_connection(connection: &Connection) -> Result<PeerId, Error> {
    let identity = connection.peer_identity().ok_or(Error::QuicPeerIdentity)?;
    let chain = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| Error::QuicPeerIdentity)?;
    peer_id_from_rustls_chain(chain.as_slice()).ok_or(Error::QuicPeerIdentity)
}
