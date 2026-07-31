// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

//! Per-state protocol coverage for the `IoDriver`, driven over an in-memory TLS duplex.
//!
//! Generalizes `ready_ping_pong.rs` from the single happy path into a matrix: it walks
//! HELLO -> PEER-ID -> READY asserting the exact server lines, checks PING/PONG, checks that
//! messages the driver does not answer keep the connection open (the live counterpart to the
//! byte-level parity tests), and checks that an out-of-state or error line closes the connection.

use htr_core::network_info::NETWORK_INFO_TESTNET_HOTEL as INFO;
use htr_core::peer::PrivatePeer;
use htr_core::protocol::drivers::IoDriver;
use htr_core::protocol::message::{
    HelloMessage, HelloStateMessage, PeerIdMessage, PeerIdStateMessage, ReadyMessage,
    ReadyStateMessage,
};
use rustls_pki_types::ServerName;
use std::net::{IpAddr, Ipv4Addr};
use tokio::io::{
    self, AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader, DuplexStream,
};
use tokio::task::JoinHandle;
use tokio::time::{Duration, timeout};
use tokio_rustls::client::TlsStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Stand up a TLS-secured in-memory connection with the `IoDriver` running on the server side.
/// Returns the client-side TLS stream, the client peer (needed to send PEER-ID), and the server
/// task handle.
async fn setup() -> (TlsStream<DuplexStream>, PrivatePeer, JoinHandle<()>) {
    htr_core::ensure_default_crypto_provider();
    let (cli_io, srv_io) = io::duplex(64 * 1024);

    let server_peer = PrivatePeer::generate_default().expect("server peer gen");
    let client_peer = PrivatePeer::generate_default().expect("client peer gen");

    let acceptor = TlsAcceptor::from(server_peer.gen_server_config().expect("srv cfg"));
    let connector = TlsConnector::from(client_peer.gen_client_config().expect("cli cfg"));

    let (srv_tls, cli_tls) = tokio::join!(
        async { acceptor.accept(srv_io).await.expect("accept") },
        async {
            let name = ServerName::IpAddress(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)).into());
            connector.connect(name, cli_io).await.expect("connect")
        }
    );

    let handle = tokio::spawn(async move {
        let driver = IoDriver::new(INFO.clone(), server_peer.into());
        let _ = driver.handle(srv_tls).await;
    });

    (cli_tls, client_peer, handle)
}

/// Read one CRLF-terminated line, returning `None` on EOF (i.e. the server closed the connection).
async fn read_line<R: AsyncBufRead + Unpin>(reader: &mut R) -> Option<String> {
    let mut buf = Vec::new();
    let result = timeout(READ_TIMEOUT, reader.read_until(b'\n', &mut buf))
        .await
        .expect("read timed out");
    let n = match result {
        Ok(n) => n,
        // A closed connection surfaces either as a clean EOF (`Ok(0)`) or, when the peer drops the
        // socket without a TLS close_notify, as `UnexpectedEof` from rustls. Both mean "closed".
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return None,
        Err(e) => panic!("read failed: {e}"),
    };
    if n == 0 {
        return None;
    }
    if buf.ends_with(b"\n") {
        buf.pop();
    }
    if buf.ends_with(b"\r") {
        buf.pop();
    }
    Some(String::from_utf8(buf).expect("utf-8 line"))
}

async fn send_line<W: AsyncWrite + Unpin>(w: &mut W, line: &str) {
    w.write_all(line.as_bytes()).await.expect("write line");
    w.write_all(b"\r\n").await.expect("write crlf");
}

/// Drive the client side of the handshake through to READY, asserting each server line exactly.
async fn handshake_to_ready<R, W>(reader: &mut R, w: &mut W, client_peer: &PrivatePeer)
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // HELLO: the server greets first; its HELLO must carry our network.
    let line = read_line(reader).await.expect("server HELLO");
    match line
        .parse::<HelloStateMessage>()
        .expect("parse server HELLO")
    {
        HelloStateMessage::Hello(HelloMessage::Hello(data)) => {
            assert_eq!(data.network, INFO.name.to_string());
        }
        other => panic!("expected HELLO, got {other:?}"),
    }
    send_line(w, &HelloMessage::Hello(INFO.make_hello_data()).to_string()).await;

    // PEER-ID: the server sends its identity; we answer with ours.
    let line = read_line(reader).await.expect("server PEER-ID");
    match line
        .parse::<PeerIdStateMessage>()
        .expect("parse server PEER-ID")
    {
        PeerIdStateMessage::PeerId(PeerIdMessage::PeerId(_)) => {}
        other => panic!("expected PEER-ID, got {other:?}"),
    }
    send_line(
        w,
        &PeerIdMessage::PeerId(client_peer.clone().into()).to_string(),
    )
    .await;

    // READY: exact line, then we send ours to complete the handshake.
    let line = read_line(reader).await.expect("server READY");
    assert_eq!(line, "READY");
    send_line(w, &PeerIdMessage::Ready.to_string()).await;
}

#[tokio::test]
async fn handshake_reaches_ready_and_ping_pongs() {
    let (cli_tls, client_peer, server) = setup().await;
    let (r, mut w) = io::split(cli_tls);
    let mut reader = BufReader::new(r);

    handshake_to_ready(&mut reader, &mut w, &client_peer).await;

    send_line(&mut w, &ReadyMessage::Ping("deadbeef".into()).to_string()).await;
    let line = read_line(&mut reader).await.expect("PONG");
    match line.parse::<ReadyStateMessage>().expect("parse PONG") {
        ReadyStateMessage::Ready(ReadyMessage::Pong(salt)) => assert_eq!(salt, "deadbeef"),
        other => panic!("expected PONG, got {other:?}"),
    }

    let _ = w.shutdown().await;
    let _ = timeout(Duration::from_secs(1), server).await;
}

#[tokio::test]
async fn ignored_ready_message_keeps_connection_open() {
    let (cli_tls, client_peer, server) = setup().await;
    let (r, mut w) = io::split(cli_tls);
    let mut reader = BufReader::new(r);

    handshake_to_ready(&mut reader, &mut w, &client_peer).await;

    // GET-PEERS is parsed but not answered by the passive driver; the connection must stay open,
    // which we prove by a subsequent PING still returning a PONG.
    send_line(&mut w, &ReadyMessage::GetPeers.to_string()).await;
    send_line(&mut w, &ReadyMessage::Ping("c0ffee".into()).to_string()).await;
    let line = read_line(&mut reader).await.expect("PONG after GET-PEERS");
    match line.parse::<ReadyStateMessage>().expect("parse PONG") {
        ReadyStateMessage::Ready(ReadyMessage::Pong(salt)) => assert_eq!(salt, "c0ffee"),
        other => panic!("expected PONG, got {other:?}"),
    }

    let _ = w.shutdown().await;
    let _ = timeout(Duration::from_secs(1), server).await;
}

#[tokio::test]
async fn ignored_sync_message_keeps_connection_open() {
    let (cli_tls, client_peer, server) = setup().await;
    let (r, mut w) = io::split(cli_tls);
    let mut reader = BufReader::new(r);

    handshake_to_ready(&mut reader, &mut w, &client_peer).await;

    // A sync-v2 request is parsed but not answered; the connection must stay open.
    send_line(&mut w, "GET-BEST-BLOCK").await;
    send_line(&mut w, &ReadyMessage::Ping("abcabc".into()).to_string()).await;
    let line = read_line(&mut reader)
        .await
        .expect("PONG after GET-BEST-BLOCK");
    match line.parse::<ReadyStateMessage>().expect("parse PONG") {
        ReadyStateMessage::Ready(ReadyMessage::Pong(salt)) => assert_eq!(salt, "abcabc"),
        other => panic!("expected PONG, got {other:?}"),
    }

    let _ = w.shutdown().await;
    let _ = timeout(Duration::from_secs(1), server).await;
}

#[tokio::test]
async fn out_of_state_message_during_hello_closes_connection() {
    let (cli_tls, _client_peer, server) = setup().await;
    let (r, mut w) = io::split(cli_tls);
    let mut reader = BufReader::new(r);

    // Read the server HELLO, then send a READY-only message instead of HELLO. It is invalid in the
    // HELLO state, so the server drops the connection.
    let _ = read_line(&mut reader).await.expect("server HELLO");
    send_line(&mut w, &ReadyMessage::Ping("nope".into()).to_string()).await;

    assert!(
        read_line(&mut reader).await.is_none(),
        "server should close the connection on an out-of-state message",
    );

    let _ = timeout(Duration::from_secs(1), server).await;
}

#[tokio::test]
async fn error_control_during_hello_closes_connection() {
    let (cli_tls, _client_peer, server) = setup().await;
    let (r, mut w) = io::split(cli_tls);
    let mut reader = BufReader::new(r);

    // An ERROR control message is accepted in any state and ends the connection.
    let _ = read_line(&mut reader).await.expect("server HELLO");
    send_line(&mut w, "ERROR boom").await;

    assert!(
        read_line(&mut reader).await.is_none(),
        "server should close the connection after receiving ERROR",
    );

    let _ = timeout(Duration::from_secs(1), server).await;
}
