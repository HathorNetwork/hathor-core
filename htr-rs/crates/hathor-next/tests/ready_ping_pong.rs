// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use hathor_next::network_info::NETWORK_INFO_TESTNET_HOTEL as INFO;
use hathor_next::peer::PrivatePeer;
use hathor_next::protocol;
use hathor_next::protocol::message::{
    HelloMessage, HelloStateMessage, PeerIdMessage, PeerIdStateMessage, ReadyMessage,
    ReadyStateMessage,
};
use rustls_pki_types::ServerName;
use tokio::io::duplex;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::time::{Duration, timeout};
use tokio_rustls::{TlsAcceptor, TlsConnector};
// PrivatePeer generator used directly in tests

#[tokio::test]
async fn run_typed_happy_path_ping_pong() {
    hathor_next::ensure_default_crypto_provider();
    // TLS accept/connect over an in-memory duplex
    let (cli_io, srv_io) = duplex(64 * 1024);

    let server_peer = PrivatePeer::generate_default().expect("peer gen");
    let client_peer = PrivatePeer::generate_default().expect("peer gen");

    let acceptor = TlsAcceptor::from(server_peer.gen_server_config().expect("srv cfg"));
    let connector = TlsConnector::from(client_peer.gen_client_config().expect("cli cfg"));

    // Perform TLS handshake concurrently
    let (srv_tls, cli_tls) = tokio::join!(
        async { acceptor.accept(srv_io).await.expect("accept") },
        async {
            connector
                .connect(
                    ServerName::IpAddress(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)).into(),
                    ),
                    cli_io,
                )
                .await
                .expect("connect")
        }
    );

    // Launch typed engine on the server side
    let server = tokio::spawn(async move {
        let driver = protocol::drivers::IoDriver::new(INFO.clone(), server_peer.into());
        let _ = driver.handle(srv_tls).await;
    });

    // Client harness: split TLS stream and talk ASCII lines
    let (r, mut w) = io::split(cli_tls);
    let mut reader = BufReader::new(r);

    // Expect server HELLO first
    let mut buf = Vec::new();
    timeout(Duration::from_secs(2), reader.read_until(b'\n', &mut buf))
        .await
        .expect("timeout reading server HELLO")
        .expect("read server HELLO");
    if buf.ends_with(b"\n") {
        buf.pop();
    }
    if buf.ends_with(b"\r") {
        buf.pop();
    }
    let line = String::from_utf8(buf).unwrap();
    let inbound: HelloStateMessage = line.parse().expect("parse server HELLO");
    assert!(matches!(inbound, HelloStateMessage::Hello(_)));

    // Send our HELLO
    let hello_line = HelloMessage::Hello(INFO.make_hello_data()).to_string();
    w.write_all(hello_line.as_bytes()).await.unwrap();
    w.write_all(b"\r\n").await.unwrap();

    // Expect server PEER-ID
    let mut buf = Vec::new();
    timeout(Duration::from_secs(2), reader.read_until(b'\n', &mut buf))
        .await
        .expect("timeout reading server PEER-ID")
        .expect("read server PEER-ID");
    if buf.ends_with(b"\n") {
        buf.pop();
    }
    if buf.ends_with(b"\r") {
        buf.pop();
    }
    let line = String::from_utf8(buf).unwrap();
    let got_peer: PeerIdStateMessage = line.parse().expect("parse server PEER-ID");
    assert!(matches!(
        got_peer,
        PeerIdStateMessage::PeerId(PeerIdMessage::PeerId(_))
    ));

    // Send our PEER-ID
    let pid_line = PeerIdMessage::PeerId(client_peer.clone().into()).to_string();
    w.write_all(pid_line.as_bytes()).await.unwrap();
    w.write_all(b"\r\n").await.unwrap();

    // Expect server READY
    let mut buf = Vec::new();
    timeout(Duration::from_secs(2), reader.read_until(b'\n', &mut buf))
        .await
        .expect("timeout reading server READY")
        .expect("read server READY");
    if buf.ends_with(b"\n") {
        buf.pop();
    }
    if buf.ends_with(b"\r") {
        buf.pop();
    }
    let line = String::from_utf8(buf).unwrap();
    let got_ready: PeerIdStateMessage = line.parse().expect("parse server READY");
    assert!(matches!(
        got_ready,
        PeerIdStateMessage::PeerId(PeerIdMessage::Ready)
    ));

    // Send our READY
    let ready_line = PeerIdMessage::Ready.to_string();
    w.write_all(ready_line.as_bytes()).await.unwrap();
    w.write_all(b"\r\n").await.unwrap();

    // Send PING and expect PONG with equal payload
    let salt = "deadbeef".to_string();
    let ping_line = ReadyMessage::Ping(salt.clone()).to_string();
    w.write_all(ping_line.as_bytes()).await.unwrap();
    w.write_all(b"\r\n").await.unwrap();

    let mut buf = Vec::new();
    timeout(Duration::from_secs(2), reader.read_until(b'\n', &mut buf))
        .await
        .expect("timeout reading server PONG")
        .expect("read server PONG");
    if buf.ends_with(b"\n") {
        buf.pop();
    }
    if buf.ends_with(b"\r") {
        buf.pop();
    }
    let line = String::from_utf8(buf).unwrap();
    let inbound: ReadyStateMessage = line.parse().expect("parse PONG");
    match inbound {
        ReadyStateMessage::Ready(ReadyMessage::Pong(s)) => assert_eq!(s, salt),
        other => panic!("unexpected READY response: {:?}", other),
    }

    // Close
    let _ = w.shutdown().await;
    drop(reader);
    let _ = timeout(Duration::from_secs(1), server).await;
}
