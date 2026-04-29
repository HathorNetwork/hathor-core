// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use std::net::{Ipv6Addr, SocketAddr};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn bin(name: &str) -> std::path::PathBuf {
    let var = format!("CARGO_BIN_EXE_{}", name);
    let path = std::env::var_os(var).expect("binary not built");
    path.into()
}

fn run_pair(server_backend: &str, client_backend: &str) {
    // Use a fixed port in high range for simplicity
    let port = 18999u16;
    let _addr = SocketAddr::from((Ipv6Addr::LOCALHOST, port));
    let peer = std::path::Path::new("peer.json");
    assert!(peer.exists(), "peer.json missing at repo root");

    // Start server
    let srv = Command::new(bin("interop"))
        .arg("--backend")
        .arg(server_backend)
        .arg("--mode")
        .arg("server")
        .arg("--addr")
        .arg(format!("[::1]:{}", port))
        .arg("--peer")
        .arg(peer)
        .arg("--timeout")
        .arg("6")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");

    // Start client
    let cli = Command::new(bin("interop"))
        .arg("--backend")
        .arg(client_backend)
        .arg("--mode")
        .arg("client")
        .arg("--addr")
        .arg("127.0.0.1:18999")
        .arg("--peer")
        .arg(peer)
        .arg("--timeout")
        .arg("6")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn client");

    let deadline = Instant::now() + Duration::from_secs(20);
    let (mut srv, mut cli) = (srv, cli);
    loop {
        let s = srv.try_wait().unwrap();
        let c = cli.try_wait().unwrap();
        if let (Some(se), Some(ce)) = (s, c) {
            assert!(se.success(), "server exit: {:?}", se);
            assert!(ce.success(), "client exit: {:?}", ce);
            break;
        }
        assert!(Instant::now() < deadline, "timeout waiting processes");
        std::thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[ignore]
fn tls_cross_backend_matrix() {
    // Build with --all-features to enable all backends
    let backends = [
        #[cfg(feature = "crypto-aws-lc")]
        "aws-lc",
        #[cfg(feature = "crypto-graviola")]
        "graviola",
        #[cfg(feature = "crypto-openssl")]
        "openssl",
    ];
    for &srv in &backends {
        for &cli in &backends {
            run_pair(srv, cli);
        }
    }
}
