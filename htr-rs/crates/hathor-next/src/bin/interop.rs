// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, ValueEnum};
use hathor_next as core;
use hathor_next::{network_info, peer};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Backend {
    AwsLc,
    Graviola,
    Openssl,
}

impl Backend {
    fn install(self) {
        use rustls::crypto::CryptoProvider;
        match self {
            Backend::AwsLc => {
                #[cfg(feature = "crypto-aws-lc")]
                {
                    let _ = CryptoProvider::install_default(
                        rustls::crypto::aws_lc_rs::default_provider(),
                    );
                }
                #[cfg(not(feature = "crypto-aws-lc"))]
                panic!("aws-lc backend not compiled");
            }
            Backend::Graviola => {
                #[cfg(feature = "crypto-graviola")]
                {
                    let _ = CryptoProvider::install_default(rustls_graviola::default_provider());
                }
                #[cfg(not(feature = "crypto-graviola"))]
                panic!("graviola backend not compiled");
            }
            Backend::Openssl => {
                #[cfg(feature = "crypto-openssl")]
                {
                    let _ = CryptoProvider::install_default(rustls_openssl::default_provider());
                }
                #[cfg(not(feature = "crypto-openssl"))]
                panic!("openssl backend not compiled");
            }
        }
    }
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum Mode {
    Server,
    Client,
}

#[derive(Debug, Parser)]
#[command(about = "Interop binary with selectable TLS backend")]
struct Cli {
    #[arg(long, value_enum)]
    backend: Backend,
    #[arg(long, value_enum)]
    mode: Mode,
    #[arg(long)]
    addr: SocketAddr,
    #[arg(long)]
    peer: PathBuf,
    #[arg(long)]
    timeout: Option<u64>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    // Select provider at runtime
    cli.backend.install();

    let peer = peer::PrivatePeer::load_file(cli.peer)?;
    let network = network_info::NETWORK_INFO_TESTNET_INDIA.clone();
    let timeout = cli.timeout.map(std::time::Duration::from_secs);
    match cli.mode {
        Mode::Server => {
            let addr = peer::PeerAddress::from_socket_tcp(cli.addr);
            core::p2p::run_server_main(
                peer.clone(),
                Vec::new(),
                vec![addr.to_socket_addr().expect("socket")],
                Vec::new(),
                network.clone(),
                timeout,
            )?
        }
        Mode::Client => {
            let addr = peer::PeerAddress::from_socket_tcp(cli.addr);
            core::p2p::run_server_main(peer, vec![addr], Vec::new(), Vec::new(), network, timeout)?
        }
    }
    Ok(())
}
