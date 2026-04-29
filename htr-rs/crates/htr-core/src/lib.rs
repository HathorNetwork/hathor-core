// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

#![allow(unexpected_cfgs)]

// At least one crypto backend must be selected.
#[cfg(not(any(
    feature = "crypto-aws-lc",
    feature = "crypto-graviola",
    feature = "crypto-openssl"
)))]
compile_error!("Enable at least one of: 'crypto-aws-lc', 'crypto-graviola', or 'crypto-openssl'");

// QUIC transport currently relies on the AWS-LC-powered rustls backend.
#[cfg(all(feature = "transport-quic", not(feature = "crypto-aws-lc")))]
compile_error!("Feature 'transport-quic' requires 'crypto-aws-lc'");

// The Tokio console layer only receives task data when the binary is built with `--cfg
// tokio_unstable`. Enabling the `tokio-console` feature without that cfg still compiles (so the
// whole workspace builds under `--all-features`); the console layer is simply skipped at runtime
// and a warning is emitted instead — see `logging::init_subscriber`.

pub mod ca;
pub mod common;
pub mod config;
pub mod crypto;
pub mod discovery;
pub mod logging;
pub mod nano;
pub mod network_info;
pub mod p2p;
pub mod peer;
pub mod protocol;
pub mod stun;
pub mod utils;
pub mod vertex;

// Install a process-level CryptoProvider, preferring AWS‑LC (shim for now).
// Safe to call multiple times; errors are ignored.
pub fn ensure_default_crypto_provider() {
    crate::crypto::install_default_crypto_provider();
}
