// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

//! Crypto utilities
//!
//! Feature-gated SHA-256 hashing (provider shim; defaults to aws_lc_rs),
//! exposing a small, stable wrapper API for the rest of the crate.

use base64::prelude::*;
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

mod digest;
mod keygen;
mod priv_key;
mod pub_key;
mod verifier;

// Backend-specific implementations live in feature-gated modules so they all
// compile under `--all-features`.

// Backend implementations are compiled per feature. Select a single active
// backend alias as `backend`, preferring aws-lc when enabled.
#[cfg(feature = "crypto-aws-lc")]
#[path = "backend/aws_lc.rs"]
mod backend_aws_lc;

#[cfg(feature = "crypto-graviola")]
#[path = "backend/graviola.rs"]
mod backend_graviola;

#[cfg(feature = "crypto-openssl")]
#[path = "backend/openssl.rs"]
mod backend_openssl;

// The preferred default backend is aliased to `backend` instead of `backend_<name>`
std::cfg_select! {
    feature = "crypto-aws-lc" => {
        use self::backend_aws_lc as backend;
    }
    feature = "crypto-graviola" => {
        use self::backend_graviola as backend;
    }
    feature = "crypto-openssl" => {
        use self::backend_openssl as backend;
    }
    _ => {
        compile_error!("No crypto backend selected. Enable one of: crypto-aws-lc, crypto-graviola, crypto-openssl");
    }
}

pub use self::digest::Algorithm as DigestAlgorithm;
pub use self::digest::Context as DigestContext;
pub use self::digest::helpers::*;
pub use self::keygen::*;
pub use self::priv_key::PrivateKey;
pub use self::pub_key::PublicKey;
pub use self::verifier::NoSanVerification;
pub use backend::rustls_preferred_provider;

use rustls::crypto::CryptoProvider;

/// Ensure rustls has a process-wide default `CryptoProvider` installed when
/// both providers are compiled in. This is a no-op otherwise. Safe to call
/// multiple times; installation is guarded by `Once`.
/// Install the preferred rustls CryptoProvider as the global default.
/// Safe to call multiple times; if a provider is already installed, the error is ignored.
pub fn install_default_crypto_provider() {
    let provider = rustls_preferred_provider();
    let _ = rustls::crypto::CryptoProvider::install_default(provider);
}

/// Sign TBSCertificate bytes with the embedded CA private key using RSA/PKCS#1 v1.5 + SHA-256.
pub fn x509_rsa_sha256_sign(
    ca_key: &rustls_pki_types::PrivatePkcs8KeyDer<'_>,
    tbs: &[u8],
) -> Result<Vec<u8>, KeygenError> {
    self::backend::x509_rsa_sha256_sign(ca_key, tbs)
}

/// Return whether the selected backend supports a given SPKI algorithm OID
/// (dotted-decimal string, e.g., "1.3.101.112" for Ed25519, "1.2.840.113549.1.1.1" for RSA,
/// "1.2.840.10045.2.1" for ECDSA).
pub fn spki_oid_supported(oid: &str) -> bool {
    self::backend::spki_oid_supported(oid)
}
