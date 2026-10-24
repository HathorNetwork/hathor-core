// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use super::*;
use openssl::ec::{EcGroup, EcKey};
use openssl::nid::Nid;
use openssl::pkey::{PKey, Private};
use openssl::rsa::Rsa;

pub fn rustls_preferred_provider() -> CryptoProvider {
    rustls_openssl::default_provider()
}

// Digest via OpenSSL
pub struct Context(openssl::sha::Sha256);
// Backend-specific marker to select digest algorithm (avoids conflicts under all-features)
pub struct Algo;

pub struct DigestBytes([u8; 32]);

impl AsRef<[u8]> for DigestBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Context {
    pub fn new(_algo: Algo) -> Self {
        Self(openssl::sha::Sha256::new())
    }
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    pub fn finish(self) -> DigestBytes {
        let out = self.0.finish();
        DigestBytes(out)
    }
}

impl From<DigestAlgorithm> for Algo {
    fn from(_algo: DigestAlgorithm) -> Self {
        Algo
    }
}

fn pkey_to_pkcs8(pkey: PKey<Private>) -> Result<PrivateKey, KeygenError> {
    let der = pkey
        .private_key_to_der()
        .map_err(|_| KeygenError::Backend("openssl: private_key_to_der"))?;
    Ok(PrivateKey(
        PrivatePkcs8KeyDer::from(der.as_slice()).clone_key(),
    ))
}

fn gen_key_ed25519() -> Result<PrivateKey, KeygenError> {
    let pkey =
        PKey::generate_ed25519().map_err(|_| KeygenError::Backend("openssl: generate_ed25519"))?;
    pkey_to_pkcs8(pkey)
}

impl From<EcdsaKeygenParams> for Nid {
    fn from(params: EcdsaKeygenParams) -> Self {
        match params {
            EcdsaKeygenParams::EcdsaP256Sha256 => Nid::X9_62_PRIME256V1,
            EcdsaKeygenParams::EcdsaP384Sha384 => Nid::SECP384R1,
        }
    }
}

fn gen_key_ecdsa(params: EcdsaKeygenParams) -> Result<PrivateKey, KeygenError> {
    let group = EcGroup::from_curve_name(params.into())
        .map_err(|_| KeygenError::Backend("openssl: EcGroup::from_curve_name"))?;
    let ec_key =
        EcKey::generate(&group).map_err(|_| KeygenError::Backend("openssl: EcKey::generate"))?;
    let pkey = PKey::from_ec_key(ec_key)
        .map_err(|_| KeygenError::Backend("openssl: PKey::from_ec_key"))?;
    pkey_to_pkcs8(pkey)
}

impl From<RsaKeygenParams> for u32 {
    fn from(params: RsaKeygenParams) -> Self {
        match params {
            RsaKeygenParams::Rsa2048 => 2048,
            RsaKeygenParams::Rsa3072 => 3072,
            RsaKeygenParams::Rsa4096 => 4096,
        }
    }
}

fn gen_key_rsa(params: RsaKeygenParams) -> Result<PrivateKey, KeygenError> {
    let rsa =
        Rsa::generate(params.into()).map_err(|_| KeygenError::Backend("openssl: Rsa::generate"))?;
    let pkey = PKey::from_rsa(rsa).map_err(|_| KeygenError::Backend("openssl: PKey::from_rsa"))?;
    pkey_to_pkcs8(pkey)
}

pub(super) fn gen_priv_key(params: KeygenParams) -> Result<PrivateKey, KeygenError> {
    match params {
        KeygenParams::Ed25519 => gen_key_ed25519(),
        KeygenParams::Ecdsa(params) => gen_key_ecdsa(params),
        KeygenParams::Rsa(params) => gen_key_rsa(params),
    }
}

pub(super) fn x509_rsa_sha256_sign(
    ca_key: &PrivatePkcs8KeyDer<'_>,
    tbs: &[u8],
) -> Result<Vec<u8>, KeygenError> {
    use openssl::hash::MessageDigest;
    use openssl::pkey::PKey;
    use openssl::sign::Signer;
    let pkey = PKey::private_key_from_der(ca_key.secret_pkcs8_der())
        .map_err(|_| KeygenError::Backend("openssl: rsa from_pkcs8"))?;
    let mut signer =
        Signer::new(MessageDigest::sha256(), &pkey).map_err(|_| KeygenError::Backend("signer"))?;
    signer
        .update(tbs)
        .map_err(|_| KeygenError::Backend("update"))?;
    signer
        .sign_to_vec()
        .map_err(|_| KeygenError::Backend("sign"))
}

pub(super) fn derive_pub_key(pkcs8: &PrivatePkcs8KeyDer<'_>) -> Result<PublicKey, KeygenError> {
    // Parse PKCS#8 using OpenSSL and emit SPKI via `public_key_to_der`.
    let pkey = PKey::private_key_from_der(pkcs8.secret_pkcs8_der())
        .map_err(|_| KeygenError::Backend("openssl: private_key_from_der"))?;
    let spki = pkey
        .public_key_to_der()
        .map_err(|_| KeygenError::Backend("openssl: public_key_to_der"))?;
    Ok(PublicKey(
        SubjectPublicKeyInfoDer::from(spki.as_slice()).into_owned(),
    ))
}

pub(super) fn spki_oid_supported(oid: &str) -> bool {
    // OpenSSL supports RSA, ECDSA (P-256/P-384), and Ed25519
    matches!(
        oid,
        "1.2.840.113549.1.1.1" // rsaEncryption
            | "1.2.840.10045.2.1" // id-ecPublicKey
            | "1.3.101.112" // Ed25519
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;
    use spki::SubjectPublicKeyInfoRef;

    #[test]
    fn gen_ed25519() {
        let priv_key = super::gen_key_ed25519().expect("ed25519");
        assert!(!priv_key.0.secret_pkcs8_der().is_empty());
        // Build SPKI via OpenSSL directly to avoid cross-backend interaction under --all-features.
        let pkey = PKey::private_key_from_der(priv_key.0.secret_pkcs8_der()).unwrap();
        let spki = pkey.public_key_to_der().unwrap();
        let _ = SubjectPublicKeyInfoRef::from_der(spki.as_slice()).expect("spki parse");
    }

    #[test]
    fn gen_ecdsa_p256() {
        let params = EcdsaKeygenParams::EcdsaP256Sha256;
        let priv_key = super::gen_key_ecdsa(params).expect("ecdsa-p256");
        assert!(!priv_key.0.secret_pkcs8_der().is_empty());
        let pkey = PKey::private_key_from_der(priv_key.0.secret_pkcs8_der()).unwrap();
        let spki = pkey.public_key_to_der().unwrap();
        let _ = SubjectPublicKeyInfoRef::from_der(spki.as_slice()).expect("spki parse");
    }

    #[test]
    fn gen_rsa() {
        let params = RsaKeygenParams::Rsa2048;
        let priv_key = super::gen_key_rsa(params).expect("rsa");
        assert!(!priv_key.0.secret_pkcs8_der().is_empty());
        let pkey = PKey::private_key_from_der(priv_key.0.secret_pkcs8_der()).unwrap();
        let spki = pkey.public_key_to_der().unwrap();
        let _ = SubjectPublicKeyInfoRef::from_der(spki.as_slice()).expect("spki parse");
    }
}
