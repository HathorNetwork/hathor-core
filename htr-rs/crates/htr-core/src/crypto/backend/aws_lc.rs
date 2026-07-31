// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use super::*;
pub use aws_lc_rs::digest::Context;
use aws_lc_rs::digest::{Algorithm, SHA256};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::KeyPair as _;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, ECDSA_P384_SHA384_ASN1_SIGNING, EcdsaKeyPair,
    EcdsaSigningAlgorithm, Ed25519KeyPair, RsaKeyPair,
};

pub fn rustls_preferred_provider() -> CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

impl From<DigestAlgorithm> for &'static Algorithm {
    fn from(algo: DigestAlgorithm) -> Self {
        match algo {
            DigestAlgorithm::Sha256 => &SHA256,
        }
    }
}

impl From<Unspecified> for KeygenError {
    fn from(_: Unspecified) -> Self {
        KeygenError::Backend("unspecified aws-lc-rs error")
    }
}

fn gen_key_ed25519() -> Result<PrivateKey, KeygenError> {
    let keypair = Ed25519KeyPair::generate()?;
    // Emit PKCS#8 v1 for maximum interoperability
    let pkcs8 = keypair.to_pkcs8v1()?;
    Ok(PrivateKey(
        PrivatePkcs8KeyDer::from(pkcs8.as_ref()).clone_key(),
    ))
}

impl From<EcdsaKeygenParams> for &'static EcdsaSigningAlgorithm {
    fn from(params: EcdsaKeygenParams) -> Self {
        match params {
            // XXX: ASN.1 or fixed-length? for now using one of each, but maybe move both to ASN.1?
            EcdsaKeygenParams::EcdsaP256Sha256 => &ECDSA_P256_SHA256_FIXED_SIGNING,
            EcdsaKeygenParams::EcdsaP384Sha384 => &ECDSA_P384_SHA384_ASN1_SIGNING,
        }
    }
}

fn gen_key_ecdsa_p256(params: EcdsaKeygenParams) -> Result<PrivateKey, KeygenError> {
    let keypair = EcdsaKeyPair::generate(params.into())?;
    let pkcs8 = keypair.to_pkcs8v1()?;
    Ok(PrivateKey(
        PrivatePkcs8KeyDer::from(pkcs8.as_ref()).clone_key(),
    ))
}

impl From<RsaKeygenParams> for KeySize {
    fn from(params: RsaKeygenParams) -> Self {
        match params {
            RsaKeygenParams::Rsa2048 => KeySize::Rsa2048,
            RsaKeygenParams::Rsa3072 => KeySize::Rsa3072,
            RsaKeygenParams::Rsa4096 => KeySize::Rsa4096,
        }
    }
}

fn gen_key_rsa(params: RsaKeygenParams) -> Result<PrivateKey, KeygenError> {
    let keypair = RsaKeyPair::generate(params.into())?;
    let pkcs8 = keypair.as_der()?;
    Ok(PrivateKey(
        PrivatePkcs8KeyDer::from(pkcs8.as_ref()).clone_key(),
    ))
}

pub(super) fn gen_priv_key(params: KeygenParams) -> Result<PrivateKey, KeygenError> {
    match params {
        KeygenParams::Ed25519 => gen_key_ed25519(),
        KeygenParams::Ecdsa(params) => gen_key_ecdsa_p256(params),
        KeygenParams::Rsa(params) => gen_key_rsa(params),
    }
}

pub(super) fn derive_pub_key(pkcs8: &PrivatePkcs8KeyDer<'_>) -> Result<PublicKey, KeygenError> {
    // Try Ed25519
    if let Ok(kp) = aws_lc_rs::signature::Ed25519KeyPair::from_pkcs8(pkcs8.secret_pkcs8_der()) {
        let der: aws_lc_rs::encoding::PublicKeyX509Der<'_> = kp
            .public_key()
            .as_der()
            .map_err(|_| KeygenError::Backend("aws-lc: ed25519 as_der"))?;
        return Ok(PublicKey(
            SubjectPublicKeyInfoDer::from(der.as_ref()).into_owned(),
        ));
    }

    // Try ECDSA P-256 / P-384
    if let Ok(kp) = aws_lc_rs::signature::EcdsaKeyPair::from_pkcs8(
        &aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        pkcs8.secret_pkcs8_der(),
    ) {
        let der: aws_lc_rs::encoding::PublicKeyX509Der<'_> = kp
            .public_key()
            .as_der()
            .map_err(|_| KeygenError::Backend("aws-lc: ecdsa-p256 as_der"))?;
        return Ok(PublicKey(
            SubjectPublicKeyInfoDer::from(der.as_ref()).into_owned(),
        ));
    }
    if let Ok(kp) = aws_lc_rs::signature::EcdsaKeyPair::from_pkcs8(
        &aws_lc_rs::signature::ECDSA_P384_SHA384_ASN1_SIGNING,
        pkcs8.secret_pkcs8_der(),
    ) {
        let der: aws_lc_rs::encoding::PublicKeyX509Der<'_> = kp
            .public_key()
            .as_der()
            .map_err(|_| KeygenError::Backend("aws-lc: ecdsa-p384 as_der"))?;
        return Ok(PublicKey(
            SubjectPublicKeyInfoDer::from(der.as_ref()).into_owned(),
        ));
    }

    // Try RSA
    if let Ok(rsa_priv) = aws_lc_rs::rsa::PrivateDecryptingKey::from_pkcs8(pkcs8.secret_pkcs8_der())
    {
        let rsa_pub = rsa_priv.public_key();
        let der: aws_lc_rs::encoding::PublicKeyX509Der<'_> =
            aws_lc_rs::encoding::AsDer::as_der(&rsa_pub)
                .map_err(|_| KeygenError::Backend("aws-lc: rsa as_der"))?;
        return Ok(PublicKey(
            SubjectPublicKeyInfoDer::from(der.as_ref()).into_owned(),
        ));
    }

    Err(KeygenError::Backend(
        "aws-lc: unsupported/private key parse failed",
    ))
}

pub(super) fn x509_rsa_sha256_sign(
    ca_key: &PrivatePkcs8KeyDer<'_>,
    tbs: &[u8],
) -> Result<Vec<u8>, KeygenError> {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
    let key = RsaKeyPair::from_pkcs8(ca_key.secret_pkcs8_der())
        .map_err(|_| KeygenError::Backend("aws-lc: rsa from_pkcs8"))?;
    let mut sig = vec![0u8; key.public_modulus_len()];
    key.sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), tbs, &mut sig)
        .map_err(|_| KeygenError::Backend("aws-lc: rsa sign"))?;
    Ok(sig)
}

pub(super) fn spki_oid_supported(oid: &str) -> bool {
    // AWS-LC supports RSA, ECDSA (P-256/P-384), and Ed25519
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
        let priv_key = gen_key_ed25519().expect("ed25519");
        let pub_key = priv_key.derive_pub_key().expect("spki");
        assert!(!priv_key.0.secret_pkcs8_der().is_empty());
        let _ = SubjectPublicKeyInfoRef::from_der(pub_key.0.as_ref()).expect("spki parse");
    }

    #[test]
    fn gen_ecdsa_p256() {
        let params = Default::default();
        let priv_key = gen_key_ecdsa_p256(params).expect("ecdsa-p256");
        let pub_key = priv_key.derive_pub_key().expect("spki");
        assert!(!priv_key.0.secret_pkcs8_der().is_empty());
        let _ = SubjectPublicKeyInfoRef::from_der(pub_key.0.as_ref()).expect("spki parse");
    }

    #[test]
    fn gen_rsa() {
        let params = Default::default();
        let priv_key = gen_key_rsa(params).expect("rsa");
        let pub_key = priv_key.derive_pub_key().expect("spki");
        assert!(!priv_key.0.secret_pkcs8_der().is_empty());
        let _ = SubjectPublicKeyInfoRef::from_der(pub_key.0.as_ref()).expect("spki parse");
    }
}
