// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use super::*;

// Digest via graviola
use graviola::hashing::{
    Hash as GraviolaHash, HashContext, HashOutput as GraviolaHashOutput, Sha256,
};

pub fn rustls_preferred_provider() -> CryptoProvider {
    rustls_graviola::default_provider()
}

pub struct Context(<Sha256 as GraviolaHash>::Context);
// Backend-specific marker for digest algorithm selection (avoids trait impl conflicts under
// `--all-features`).
pub struct Algo;
pub struct DigestBytes(GraviolaHashOutput);

impl AsRef<[u8]> for DigestBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Context {
    pub fn new(_algo: Algo) -> Self {
        Self(Sha256::new())
    }
    pub fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
    pub fn finish(self) -> DigestBytes {
        DigestBytes(self.0.finish())
    }
}

impl From<DigestAlgorithm> for Algo {
    fn from(_algo: DigestAlgorithm) -> Self {
        Algo
    }
}

fn gen_key_ed25519() -> Result<PrivateKey, KeygenError> {
    use graviola::signing::eddsa::Ed25519SigningKey;
    let sk = Ed25519SigningKey::generate()
        .map_err(|_| KeygenError::Backend("graviola: ed25519 generate"))?;
    let pkcs8 = ed25519_pkcs8_v1_from_seed(&sk.as_seed());
    Ok(PrivateKey(
        PrivatePkcs8KeyDer::from(pkcs8.as_slice()).clone_key(),
    ))
}

fn ed25519_pkcs8_v1_from_seed(seed: &[u8; 32]) -> [u8; 48] {
    let mut pkcs8 = [0u8; 48];
    pkcs8[..16].copy_from_slice(&[
        0x30, 0x2e, // SEQUENCE, 46 bytes
        0x02, 0x01, 0x00, // version = 0
        0x30, 0x05, // AlgorithmIdentifier, 5 bytes
        0x06, 0x03, 0x2b, 0x65, 0x70, // id-Ed25519
        0x04, 0x22, // privateKey OCTET STRING, 34 bytes
        0x04, 0x20, // nested Ed25519 seed OCTET STRING, 32 bytes
    ]);
    pkcs8[16..].copy_from_slice(seed);
    pkcs8
}

fn gen_key_ecdsa(params: EcdsaKeygenParams) -> Result<PrivateKey, KeygenError> {
    use graviola::key_agreement::p256::StaticPrivateKey as P256Priv;
    use graviola::key_agreement::p384::StaticPrivateKey as P384Priv;
    use graviola::signing::ecdsa::SigningKey as EcdsaSigningKey;
    use graviola::signing::ecdsa::{P256, P384};
    let pkcs8 = match params {
        EcdsaKeygenParams::EcdsaP256Sha256 => {
            let sk = P256Priv::new_random()
                .map_err(|_| KeygenError::Backend("graviola: p256 new_random"))?;
            let sk = EcdsaSigningKey::<P256> { private_key: sk };
            let mut buf = [0u8; 512];
            sk.to_pkcs8_der(&mut buf)
                .map_err(|_| KeygenError::Backend("graviola: p256 to_pkcs8"))?
                .to_vec()
        }
        EcdsaKeygenParams::EcdsaP384Sha384 => {
            let sk = P384Priv::new_random()
                .map_err(|_| KeygenError::Backend("graviola: p384 new_random"))?;
            let sk = EcdsaSigningKey::<P384> { private_key: sk };
            let mut buf = [0u8; 512];
            sk.to_pkcs8_der(&mut buf)
                .map_err(|_| KeygenError::Backend("graviola: p384 to_pkcs8"))?
                .to_vec()
        }
    };
    Ok(PrivateKey(
        PrivatePkcs8KeyDer::from(pkcs8.as_slice()).clone_key(),
    ))
}

use graviola::signing::rsa::KeySize as GraviolaRsaKeySize;

impl From<RsaKeygenParams> for GraviolaRsaKeySize {
    fn from(params: RsaKeygenParams) -> Self {
        match params {
            RsaKeygenParams::Rsa2048 => GraviolaRsaKeySize::Rsa2048,
            RsaKeygenParams::Rsa3072 => GraviolaRsaKeySize::Rsa3072,
            RsaKeygenParams::Rsa4096 => GraviolaRsaKeySize::Rsa4096,
        }
    }
}

fn gen_key_rsa(params: RsaKeygenParams) -> Result<PrivateKey, KeygenError> {
    use graviola::signing::rsa::SigningKey;
    let size: GraviolaRsaKeySize = params.into();
    let sk =
        SigningKey::generate(size).map_err(|_| KeygenError::Backend("graviola: rsa generate"))?;
    let mut buf = vec![0u8; 8192];
    let der = sk
        .to_pkcs8_der(&mut buf)
        .map_err(|_| KeygenError::Backend("graviola: rsa to_pkcs8_der"))?;
    Ok(PrivateKey(PrivatePkcs8KeyDer::from(der).clone_key()))
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
    use graviola::signing::rsa::SigningKey;
    let sk = SigningKey::from_pkcs8_der(ca_key.secret_pkcs8_der())
        .map_err(|_| KeygenError::Backend("graviola: rsa from_pkcs8"))?;
    let mut sig = vec![0u8; sk.modulus_len_bytes()];
    let sig = sk
        .sign_pkcs1_sha256(&mut sig, tbs)
        .map_err(|_| KeygenError::Backend("graviola: rsa sign"))?;
    Ok(sig.to_vec())
}

pub(super) fn derive_pub_key(pkcs8: &PrivatePkcs8KeyDer<'_>) -> Result<PublicKey, KeygenError> {
    use graviola::signing::ecdsa::{P256, P384, SigningKey as EcdsaSigningKey};
    use graviola::signing::rsa::SigningKey as RsaSigningKey;

    // Try RSA first
    if let Ok(sk) = RsaSigningKey::from_pkcs8_der(pkcs8.secret_pkcs8_der()) {
        let mut buf = [0u8; 4096];
        let spki = sk
            .public_key()
            .to_spki_der(&mut buf)
            .map_err(|_| KeygenError::Backend("graviola: rsa to_spki"))?
            .to_vec();
        return Ok(PublicKey(SubjectPublicKeyInfoDer::from(spki).into_owned()));
    }

    // Try ECDSA P-256
    if let Ok(sk) = EcdsaSigningKey::<P256>::from_pkcs8_der(pkcs8.secret_pkcs8_der()) {
        let mut buf = [0u8; 512];
        let spki = sk
            .to_spki_der(&mut buf)
            .map_err(|_| KeygenError::Backend("graviola: p256 to_spki"))?
            .to_vec();
        return Ok(PublicKey(SubjectPublicKeyInfoDer::from(spki).into_owned()));
    }

    // Try ECDSA P-384
    if let Ok(sk) = EcdsaSigningKey::<P384>::from_pkcs8_der(pkcs8.secret_pkcs8_der()) {
        let mut buf = [0u8; 512];
        let spki = sk
            .to_spki_der(&mut buf)
            .map_err(|_| KeygenError::Backend("graviola: p384 to_spki"))?
            .to_vec();
        return Ok(PublicKey(SubjectPublicKeyInfoDer::from(spki).into_owned()));
    }

    // Try Ed25519
    {
        use graviola::signing::eddsa::Ed25519SigningKey;
        if let Ok(sk) = Ed25519SigningKey::from_pkcs8_der(pkcs8.secret_pkcs8_der()) {
            let mut buf = [0u8; 128];
            let spki = sk
                .public_key()
                .to_spki_der(&mut buf)
                .map_err(|_| KeygenError::Backend("graviola: ed25519 to_spki"))?
                .to_vec();
            return Ok(PublicKey(SubjectPublicKeyInfoDer::from(spki).into_owned()));
        }
    }

    Err(KeygenError::Unsupported(
        "graviola: unsupported key in PKCS#8",
    ))
}

pub(super) fn spki_oid_supported(oid: &str) -> bool {
    // Graviola supports Ed25519 for peer identities.
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
    fn gen_ecdsa_p256() {
        let params = EcdsaKeygenParams::EcdsaP256Sha256;
        let priv_key = gen_key_ecdsa(params).expect("ecdsa-p256");
        let pub_key = priv_key.derive_pub_key().expect("spki");
        assert!(!priv_key.0.secret_pkcs8_der().is_empty());
        let _ = SubjectPublicKeyInfoRef::from_der(pub_key.0.as_ref()).expect("spki parse");
    }

    #[test]
    fn gen_ed25519_uses_pkcs8_v1() {
        let priv_key = gen_key_ed25519().expect("ed25519");
        let der = priv_key.0.secret_pkcs8_der();

        assert_eq!(
            &der[..16],
            b"\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20"
        );
        assert_eq!(der.len(), 48);
        let _ = priv_key.derive_pub_key().expect("spki");
    }
}
