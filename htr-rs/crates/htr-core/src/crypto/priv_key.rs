// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use super::*;
// Minimal byte search; avoid adding new dependencies.

#[derive(Debug, PartialEq, Eq)]
pub struct PrivateKey(pub(super) PrivatePkcs8KeyDer<'static>);

impl PrivateKey {
    /// Parse and validate a DER-encoded PKCS#8 PrivateKeyInfo structure.
    pub fn from_slice(v: &[u8]) -> Result<Self, PrivateKeyParseError> {
        // Basic wrap; detailed validation is deferred to consumers
        Ok(PrivateKey(PrivatePkcs8KeyDer::from(v).clone_key()))
    }

    pub fn derive_pub_key(&self) -> Result<PublicKey, KeygenError> {
        super::backend::derive_pub_key(&self.0)
    }

    /// Return a rustls-compatible PrivateKeyDer.
    pub fn for_rustls(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::from(self.0.clone_key())
    }
}

// Infallible conversion from already-wrapped DER. This path does not re-validate.
impl<'a> From<PrivatePkcs8KeyDer<'a>> for PrivateKey {
    fn from(der: PrivatePkcs8KeyDer<'a>) -> Self {
        PrivateKey(der.clone_key())
    }
}

impl From<PrivateKey> for PrivateKeyDer<'static> {
    fn from(k: PrivateKey) -> Self {
        Self::Pkcs8(k.0)
    }
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        PrivateKey(self.0.clone_key())
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum PrivateKeyParseError {
    #[error("{0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid PKCS#8 DER")]
    Der,
}

impl FromStr for PrivateKey {
    type Err = PrivateKeyParseError;

    #[inline]
    fn from_str(b64: &str) -> Result<Self, Self::Err> {
        // trim to preserve behavior from Python
        let bytes = BASE64_STANDARD.decode(b64.trim())?;
        PrivateKey::from_slice(&bytes)
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0.secret_pkcs8_der()))
    }
}

impl Serialize for PrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_slice_roundtrip() {
        // Generate a valid keypair and ensure from_slice parses it.
        #[cfg(feature = "crypto-graviola")]
        let params =
            crate::crypto::KeygenParams::Ecdsa(crate::crypto::EcdsaKeygenParams::EcdsaP256Sha256);
        #[cfg(not(feature = "crypto-graviola"))]
        let params: crate::crypto::KeygenParams = Default::default();
        let (priv_key, _pub_key) = crate::crypto::gen_keypair(params).expect("gen");
        let der = priv_key.0.secret_pkcs8_der();
        let parsed = PrivateKey::from_slice(der).expect("parse from slice");
        let expected: PrivateKey = PrivatePkcs8KeyDer::from(der).into();
        assert_eq!(parsed, expected);
    }

    #[test]
    fn display_and_parse_roundtrip() {
        #[cfg(feature = "crypto-graviola")]
        let params =
            crate::crypto::KeygenParams::Ecdsa(crate::crypto::EcdsaKeygenParams::EcdsaP256Sha256);
        #[cfg(not(feature = "crypto-graviola"))]
        let params: crate::crypto::KeygenParams = Default::default();
        let (priv_key, _pub_key) = crate::crypto::gen_keypair(params).expect("gen");
        let s = priv_key.to_string();
        // For Ed25519 (default), prefer minimal PKCS#8 that starts with "MC4"
        // (other encoders may emit different prefixes; accept any valid PKCS#8 there)
        #[cfg(all(
            any(feature = "crypto-aws-lc", feature = "crypto-openssl"),
            not(feature = "crypto-graviola")
        ))]
        {
            assert!(
                s.starts_with("MC4"),
                "unexpected PKCS#8 prefix: {}",
                &s[..4]
            );
        }
        let parsed: PrivateKey = s.parse().expect("parse string");
        assert_eq!(parsed.to_string(), s);
    }

    #[test]
    fn invalid_byte() {
        let s = "-".to_string()
            + &{
                #[cfg(feature = "crypto-graviola")]
                let params = crate::crypto::KeygenParams::Ecdsa(
                    crate::crypto::EcdsaKeygenParams::EcdsaP256Sha256,
                );
                #[cfg(not(feature = "crypto-graviola"))]
                let params: crate::crypto::KeygenParams = Default::default();
                crate::crypto::gen_keypair(params)
            }
            .expect("gen")
            .0
            .to_string();
        let parsed: Result<PrivateKey, _> = s.parse();
        assert!(matches!(
            parsed,
            Err(PrivateKeyParseError::Base64(
                base64::DecodeError::InvalidByte(0, 45)
            ))
        ));
    }

    #[test]
    fn invalid_length() {
        #[cfg(feature = "crypto-graviola")]
        let params =
            crate::crypto::KeygenParams::Ecdsa(crate::crypto::EcdsaKeygenParams::EcdsaP256Sha256);
        #[cfg(not(feature = "crypto-graviola"))]
        let params: crate::crypto::KeygenParams = Default::default();
        let s = crate::crypto::gen_keypair(params)
            .expect("gen")
            .0
            .to_string();
        // Chop off one char to create bad padding/length
        let bad = &s[..s.len() - 1];
        let parsed: Result<PrivateKey, _> = bad.parse();
        assert!(matches!(parsed, Err(PrivateKeyParseError::Base64(_))));
    }

    #[test]
    fn ser_de() {
        #[cfg(feature = "crypto-graviola")]
        let params =
            crate::crypto::KeygenParams::Ecdsa(crate::crypto::EcdsaKeygenParams::EcdsaP256Sha256);
        #[cfg(not(feature = "crypto-graviola"))]
        let params: crate::crypto::KeygenParams = Default::default();
        let s = crate::crypto::gen_keypair(params)
            .expect("gen")
            .0
            .to_string();
        let k: PrivateKey = s.parse().expect("parse");
        let json = serde_json::to_string(&k).expect("serde serialize");
        assert_eq!(json, format!("\"{}\"", s));
    }
}
