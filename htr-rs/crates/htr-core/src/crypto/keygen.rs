// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use super::*;
use clap::ValueEnum;
use clap::builder::PossibleValue;
use std::str::FromStr;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum EcdsaKeygenParams {
    #[default]
    EcdsaP256Sha256,
    EcdsaP384Sha384,
}

impl EcdsaKeygenParams {}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum RsaKeygenParams {
    #[default]
    Rsa2048,
    Rsa3072,
    Rsa4096,
}

impl RsaKeygenParams {}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub enum KeygenParams {
    #[default]
    Ed25519,
    Ecdsa(EcdsaKeygenParams),
    Rsa(RsaKeygenParams),
}

impl KeygenParams {}

impl ValueEnum for KeygenParams {
    fn value_variants<'a>() -> &'a [Self] {
        // Full set of exposed values (with aliases added in to_possible_value)
        static VARIANTS: [KeygenParams; 6] = [
            KeygenParams::Ed25519,
            KeygenParams::Ecdsa(EcdsaKeygenParams::EcdsaP256Sha256),
            KeygenParams::Ecdsa(EcdsaKeygenParams::EcdsaP384Sha384),
            KeygenParams::Rsa(RsaKeygenParams::Rsa2048),
            KeygenParams::Rsa(RsaKeygenParams::Rsa3072),
            KeygenParams::Rsa(RsaKeygenParams::Rsa4096),
        ];
        &VARIANTS
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        let pv = match *self {
            KeygenParams::Ed25519 => PossibleValue::new("ed25519"),
            KeygenParams::Ecdsa(EcdsaKeygenParams::EcdsaP256Sha256) => {
                PossibleValue::new("ecdsa-p256")
            }
            KeygenParams::Ecdsa(EcdsaKeygenParams::EcdsaP384Sha384) => {
                PossibleValue::new("ecdsa-p384")
            }
            KeygenParams::Rsa(RsaKeygenParams::Rsa2048) => PossibleValue::new("rsa-2048"),
            KeygenParams::Rsa(RsaKeygenParams::Rsa3072) => PossibleValue::new("rsa-3072"),
            KeygenParams::Rsa(RsaKeygenParams::Rsa4096) => PossibleValue::new("rsa-4096"),
        };
        Some(pv)
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[error("unsupported algo: {0}")]
pub struct KeygenParamsParseError(pub String);

impl FromStr for KeygenParams {
    type Err = KeygenParamsParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = s.trim().to_ascii_lowercase();
        Ok(match v.as_str() {
            "ed25519" => KeygenParams::Ed25519,
            "ecdsa" => KeygenParams::Ecdsa(Default::default()),
            "ecdsa-p256" => KeygenParams::Ecdsa(EcdsaKeygenParams::EcdsaP256Sha256),
            "ecdsa-p384" => KeygenParams::Ecdsa(EcdsaKeygenParams::EcdsaP384Sha384),
            "rsa" => KeygenParams::Rsa(Default::default()),
            "rsa-2048" => KeygenParams::Rsa(RsaKeygenParams::Rsa2048),
            "rsa-3072" => KeygenParams::Rsa(RsaKeygenParams::Rsa3072),
            "rsa-4096" => KeygenParams::Rsa(RsaKeygenParams::Rsa4096),
            other => return Err(KeygenParamsParseError(other.to_string())),
        })
    }
}

#[derive(Debug, Error)]
pub enum KeygenError {
    #[error("unsupported in current crypto backend: {0}")]
    Unsupported(&'static str),
    #[error("backend key generation failed: {0}")]
    Backend(&'static str),
    #[error("failed to parse generated certificate for SPKI")]
    X509,
}

#[inline(always)]
fn gen_priv_key(params: KeygenParams) -> Result<PrivateKey, KeygenError> {
    backend::gen_priv_key(params)
}

pub fn gen_keypair(params: KeygenParams) -> Result<(PrivateKey, PublicKey), KeygenError> {
    let private_key = gen_priv_key(params)?;
    let public_key = private_key.derive_pub_key()?;
    Ok((private_key, public_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use der::Decode;
    use spki::SubjectPublicKeyInfoRef;

    #[test]
    fn keygen_spki_parses_for_supported_algs() {
        // Build the table of supported algorithms for this build.
        let mut cases: Vec<KeygenParams> = vec![
            KeygenParams::Ecdsa(EcdsaKeygenParams::EcdsaP256Sha256),
            KeygenParams::Ecdsa(EcdsaKeygenParams::EcdsaP384Sha384),
        ];

        // Ed25519 supported by aws-lc and openssl backends (not graviola)
        #[cfg(any(feature = "crypto-aws-lc", feature = "crypto-openssl"))]
        {
            cases.push(KeygenParams::Ed25519);
        }

        // RSA supported on aws-lc, openssl, and graviola (via graviola)
        #[cfg(any(
            feature = "crypto-aws-lc",
            feature = "crypto-openssl",
            feature = "crypto-graviola"
        ))]
        {
            cases.push(KeygenParams::Rsa(RsaKeygenParams::Rsa2048));
            cases.push(KeygenParams::Rsa(RsaKeygenParams::Rsa3072));
            cases.push(KeygenParams::Rsa(RsaKeygenParams::Rsa4096));
        }

        for params in cases {
            let (private_key, public_key) = gen_keypair(params)
                .unwrap_or_else(|e| panic!("keygen failed for {:?}: {}", params, e));
            let priv_der = private_key.0;
            let spki = public_key.0;
            assert!(!priv_der.secret_pkcs8_der().is_empty());
            // Parse SPKI to validate shape/OIDs/bitstring
            let _ = SubjectPublicKeyInfoRef::from_der(spki.as_ref()).expect("valid SPKI");
        }
    }

    #[cfg(feature = "crypto-graviola")]
    #[test]
    fn rsa_supported_on_graviola_for_all_sizes() {
        for params in [
            RsaKeygenParams::Rsa2048,
            RsaKeygenParams::Rsa3072,
            RsaKeygenParams::Rsa4096,
        ] {
            let (priv_key, pub_key) = gen_keypair(KeygenParams::Rsa(params))
                .unwrap_or_else(|e| panic!("RSA {:?} failed: {}", params, e));
            assert!(!priv_key.0.secret_pkcs8_der().is_empty());
            assert!(!pub_key.0.as_ref().is_empty());
        }
    }

    #[cfg(feature = "crypto-openssl")]
    #[test]
    fn rsa_supported_on_openssl_for_all_sizes() {
        for params in [
            RsaKeygenParams::Rsa2048,
            RsaKeygenParams::Rsa3072,
            RsaKeygenParams::Rsa4096,
        ] {
            let (priv_key, pub_key) = gen_keypair(KeygenParams::Rsa(params))
                .unwrap_or_else(|e| panic!("RSA {:?} failed: {}", params, e));
            assert!(!priv_key.0.secret_pkcs8_der().is_empty());
            assert!(!pub_key.0.as_ref().is_empty());
        }
    }
}
