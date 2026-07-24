// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::sync::LazyLock;
use time::{Duration, OffsetDateTime};

use rand;
use std::sync::Arc;
use thiserror::Error;

// ASN.1/PKIX structure-only crates for building X.509 certificates without
// pulling in any crypto. Signing is delegated to the selected backend.
use der::asn1::{BitString, ObjectIdentifier, UtcTime};
use der::referenced::RefToOwned;
use der::{Any, Decode, Encode};
use spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned, SubjectPublicKeyInfoRef};
use x509_cert::certificate::Version;
use x509_cert::ext::ToExtension;
use x509_cert::ext::pkix::{BasicConstraints, ExtendedKeyUsage, KeyUsage, KeyUsages};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::time::{Time, Validity};

#[derive(Error, Debug)]
pub enum Error {
    #[error("from rustls")]
    Rustls(#[from] rustls::Error),
    #[error("I/O error")]
    Io(#[from] std::io::Error),
}

static SUBJECT_NAME: &str = "Hathor full node";
const OFFSET_NOT_BEFORE: Duration = Duration::hours(1);
// 10 years
const OFFSET_NOT_AFTER: Duration = Duration::days(3_650);

const CA_CERT_DER_BYTES: &[u8] = include_bytes!("ca.cert.der");
const CA_KEY_DER_BYTES: &[u8] = include_bytes!("ca.key.der");

#[derive(der::Sequence)]
struct EncodedTbsCertificate {
    #[asn1(context_specific = "0", default = "Default::default")]
    version: Version,
    serial_number: SerialNumber,
    signature: AlgorithmIdentifierOwned,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfoOwned,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    issuer_unique_id: Option<BitString>,
    #[asn1(context_specific = "2", tag_mode = "IMPLICIT", optional = "true")]
    subject_unique_id: Option<BitString>,
    #[asn1(context_specific = "3", tag_mode = "EXPLICIT", optional = "true")]
    extensions: Option<x509_cert::ext::Extensions>,
}

#[derive(der::Sequence)]
struct EncodedCertificate {
    tbs_certificate: EncodedTbsCertificate,
    signature_algorithm: AlgorithmIdentifierOwned,
    signature: BitString,
}

// CertificateDer exposes a const fn from_slice, so we can use a plain static.
pub static CA_CERT: CertificateDer<'static> = CertificateDer::from_slice(CA_CERT_DER_BYTES);

// PrivatePkcs8KeyDer does not provide a const constructor; initialize once on first use.
pub static CA_KEY: LazyLock<PrivatePkcs8KeyDer<'static>> =
    LazyLock::new(|| PrivatePkcs8KeyDer::from(CA_KEY_DER_BYTES));

// Root trust store containing the embedded CA certificate
pub static ROOT_STORE: LazyLock<Arc<RootCertStore>> = LazyLock::new(|| {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_slice(CA_CERT.as_ref()))
        .expect("add embedded CA to root store");
    Arc::new(roots)
});

pub struct CertificateBuilder {
    pubkey: crate::crypto::PublicKey,
    timestamp: Option<OffsetDateTime>,
    serial: Option<[u8; 20]>,
}

impl CertificateBuilder {
    pub fn new(pubkey: crate::crypto::PublicKey) -> Self {
        Self {
            pubkey,
            timestamp: None,
            serial: None,
        }
    }

    pub fn timestamp(mut self, timestamp: OffsetDateTime) -> Self {
        self.timestamp.replace(timestamp);
        self
    }

    pub fn serial(mut self, serial: [u8; 20]) -> Self {
        self.serial.replace(serial);
        self
    }

    pub fn build_with_ca(
        self,
        ca_cert: &CertificateDer<'_>,
        ca_key: &PrivatePkcs8KeyDer<'static>,
    ) -> CertificateDer<'static> {
        let now = self.timestamp.unwrap_or_else(OffsetDateTime::now_utc);
        let serial = self.serial.unwrap_or_else(|| {
            let mut s: [u8; 20] = rand::random();
            s[0] >>= 1;
            s
        });

        // issuer = subject from CA certificate
        let ca =
            x509_cert::Certificate::from_der(ca_cert.as_ref()).expect("parse embedded CA cert");
        let issuer_name: Name = ca.tbs_certificate().subject().clone();

        // subject: CN=Hathor full node
        let subject_name: Name =
            core::str::FromStr::from_str(&format!("CN={}", SUBJECT_NAME)).expect("subject name");

        // SubjectPublicKeyInfo from provided SPKI DER
        let spki_ref = SubjectPublicKeyInfoRef::try_from(self.pubkey.as_der()).expect("valid SPKI");
        let spki_owned: SubjectPublicKeyInfoOwned = spki_ref.ref_to_owned();

        // Validity (use GeneralizedTime for wide range)
        let nb_secs = (now - OFFSET_NOT_BEFORE).unix_timestamp();
        let na_secs = (now + OFFSET_NOT_AFTER).unix_timestamp();
        let not_before = Time::UtcTime(
            UtcTime::from_unix_duration(std::time::Duration::from_secs(nb_secs as u64))
                .expect("nb"),
        );
        let not_after = Time::UtcTime(
            UtcTime::from_unix_duration(std::time::Duration::from_secs(na_secs as u64))
                .expect("na"),
        );
        let validity = Validity::new(not_before, not_after);

        // Signature algorithm: sha256WithRSAEncryption (1.2.840.113549.1.1.11) with NULL params
        let sig_oid = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
        let sig_alg: AlgorithmIdentifierOwned = AlgorithmIdentifierOwned {
            oid: sig_oid,
            parameters: Some(Any::from(der::asn1::Null)),
        };

        // Build TBSCertificate v1
        // X.509 v3 extensions suitable for both TLS server and client auth
        let mut extensions = x509_cert::ext::Extensions::new();
        // BasicConstraints: CA = false
        extensions.push(
            BasicConstraints {
                ca: false,
                path_len_constraint: None,
            }
            .to_extension(&subject_name, &extensions)
            .expect("ext: basic_constraints"),
        );
        // KeyUsage: digitalSignature (+ keyEncipherment for RSA)
        extensions.push(
            KeyUsage(KeyUsages::DigitalSignature.into())
                .to_extension(&subject_name, &extensions)
                .expect("ext: key_usage"),
        );
        // ExtendedKeyUsage: serverAuth + clientAuth
        let kp_serverauth = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.1");
        let kp_clientauth = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.3.2");
        extensions.push(
            ExtendedKeyUsage(vec![kp_serverauth, kp_clientauth])
                .to_extension(&subject_name, &extensions)
                .expect("ext: extended_key_usage"),
        );

        let tbs = EncodedTbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&serial).expect("serial"),
            signature: sig_alg.clone(),
            issuer: issuer_name,
            validity,
            subject: subject_name,
            subject_public_key_info: spki_owned,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: Some(extensions),
        };
        let tbs_der = tbs.to_der().expect("encode tbs");

        // Sign TBS with backend RSA/SHA256
        let sig = crate::crypto::x509_rsa_sha256_sign(ca_key, &tbs_der).expect("rsa sign");

        // Assemble final certificate
        let signature = BitString::new(0, sig).expect("bitstring");
        let cert = EncodedCertificate {
            tbs_certificate: tbs,
            signature_algorithm: sig_alg,
            signature,
        };
        let cert_der = cert.to_der().expect("encode cert");
        CertificateDer::from(cert_der)
    }

    pub fn build(self) -> CertificateDer<'static> {
        self.build_with_ca(&CA_CERT, &CA_KEY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::PrivatePeer;
    use ::time::{Date, Month};
    use x509_cert::certificate::Certificate;

    #[test]
    fn parse_ca_certificate() {
        let _ca = Certificate::from_der(CA_CERT.as_ref()).expect("parse ca");
    }

    #[test]
    fn certificate_with_timestamp() {
        let now = OffsetDateTime::new_utc(
            Date::from_calendar_date(2025, Month::January, 7).unwrap(),
            ::time::Time::from_hms(14, 15, 5).unwrap(),
        );
        let peer = PrivatePeer::example();
        let cert_der = CertificateBuilder::new(peer.get_public_key_der())
            .timestamp(now)
            .build();
        let _cert = Certificate::from_der(cert_der.as_ref()).expect("parse built");
    }
}
