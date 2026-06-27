// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerifier};
use rustls::client::verify_server_cert_signed_by_trust_anchor;
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{self, RootCertStore};
use std::sync::Arc;

#[derive(Debug)]
pub struct NoSanVerification {
    roots: Arc<RootCertStore>,
}

impl NoSanVerification {
    pub fn new(roots: Arc<RootCertStore>) -> Self {
        Self { roots }
    }
}

impl ServerCertVerifier for NoSanVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Provide a clearer error when the selected backend does not support the
        // server certificate's public key algorithm (e.g., Ed25519 under graviola).
        // Do not attempt to reject based on SPKI OID here; rely on the selected
        // rustls provider to validate and handle algorithm support. This keeps
        // behavior consistent across backends (including forks that add new algs).
        // Verify chain, validity, and key usage against our roots, but ignore SAN/hostname.
        let cert = ParsedCertificate::try_from(end_entity)?;
        // Use the currently installed default provider to select verification algorithms
        let provider = CryptoProvider::get_default()
            .map(Arc::clone)
            .unwrap_or_else(|| Arc::new(crate::crypto::rustls_preferred_provider()));

        verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            provider.signature_verification_algorithms.all,
        )?;
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let provider = CryptoProvider::get_default()
            .map(Arc::clone)
            .unwrap_or_else(|| Arc::new(crate::crypto::rustls_preferred_provider()));
        verify_tls12_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        let provider = CryptoProvider::get_default()
            .map(Arc::clone)
            .unwrap_or_else(|| Arc::new(crate::crypto::rustls_preferred_provider()));
        verify_tls13_signature(
            message,
            cert,
            dss,
            &provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        let provider = CryptoProvider::get_default()
            .map(Arc::clone)
            .unwrap_or_else(|| Arc::new(crate::crypto::rustls_preferred_provider()));
        provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ensure_provider() {
        crate::ensure_default_crypto_provider();
    }
    use crate::ca;
    use crate::peer::*;
    use rustls_pki_types::{PrivateKeyDer, ServerName};
    use std::sync::Arc;
    use tokio::io::duplex;
    use tokio::time::{Duration, timeout};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    // Common handshake runner used by tests. Accepts already built acceptor and connector.
    async fn handshake_with(
        acceptor: TlsAcceptor,
        connector: TlsConnector,
    ) -> (Result<(), std::io::Error>, Result<(), std::io::Error>) {
        let (cli_io, srv_io) = duplex(16 * 1024);
        let join = async {
            tokio::join!(
                acceptor.accept(srv_io),
                connector.connect(
                    ServerName::IpAddress(
                        std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)).into(),
                    ),
                    cli_io,
                )
            )
        };
        let (srv_res, cli_res) = timeout(Duration::from_secs(5), join)
            .await
            .expect("handshake timed out");
        (srv_res.map(|_| ()), cli_res.map(|_| ()))
    }

    fn make_good_acceptor() -> TlsAcceptor {
        let peer = PrivatePeer::example();
        let cfg = peer.gen_server_config().unwrap();
        TlsAcceptor::from(cfg)
    }

    fn make_good_connector() -> TlsConnector {
        let peer = PrivatePeer::example();
        let cfg = peer.gen_client_config().unwrap();
        TlsConnector::from(cfg)
    }

    fn make_wrong_acceptor() -> TlsAcceptor {
        use crate::ca::CertificateBuilder;
        use crate::crypto::{KeygenParams, RsaKeygenParams, gen_keypair};

        // Generate an unrelated RSA keypair and sign a bogus certificate with it.
        let (wrong_priv, wrong_pub) =
            gen_keypair(KeygenParams::Rsa(RsaKeygenParams::Rsa2048)).unwrap();
        let wrong_srv_cert =
            CertificateBuilder::new(wrong_pub).build_with_ca(&crate::ca::CA_CERT, &wrong_priv.0);
        let wrong_srv_key: PrivateKeyDer<'static> = wrong_priv.clone().into();
        let cfg = rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_no_client_auth()
            .with_single_cert(vec![wrong_srv_cert], wrong_srv_key)
            .unwrap();
        TlsAcceptor::from(Arc::new(cfg))
    }

    fn make_wrong_connector() -> TlsConnector {
        use crate::ca::CertificateBuilder;
        use crate::crypto::{KeygenParams, RsaKeygenParams, gen_keypair};

        // Generate an unrelated RSA keypair and sign a bogus certificate with it.
        let (wrong_priv, wrong_pub) =
            gen_keypair(KeygenParams::Rsa(RsaKeygenParams::Rsa2048)).unwrap();
        let wrong_client_cert =
            CertificateBuilder::new(wrong_pub).build_with_ca(&crate::ca::CA_CERT, &wrong_priv.0);
        let wrong_client_key: PrivateKeyDer<'static> = wrong_priv.clone().into();
        // Client trusts the real CA (so server cert is validated), but presents
        // an unrelated client certificate.
        let cfg = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
            .with_root_certificates(ca::ROOT_STORE.as_ref().clone())
            .with_client_auth_cert(vec![wrong_client_cert], wrong_client_key)
            .unwrap();
        TlsConnector::from(Arc::new(cfg))
    }

    // Test 1: client is built via PrivatePeer.gen_client_config but the server presents
    // an invalid (untrusted) certificate. The handshake should fail.
    // If this test fails, it indicates a bug in gen_client_config.
    #[tokio::test]
    async fn client_built_config_rejects_wrong_server_cert() {
        ensure_provider();
        let acceptor = make_wrong_acceptor();
        let connector = make_good_connector();
        let (srv_res, cli_res) = handshake_with(acceptor, connector).await;
        assert!(
            srv_res.is_err(),
            "server handshake should fail: {:?}",
            srv_res
        );
        assert!(
            cli_res.is_err(),
            "client handshake should fail: {:?}",
            cli_res
        );
    }

    // Test 2: server is built via build_server_config with a valid certificate,
    // but the client presents a wrong certificate. The handshake should fail
    // if the server requires/validates client auth. If it succeeds, it reveals
    // a bug (server not enforcing client auth).
    #[tokio::test]
    async fn server_built_config_rejects_wrong_client_cert() {
        ensure_provider();
        let acceptor = make_good_acceptor();
        let connector = make_wrong_connector();
        let (srv_res, cli_res) = handshake_with(acceptor, connector).await;
        assert!(
            srv_res.is_err(),
            "server handshake should fail: {:?}",
            srv_res
        );
        assert!(
            cli_res.is_err(),
            "client handshake should fail: {:?}",
            cli_res
        );
    }

    // Sanity check: a handshake should succeed when both client and server
    // are built using the crate helpers with the same trusted CA.
    #[tokio::test]
    async fn handshake_succeeds_with_built_client_and_server() {
        ensure_provider();
        let acceptor = make_good_acceptor();
        let connector = make_good_connector();
        let (srv_res, cli_res) = handshake_with(acceptor, connector).await;
        assert!(
            srv_res.is_ok(),
            "server handshake should succeed: {:?}",
            srv_res
        );
        assert!(
            cli_res.is_ok(),
            "client handshake should succeed: {:?}",
            cli_res
        );
    }
}
