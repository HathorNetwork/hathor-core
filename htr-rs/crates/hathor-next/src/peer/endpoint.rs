// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use super::PeerId;
use crate::common::Hash32ParseError;
use http::uri;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::ops::Deref;
use std::str::FromStr;
use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("invalid URI")]
    InvalidUri(#[from] uri::InvalidUri),
    #[error("invalid peer-id")]
    InvalidPeerId(#[from] Hash32ParseError),
    #[error("could not parse host")]
    HostParse(#[from] url::ParseError),
    #[error("protocol scheme not supported")]
    InvalidProtocol,
    #[error("host not specified")]
    MissingHost,
    #[error("port not specified")]
    MissingPort,
    #[error("multiple peer-id's in query string")]
    MultiplePeerIds,
    #[error("invalid query param")]
    InvalidQueryParam,
    #[error("URI must not have a username/password/path/fragment")]
    UnexpectedComponent,
    #[error("peer-address must not have a peer-id")]
    UnexpectedPeerId,
}

type Host = url::Host<String>;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Protocol {
    Tcp,
    #[cfg(feature = "transport-quic")]
    Quic,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.scheme())
    }
}

impl Protocol {
    pub fn scheme(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            #[cfg(feature = "transport-quic")]
            Protocol::Quic => "quic",
        }
    }

    fn from_scheme(s: &str) -> Option<Self> {
        match s {
            "tcp" => Some(Protocol::Tcp),
            #[cfg(feature = "transport-quic")]
            "quic" => Some(Protocol::Quic),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerAddress {
    protocol: Protocol,
    host: Host,
    port: u16,
}

impl PeerAddress {
    pub fn from_socket_tcp(addr: SocketAddr) -> Self {
        Self::from_socket_protocol(addr, Protocol::Tcp)
    }

    #[cfg(feature = "transport-quic")]
    pub fn from_socket_quic(addr: SocketAddr) -> Self {
        Self::from_socket_protocol(addr, Protocol::Quic)
    }

    pub fn from_socket_protocol(addr: SocketAddr, protocol: Protocol) -> Self {
        let (host, port) = match addr {
            SocketAddr::V4(addr) => (Host::Ipv4(*addr.ip()), addr.port()),
            SocketAddr::V6(addr) => (Host::Ipv6(*addr.ip()), addr.port()),
        };
        Self {
            protocol,
            host,
            port,
        }
    }

    pub fn with_id(self, peer_id: PeerId) -> PeerEndpoint {
        PeerEndpoint {
            address: self,
            peer_id: Some(peer_id),
        }
    }

    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn host_string(&self) -> String {
        format!("{}", self.host)
    }

    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        match &self.host {
            Host::Ipv4(ip) => Some(SocketAddr::new(IpAddr::V4(*ip), self.port)),
            Host::Ipv6(ip) => Some(SocketAddr::new(IpAddr::V6(*ip), self.port)),
            Host::Domain(_) => None,
        }
    }

    pub fn authority(&self) -> String {
        match &self.host {
            Host::Ipv6(ip) => format!("[{}]:{}", ip, self.port),
            _ => format!("{}:{}", self.host, self.port),
        }
    }

    /// None means the host is a domain and would need name resolution to decide if it's IPv6
    pub fn is_ipv6(&self) -> Option<bool> {
        match self.host {
            Host::Domain(_) => None,
            Host::Ipv4(_) => Some(false),
            Host::Ipv6(_) => Some(true),
        }
    }

    /// None means the host is a domain and would need name resolution to decide if it's IPv4
    pub fn is_ipv4(&self) -> Option<bool> {
        match self.host {
            Host::Domain(_) => None,
            Host::Ipv4(_) => Some(true),
            Host::Ipv6(_) => Some(false),
        }
    }
}

impl From<PeerEndpoint> for PeerAddress {
    fn from(peer_endpoint: PeerEndpoint) -> Self {
        peer_endpoint.address
    }
}

impl FromStr for PeerAddress {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let endpoint = s.parse::<PeerEndpoint>()?;
        if endpoint.peer_id.is_some() {
            return Err(Error::UnexpectedPeerId);
        }
        Ok(endpoint.into())
    }
}

impl fmt::Display for PeerAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}:{}/", self.protocol, self.host, self.port)
    }
}

impl Serialize for PeerAddress {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PeerAddress {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PeerEndpoint {
    address: PeerAddress,
    peer_id: Option<PeerId>,
}

impl PeerEndpoint {
    pub fn peer_id(&self) -> Option<&PeerId> {
        (&self.peer_id).into()
    }

    pub fn address(&self) -> &PeerAddress {
        &self.address
    }
}

impl fmt::Display for PeerEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)?; // always ends with "/"
        if let Some(ref peer_id) = self.peer_id {
            write!(f, "?id={}", peer_id)?;
        }
        Ok(())
    }
}

impl TryFrom<&uri::Uri> for PeerEndpoint {
    type Error = Error;
    fn try_from(uri: &uri::Uri) -> Result<Self, Self::Error> {
        if uri.path() != "/" {
            return Err(Error::UnexpectedComponent);
        }
        let scheme = uri.scheme_str().ok_or(Error::InvalidProtocol)?;
        let protocol = Protocol::from_scheme(scheme).ok_or(Error::InvalidProtocol)?;
        let authority = uri.authority().ok_or(Error::MissingHost)?;
        if authority.as_str().contains("@") {
            return Err(Error::UnexpectedComponent);
        }
        let host = Host::parse(authority.host())?;
        let port = authority.port_u16().ok_or(Error::MissingPort)?;
        let address = PeerAddress {
            protocol,
            host,
            port,
        };
        let peer_id = if let Some(query) = uri.query() {
            let mut peer_id: Option<PeerId> = None;
            for (key, value) in form_urlencoded::parse(query.as_bytes()) {
                match key.as_ref() {
                    "id" => {
                        if peer_id.is_some() {
                            return Err(Error::MultiplePeerIds);
                        }
                        peer_id.replace(value.parse()?);
                    }
                    _ => return Err(Error::InvalidQueryParam),
                }
            }
            peer_id
        } else {
            None
        };
        Ok(Self { address, peer_id })
    }
}

impl FromStr for PeerEndpoint {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.contains("#") {
            return Err(Error::UnexpectedComponent);
        }
        let normalized = if s.contains("://") {
            s.to_string()
        } else {
            format!("tcp://{}", s)
        };
        Self::try_from(&normalized.parse::<uri::Uri>()?)
    }
}

impl From<PeerAddress> for PeerEndpoint {
    fn from(address: PeerAddress) -> Self {
        Self {
            address,
            peer_id: None,
        }
    }
}

impl Deref for PeerEndpoint {
    type Target = PeerAddress;

    fn deref(&self) -> &Self::Target {
        &self.address
    }
}

impl Serialize for PeerEndpoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PeerEndpoint {
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
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ser_de_peer_endpoint() {
        use serde_test::*;
        assert_tokens(
            &PeerEndpoint {
                address: PeerAddress {
                    protocol: Protocol::Tcp,
                    host: Host::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
                    port: 40403,
                },
                peer_id: Some(
                    "c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696"
                        .parse()
                        .expect("should parse"),
                ),
            },
            &[Token::Str(
                "tcp://127.0.0.1:40403/?id=c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696",
            )],
        );
        assert_tokens(
            &PeerEndpoint {
                address: PeerAddress {
                    protocol: Protocol::Tcp,
                    host: Host::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
                    port: 40403,
                },
                peer_id: None,
            },
            &[Token::Str("tcp://127.0.0.1:40403/")],
        );
        let foo = PeerEndpoint {
            address: PeerAddress {
                protocol: Protocol::Tcp,
                host: Host::Domain("foo".into()),
                port: 111,
            },
            peer_id: None,
        };
        assert_tokens(&foo, &[Token::Str("tcp://foo:111/")]);
        assert_de_tokens(&foo, &[Token::Str("tcp://foo:111")]);
        assert_tokens(
            &PeerEndpoint {
                address: PeerAddress {
                    protocol: Protocol::Tcp,
                    host: Host::Ipv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
                    port: 111,
                },
                peer_id: None,
            },
            &[Token::Str("tcp://[::1]:111/")],
        );
    }

    #[test]
    fn default_scheme_is_tcp() {
        let endpoint: PeerEndpoint = "127.0.0.1:40403".parse().expect("parse host:port");
        assert_eq!(endpoint.address.protocol(), Protocol::Tcp);
        assert_eq!(endpoint.to_string(), "tcp://127.0.0.1:40403/");
    }

    #[cfg(feature = "transport-quic")]
    #[test]
    fn parse_quic_endpoint_roundtrip() {
        let endpoint: PeerEndpoint = "quic://127.0.0.1:4444/".parse().expect("parse quic");
        assert_eq!(endpoint.address.protocol(), Protocol::Quic);
        assert_eq!(endpoint.to_string(), "quic://127.0.0.1:4444/");
    }

    #[cfg(not(feature = "transport-quic"))]
    #[test]
    fn quic_scheme_rejected_without_feature() {
        let err = "quic://127.0.0.1:4444/"
            .parse::<PeerEndpoint>()
            .expect_err("quic scheme should be rejected");
        assert!(matches!(err, Error::InvalidProtocol));
    }
}
