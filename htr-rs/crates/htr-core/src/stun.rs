// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use rand::Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use thiserror::Error;
use tokio::{net::UdpSocket, time};

const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS_RESPONSE: u16 = 0x0101;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("timeout waiting for STUN response")]
    Timeout,
    #[error("STUN server lookup returned no addresses")]
    NoResolvedAddrs,
    #[error("unexpected STUN response type {0:#06x}")]
    UnexpectedResponse(u16),
    #[error("response validation failed: {0}")]
    Invalid(&'static str),
    #[error("missing MAPPED-ADDRESS attribute in STUN response")]
    MissingMappedAddress,
    #[error("unsupported address family {0}")]
    UnsupportedFamily(u8),
}

/// Perform a STUN binding request against `server`, returning the observed socket address that
/// intermediaries map to. The local UDP socket is bound to `bind_addr` so the port matches the
/// advertised TCP listener. Multiple resolved addresses are attempted until one succeeds.
pub async fn discover_public_addr(
    server: &str,
    bind_addr: SocketAddr,
    timeout: Duration,
) -> Result<SocketAddr, Error> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(server)
        .await?
        .filter(|addr| {
            matches!(
                (bind_addr, *addr),
                (SocketAddr::V4(_), SocketAddr::V4(_)) | (SocketAddr::V6(_), SocketAddr::V6(_))
            )
        })
        .collect();
    if addrs.is_empty() {
        return Err(Error::NoResolvedAddrs);
    }

    let mut last_err = None;
    for addr in addrs {
        match discover_with_addr(addr, bind_addr, timeout).await {
            Ok(public_addr) => return Ok(public_addr),
            Err(err) => last_err = Some(err),
        }
    }
    Err(last_err.unwrap_or(Error::NoResolvedAddrs))
}

async fn discover_with_addr(
    server_addr: SocketAddr,
    bind_addr: SocketAddr,
    timeout: Duration,
) -> Result<SocketAddr, Error> {
    let socket = UdpSocket::bind(bind_addr).await?;

    let mut transaction_id = [0u8; 12];
    let mut rng = rand::rng();
    rng.fill_bytes(&mut transaction_id);
    let request = build_binding_request(&transaction_id);

    socket.send_to(&request, server_addr).await?;

    let mut buf = [0u8; 576];
    let recv = time::timeout(timeout, socket.recv_from(&mut buf)).await;
    let (len, _) = match recv {
        Ok(Ok(result)) => result,
        Ok(Err(err)) => return Err(Error::Io(err)),
        Err(_) => return Err(Error::Timeout),
    };

    parse_binding_response(&buf[..len], &transaction_id)
}

fn build_binding_request(transaction_id: &[u8; 12]) -> [u8; 20] {
    let mut buf = [0u8; 20];
    buf[..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    buf[2..4].copy_from_slice(&0u16.to_be_bytes());
    buf[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf[8..20].copy_from_slice(transaction_id);
    buf
}

fn parse_binding_response(data: &[u8], transaction_id: &[u8; 12]) -> Result<SocketAddr, Error> {
    if data.len() < 20 {
        return Err(Error::Invalid("response shorter than STUN header"));
    }
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != BINDING_SUCCESS_RESPONSE {
        return Err(Error::UnexpectedResponse(msg_type));
    }
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 20 + msg_len {
        return Err(Error::Invalid("response shorter than declared length"));
    }
    if data[4..8] != MAGIC_COOKIE.to_be_bytes() {
        return Err(Error::Invalid("magic cookie mismatch"));
    }
    if data[8..20] != *transaction_id {
        return Err(Error::Invalid("transaction ID mismatch"));
    }

    let mut idx = 20;
    let mut mapped = None;
    let end = 20 + msg_len;
    while idx + 4 <= end {
        let attr_type = u16::from_be_bytes([data[idx], data[idx + 1]]);
        let attr_len = u16::from_be_bytes([data[idx + 2], data[idx + 3]]) as usize;
        idx += 4;
        if idx + attr_len > end {
            return Err(Error::Invalid("attribute overruns message length"));
        }
        let value = &data[idx..idx + attr_len];
        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                mapped = Some(parse_xor_mapped_address(value, transaction_id)?);
            }
            ATTR_MAPPED_ADDRESS if mapped.is_none() => {
                mapped = Some(parse_mapped_address(value)?);
            }
            _ => {}
        }
        let pad = (4 - (attr_len % 4)) % 4;
        idx += attr_len + pad;
    }

    mapped.ok_or(Error::MissingMappedAddress)
}

fn parse_mapped_address(value: &[u8]) -> Result<SocketAddr, Error> {
    if value.len() < 4 {
        return Err(Error::Invalid("MAPPED-ADDRESS too short"));
    }
    if value[0] != 0 {
        return Err(Error::Invalid("MAPPED-ADDRESS first byte must be zero"));
    }
    let family = value[1];
    let port = u16::from_be_bytes([value[2], value[3]]);
    match family {
        0x01 => {
            if value.len() < 8 {
                return Err(Error::Invalid("MAPPED-ADDRESS/IPv4 too short"));
            }
            let octets = [value[4], value[5], value[6], value[7]];
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        0x02 => {
            if value.len() < 20 {
                return Err(Error::Invalid("MAPPED-ADDRESS/IPv6 too short"));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&value[4..20]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        other => Err(Error::UnsupportedFamily(other)),
    }
}

fn parse_xor_mapped_address(value: &[u8], transaction_id: &[u8; 12]) -> Result<SocketAddr, Error> {
    if value.len() < 4 {
        return Err(Error::Invalid("XOR-MAPPED-ADDRESS too short"));
    }
    if value[0] != 0 {
        return Err(Error::Invalid("XOR-MAPPED-ADDRESS first byte must be zero"));
    }
    let family = value[1];
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    port ^= (MAGIC_COOKIE >> 16) as u16;

    match family {
        0x01 => {
            if value.len() < 8 {
                return Err(Error::Invalid("XOR-MAPPED-ADDRESS/IPv4 too short"));
            }
            let cookie = MAGIC_COOKIE.to_be_bytes();
            let octets = [
                value[4] ^ cookie[0],
                value[5] ^ cookie[1],
                value[6] ^ cookie[2],
                value[7] ^ cookie[3],
            ];
            Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        0x02 => {
            if value.len() < 20 {
                return Err(Error::Invalid("XOR-MAPPED-ADDRESS/IPv6 too short"));
            }
            let mut mask = [0u8; 16];
            mask[..4].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
            mask[4..].copy_from_slice(transaction_id);
            let mut octets = [0u8; 16];
            for (idx, byte) in octets.iter_mut().enumerate() {
                *byte = value[4 + idx] ^ mask[idx];
            }
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        other => Err(Error::UnsupportedFamily(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4_xor_mapped_address() {
        let transaction_id = [1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
        let mut response = vec![0u8; 20 + 12];
        response[0..2].copy_from_slice(&BINDING_SUCCESS_RESPONSE.to_be_bytes());
        response[2..4].copy_from_slice(&12u16.to_be_bytes());
        response[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
        response[8..20].copy_from_slice(&transaction_id);
        response[20..22].copy_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        response[22..24].copy_from_slice(&8u16.to_be_bytes());
        // Value: 0, family IPv4
        response[24] = 0;
        response[25] = 0x01;
        let port = 4242u16 ^ ((MAGIC_COOKIE >> 16) as u16);
        response[26..28].copy_from_slice(&port.to_be_bytes());
        let cookie = MAGIC_COOKIE.to_be_bytes();
        let addr_bytes = [203u8, 0, 113, 1];
        for i in 0..4 {
            response[28 + i] = addr_bytes[i] ^ cookie[i];
        }

        let observed =
            parse_binding_response(&response, &transaction_id).expect("should parse response");
        assert_eq!(
            observed,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)), 4242)
        );
    }
}
