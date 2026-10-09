// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::array::TryFromSliceError;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;
use thiserror::Error;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    pub(crate) fn zero() -> Self {
        Self([0; 32])
    }

    pub fn from_slice(v: &[u8]) -> Result<Self, TryFromSliceError> {
        Ok(Hash32(*<&[u8; 32]>::try_from(v)?))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub(crate) fn reversed(mut self) -> Hash32 {
        self.0.reverse();
        self
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", const_hex::encode(self.0))
    }
}

impl AsRef<[u8]> for Hash32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Hash32 {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl TryFrom<&[u8]> for Hash32 {
    type Error = TryFromSliceError;
    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(v)
    }
}

#[derive(Error, Debug, PartialEq)]
pub struct Hash32ParseError {
    #[source]
    source: const_hex::FromHexError,
}

impl fmt::Display for Hash32ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.source)
    }
}

impl From<const_hex::FromHexError> for Hash32ParseError {
    fn from(source: const_hex::FromHexError) -> Self {
        Self { source }
    }
}

impl FromStr for Hash32 {
    type Err = Hash32ParseError;
    fn from_str(hex: &str) -> Result<Self, Self::Err> {
        if hex.starts_with("0x") {
            return Err(Hash32ParseError {
                source: const_hex::FromHexError::InvalidHexCharacter { c: 'x', index: 1 },
            });
        }
        Ok(Hash32(const_hex::decode_to_array(hex)?))
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", const_hex::encode(self.0))
    }
}

impl Serialize for Hash32 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Hash32 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Address(pub [u8; 25]);

impl Address {
    pub fn from_slice(v: &[u8]) -> Result<Self, TryFromSliceError> {
        Ok(Address(*<&[u8; 25]>::try_from(v)?))
    }

    pub fn as_bytes(&self) -> &[u8; 25] {
        &self.0
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Address {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl TryFrom<&[u8]> for Address {
    type Error = TryFromSliceError;
    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        Self::from_slice(v)
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum AddressParseError {
    #[error("base58 decode error: {0}")]
    Base58(#[from] bs58::decode::Error),
    #[error("invalid length: {0}")]
    InvalidLength(usize),
}

impl FromStr for Address {
    type Err = AddressParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s).into_vec()?;
        if bytes.len() != 25 {
            return Err(AddressParseError::InvalidLength(bytes.len()));
        }
        Ok(Address(bytes.try_into().unwrap()))
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", bs58::encode(self.0).into_string())
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Address {
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
    fn roundtrip_hex() {
        use crate::vertex::*;
        let h: Hash32 = "c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696"
            .parse()
            .unwrap();
        assert_eq!(
            h.to_string(),
            "c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696"
        );
        let v: VertexId = h.into();
        let b: BlockId = v.into();
        let t: TransactionId = (*b).into();
        assert_eq!(v.to_string(), b.to_string());
        assert_eq!(t.to_string(), b.to_string());
    }

    #[test]
    fn hash32_invalid_cases() {
        assert_eq!(
            "c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd662869".parse::<Hash32>(),
            Err(Hash32ParseError {
                source: const_hex::FromHexError::OddLength
            })
        );
        assert_eq!(
            "0xc0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696".parse::<Hash32>(),
            Err(Hash32ParseError {
                source: const_hex::FromHexError::InvalidHexCharacter { c: 'x', index: 1 }
            })
        );
    }

    #[test]
    fn address_roundtrip_base58() {
        // arbitrary 25 bytes (not checking checksum here)
        let mut raw = [0u8; 25];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(31).wrapping_add(7);
        }
        let addr = Address(raw);
        let s = addr.to_string();
        let parsed: Address = s.parse().unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn address_known_vectors() {
        let vectors: [(&str, &str); 4] = [
            (
                "HJB2yxxsHtudGGy3jmVeadwMfRi2zNCKKD",
                "287fd4ae0e4fb2d2854e76d359029d8078bb99649e6bb5dc10",
            ),
            (
                "WdmDUMp8KvzhWB7KLgguA2wBiKsh4Ha8eX",
                "49a584cf48b161e4a49223ed220df30037ab740e0039dd4084",
            ),
            (
                "HRXVDmLVdq8pgok1BCUKpiFWdAVAy4a5AJ",
                "28d07bc82d6e0d1bb116614076645e9b87c8c83b41830dbb43",
            ),
            (
                "WZhKusv57pvzotZrf4s7yt7P7PXEqyFTHk",
                "4978e804bf8aa68332c6c1ada274ac598178b972bf5d934763",
            ),
        ];

        for (b58, hex) in vectors {
            let addr: Address = b58.parse().expect("parse base58 address");
            let expected = const_hex::decode(hex).expect("hex");
            assert_eq!(addr.as_ref(), expected.as_slice());
            assert_eq!(addr.to_string(), b58);
        }
    }
}
