// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serializer};
use std::path::PathBuf;

pub static PROJECT_QUAL: &str = "com";
pub static PROJECT_ORG: &str = "hathorlabs";
pub static PROJECT_APP: &str = "hathor-core";

// pub fn project_dirs() -> Result<ProjectDirs, Error> {
//     ProjectDirs::from(PROJECT_QUAL, PROJECT_ORG, PROJECT_APP).ok_or(Error::HomeDirError)
// }

pub fn project_dir() -> Option<PathBuf> {
    let base_dir: Option<PathBuf>;
    #[cfg(not(target_os = "windows"))]
    {
        base_dir = dirs::home_dir().map(|dir| dir.join(format!(".{}", PROJECT_APP)));
    }
    #[cfg(target_os = "windows")]
    {
        base_dir = dirs::data_local_dir().map(|dir| dir.join(PROJECT_APP));
    }
    base_dir
}

pub fn build_tokio_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .thread_name(PROJECT_APP)
        .thread_name_fn(|| {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static ATOMIC_ID: AtomicUsize = AtomicUsize::new(0);
            let id = ATOMIC_ID.fetch_add(1, Ordering::SeqCst);
            format!("{}-{}", PROJECT_APP, id)
        })
        .enable_all()
        .build()
}

// Generic TryFrom<T> forwarding: if inner implements TryFrom<T>, so does the newtype
macro_rules! forward_try_from_slice {
    ($new:ty, $inner:ty) => {
        impl<'a> TryFrom<&'a [u8]> for $new {
            type Error = TryFromSliceError;
            fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
                <$inner>::try_from(value).map(Self)
            }
        }
    };
}
pub(crate) use forward_try_from_slice;

macro_rules! forward_try_from_serde_str {
    ($t:ty) => {
        impl ::core::convert::TryFrom<&str> for $t {
            type Error = ::serde::de::value::Error;
            fn try_from(s: &str) -> Result<Self, Self::Error> {
                let de = ::serde::de::value::StrDeserializer::<Self::Error>::new(s);
                ::serde::Deserialize::deserialize(de)
            }
        }
    };
}
pub(crate) use forward_try_from_serde_str;

// Serde helpers for hex-encoded bytes
pub mod serde_hex {
    use super::*;

    pub mod bytes {
        use super::*;
        pub fn serialize<S>(value: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&const_hex::encode(value))
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
        where
            D: Deserializer<'de>,
        {
            let s = String::deserialize(deserializer)?;
            if s.starts_with("0x") {
                return Err(serde::de::Error::custom("0x prefix not allowed"));
            }
            if s.len() % 2 != 0 {
                return Err(serde::de::Error::custom("hex string must have even length"));
            }
            let mut buf = vec![0u8; s.len() / 2];
            const_hex::decode_to_slice(&s, &mut buf).map_err(serde::de::Error::custom)?;
            Ok(Bytes::from(buf))
        }
    }

    pub mod opt_bytes {
        use super::*;

        pub fn serialize<S>(value: &Option<Bytes>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match value {
                None => serializer.serialize_none(),
                Some(b) if b.is_empty() => serializer.serialize_str(""),
                Some(b) => serializer.serialize_str(&const_hex::encode(b)),
            }
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Bytes>, D::Error>
        where
            D: Deserializer<'de>,
        {
            let opt = Option::<String>::deserialize(deserializer)?;
            match opt {
                None => Ok(None),
                Some(s) => {
                    if s.starts_with("0x") {
                        return Err(serde::de::Error::custom("0x prefix not allowed"));
                    }
                    if s.len() % 2 != 0 {
                        return Err(serde::de::Error::custom("hex string must have even length"));
                    }
                    let mut buf = vec![0u8; s.len() / 2];
                    const_hex::decode_to_slice(&s, &mut buf).map_err(serde::de::Error::custom)?;
                    Ok(Some(Bytes::from(buf)))
                }
            }
        }

        pub fn is_none_or_empty(v: &Option<Bytes>) -> bool {
            match v {
                None => true,
                Some(b) => b.is_empty(),
            }
        }
    }
}
