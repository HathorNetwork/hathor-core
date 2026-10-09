// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use crate::protocol::{HelloData, HelloTimestamp};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

pub static NETWORK_INFO_MAINNET: NetworkInfo<'_> =
    NetworkInfo::local_with_bootstrap("mainnet", "3fdff62", "mainnet.hathor.network");
pub static NETWORK_INFO_TESTNET_GOLF: NetworkInfo<'_> =
    NetworkInfo::local_with_bootstrap("testnet-golf", "12e8d7f", "golf.testnet.hathor.network");
pub static NETWORK_INFO_TESTNET_HOTEL: NetworkInfo<'_> =
    NetworkInfo::local_with_bootstrap("testnet-hotel", "12e8d7f", "hotel.testnet.hathor.network");
pub static NETWORK_INFO_TESTNET_INDIA: NetworkInfo<'_> =
    NetworkInfo::local_with_bootstrap("testnet-india", "f7438fb", "india.testnet.hathor.network");
/// The Python `unittests` network (`hathorlib/conf/unittests.yml`). Has no bootstrap; it exists so
/// interop tests can speak the same network the Python test suite runs on.
pub static NETWORK_INFO_UNITTESTS: NetworkInfo<'_> = NetworkInfo::local("unittests", "f188691");

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkInfo<'a> {
    #[serde(borrow)]
    pub name: Cow<'a, str>,
    #[serde(borrow)]
    pub genesis_short_hash: Cow<'a, str>,
    #[serde(borrow)]
    pub bootstrap_txt_domain: Option<Cow<'a, str>>,
}

impl NetworkInfo<'static> {
    pub const fn local(name: &'static str, genesis_short_hash: &'static str) -> Self {
        Self {
            name: Cow::Borrowed(name),
            genesis_short_hash: Cow::Borrowed(genesis_short_hash),
            bootstrap_txt_domain: None,
        }
    }

    pub const fn local_with_bootstrap(
        name: &'static str,
        genesis_short_hash: &'static str,
        bootstrap_txt_domain: &'static str,
    ) -> Self {
        Self {
            name: Cow::Borrowed(name),
            genesis_short_hash: Cow::Borrowed(genesis_short_hash),
            bootstrap_txt_domain: Some(Cow::Borrowed(bootstrap_txt_domain)),
        }
    }

    pub fn make_hello_data(&self) -> HelloData {
        use crate::protocol::{APP_STRING, Capability};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        HelloData {
            app: APP_STRING.to_string(),
            network: self.name.to_string(),
            remote_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9001),
            genesis_short_hash: self.genesis_short_hash.to_string(),
            timestamp: HelloTimestamp::now(),
            capabilities: Capability::default_capabilities(),
            sync_versions: vec![Default::default()],
        }
    }
}
