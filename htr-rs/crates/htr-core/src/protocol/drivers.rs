// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use super::{Error, ProtocolDriver, TlsStreamExt, engine};
use crate::network_info::NetworkInfo;
use crate::peer::PublicPeer;
use std::fmt;
use tokio::io::{AsyncRead, AsyncWrite};

#[derive(Clone)]
pub struct IoDriver {
    info: NetworkInfo<'static>,
    me: PublicPeer,
}

impl IoDriver {
    pub fn new(info: NetworkInfo<'static>, me: PublicPeer) -> Self {
        Self { info, me }
    }

    pub async fn handle<S>(&self, stream: S) -> Result<(), Error>
    where
        S: fmt::Debug + AsyncWrite + AsyncRead + std::marker::Unpin + TlsStreamExt,
    {
        engine::run(self.clone(), stream).await
    }
}

impl ProtocolDriver for IoDriver {
    fn make_hello(&self) -> super::HelloData {
        self.info.make_hello_data()
    }
    fn get_own_peer(&self) -> &PublicPeer {
        &self.me
    }
    fn get_own_network(&self) -> &NetworkInfo<'static> {
        &self.info
    }
}
