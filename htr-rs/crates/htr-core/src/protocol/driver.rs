// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

//! Shared protocol driver surface consumed by both the async I/O engine and
//! the sans-IO state machine.

use crate::network_info::NetworkInfo;
use crate::peer::PublicPeer;

use super::{ControlMessage, HelloData, ReadyMessage, SyncV2Message};

/// Driver actions that can be emitted while operating in READY.
#[derive(Clone, Debug)]
pub enum DriverAction {
    SendReady(ReadyMessage),
    SendControl(ControlMessage),
    CloseWithError(&'static str),
    CloseQuietly,
}

/// Provides data and policy to drive the protocol.
///
/// Keep implementations pure and synchronous; the driver can gather inputs
/// beforehand.  The trait is intentionally shared between the async I/O engine
/// and the sans-IO state machine to keep behavioural hooks aligned.
pub trait ProtocolDriver: Clone {
    fn make_hello(&self) -> HelloData;
    fn get_own_peer(&self) -> &PublicPeer;
    fn get_own_network(&self) -> &NetworkInfo<'static>;
    fn on_new_hello(&self, _hello: &HelloData) -> Result<(), Option<&'static str>> {
        Ok(())
    }
    fn on_peer_identity(&self, _peer: &PublicPeer) -> Result<(), Option<&'static str>> {
        Ok(())
    }
    /// Called once upon entering READY; return a message to send immediately (or None).
    fn on_ready_enter(&self, _remote: &PublicPeer) -> Option<ReadyMessage> {
        None
    }
    /// Give the driver first shot to handle a READY message; return an action or None to fall back.
    fn on_ready_message(&self, _remote: &PublicPeer, _msg: &ReadyMessage) -> Option<DriverAction> {
        None
    }
    /// Give the driver first shot to handle a Sync v2 message; return an action or None to ignore.
    fn on_sync_message(&self, _remote: &PublicPeer, _msg: &SyncV2Message) -> Option<DriverAction> {
        None
    }
}
