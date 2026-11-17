// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::fmt;
use std::sync;
use std::time::{Duration, Instant};

/// Typed state marker mapping to the compound message type that is valid to send for that state.
pub trait State {
    type Message;
}

#[derive(Clone, Debug, PartialEq)]
pub enum Action<S: State> {
    /// Send a wire message valid for the current state (compound state message type)
    Send(S::Message),
    /// Emit a THROTTLE advisory with a reason (scope is assumed global)
    Throttle(String),
    /// Send ERROR <reason> then close the connection
    CloseWithError(&'static str),
    /// Close the connection silently
    CloseQuietly,
    /// Do nothing
    Noop,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerId;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ready;

// New typed sub-states (experimental typed flow)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdAwaiting {
    pub expected_tls_peer_id: Option<crate::peer::PeerId>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerIdExchanged {
    pub remote: PublicPeer,
    pub sent_ready: bool,
    pub got_ready: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncPhase {
    Idle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadyState {
    pub remote: PublicPeer,
    pub sync: SyncPhase,
}

impl State for Hello {
    type Message = HelloStateMessage;
}
impl State for PeerId {
    type Message = PeerIdStateMessage;
}
impl State for Ready {
    type Message = ReadyStateMessage;
}
impl State for PeerIdAwaiting {
    type Message = PeerIdStateMessage;
}
impl State for PeerIdExchanged {
    type Message = PeerIdStateMessage;
}
impl State for ReadyState {
    type Message = ReadyStateMessage;
}

#[derive(Clone)]
pub struct Engine<S, D, T> {
    pub driver: D,
    pub throttler: T,
    pub state: S,
}

/// Shared throttling facility, potentially shared across connections.
pub trait Throttler {
    /// Return Ok(()) to allow; Err(reason) to throttle this hit.
    fn hit(&mut self, now: Instant, scope: ThrottleScope) -> Result<(), String>;
}

impl Throttler for () {
    fn hit(&mut self, _now: Instant, _scope: ThrottleScope) -> Result<(), String> {
        Ok(())
    }
}

impl<T: Throttler> Throttler for sync::Arc<sync::Mutex<T>> {
    fn hit(&mut self, now: Instant, scope: ThrottleScope) -> Result<(), String> {
        let mut throttler = self.lock().unwrap();
        throttler.hit(now, scope)
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ThrottleRate {
    pub max_hits: u32,
    pub window: Duration,
}

impl ThrottleRate {
    pub fn hits_per_second(max_hits: u32) -> Self {
        Self {
            max_hits,
            window: Duration::from_secs(1),
        }
    }

    pub fn hits_per_minute(max_hits: u32) -> Self {
        Self {
            max_hits,
            window: Duration::from_secs(60),
        }
    }

    pub fn mul_duration_f64(self, duration: Duration) -> f64 {
        (self.max_hits as f64) * duration.div_duration_f64(self.window)
    }
}

impl fmt::Display for ThrottleRate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} hits every {} seconds",
            self.max_hits,
            self.window.as_secs()
        )
    }
}

#[derive(Clone, Debug)]
pub struct ThrottleBucket {
    hits: f64,
    rate: ThrottleRate,
    last_hit: Option<Instant>,
}

impl ThrottleBucket {
    pub fn new(rate: ThrottleRate) -> Self {
        Self {
            rate,
            hits: 0.0,
            last_hit: None,
        }
    }

    fn add_hit(&mut self, now: Instant) -> bool {
        self.add_hit_weight(now, 1.0)
    }

    fn add_hit_weight(&mut self, now: Instant, weight: f64) -> bool {
        // compute the delta time `dt` while updating the last hit `self.last_hit`
        let dt = self
            .last_hit
            .replace(now)
            .map_or(Duration::ZERO, |t| now.saturating_duration_since(t));
        // update hits considering the refill with the given duration
        self.hits = (self.hits - self.rate.mul_duration_f64(dt)).max(0.0) + weight;
        // return whether
        self.hits <= (self.rate.max_hits as f64)
    }
}

impl Throttler for ThrottleBucket {
    fn hit(&mut self, now: Instant, _scope: ThrottleScope) -> Result<(), String> {
        // ignore scope for now
        if self.add_hit(now) {
            Ok(())
        } else {
            Err(format!("At most {}", self.rate))
        }
    }
}

impl<D: ProtocolDriver> Engine<Hello, D, ()> {
    pub fn new(me: &PrivatePeer, driver: D) -> Self {
        Engine::new_with_throttler(me, driver, ())
    }
}

impl<D, T1> Engine<Hello, D, T1> {
    pub fn with_throttler<T2>(self, throttler: T2) -> Engine<Hello, D, T2> {
        Engine {
            driver: self.driver,
            throttler,
            state: self.state,
        }
    }
}

impl<D: ProtocolDriver, T: Throttler> Engine<Hello, D, T> {
    pub fn new_with_throttler(_me: &PrivatePeer, driver: D, throttler: T) -> Self {
        Self {
            driver,
            throttler,
            state: Hello,
        }
    }

    /// Check throttling for an inbound message at time `now_seconds`.
    /// Returns Some(Action::Throttle(reason)) when denied; None when allowed.
    pub fn check_throttle(&mut self, now: Instant) -> Option<Action<Hello>> {
        // if hit returns Err(reason) send THROTTLE message
        let key = ThrottleScope::Global;
        self.throttler.hit(now, key).err().map(Action::Throttle)
    }

    pub fn outbound_hello(&self) -> HelloMessage {
        self.driver.make_hello().into()
    }

    pub fn on_incoming(
        self,
        msg: HelloMessage,
    ) -> (Engine<PeerIdAwaiting, D, T>, Action<PeerIdAwaiting>) {
        self.on_incoming_with_tls(msg, None)
    }

    pub fn on_incoming_with_tls(
        self,
        msg: HelloMessage,
        expected_tls_peer_id: Option<crate::peer::PeerId>,
    ) -> (Engine<PeerIdAwaiting, D, T>, Action<PeerIdAwaiting>) {
        match msg {
            HelloMessage::Hello(hello) => {
                let local = self.driver.get_own_network();
                if hello.network != local.name {
                    let next = Engine::<PeerIdAwaiting, D, T> {
                        driver: self.driver,
                        throttler: self.throttler,
                        state: PeerIdAwaiting {
                            expected_tls_peer_id,
                        },
                    };
                    return (next, Action::CloseWithError("network-mismatch"));
                }
                if hello.genesis_short_hash != local.genesis_short_hash {
                    let next = Engine::<PeerIdAwaiting, D, T> {
                        driver: self.driver,
                        throttler: self.throttler,
                        state: PeerIdAwaiting {
                            expected_tls_peer_id,
                        },
                    };
                    return (next, Action::CloseWithError("genesis-mismatch"));
                }
                if let Err(opt) = self.driver.on_new_hello(&hello) {
                    let next = Engine::<PeerIdAwaiting, D, T> {
                        driver: self.driver,
                        throttler: self.throttler,
                        state: PeerIdAwaiting {
                            expected_tls_peer_id,
                        },
                    };
                    let act = match opt {
                        Some(r) => Action::CloseWithError(r),
                        None => Action::CloseQuietly,
                    };
                    return (next, act);
                }
                let next = Engine::<PeerIdAwaiting, D, T> {
                    driver: self.driver,
                    throttler: self.throttler,
                    state: PeerIdAwaiting {
                        expected_tls_peer_id,
                    },
                };
                let actions = Action::Send(PeerIdStateMessage::PeerId(PeerIdMessage::PeerId(
                    next.driver.get_own_peer().clone(),
                )));
                (next, actions)
            }
        }
    }
}

impl<D: ProtocolDriver, T: Throttler> Engine<PeerId, D, T> {
    pub fn into_peer_id_awaiting(
        self,
        expected_tls_peer_id: Option<crate::peer::PeerId>,
    ) -> Engine<PeerIdAwaiting, D, T> {
        Engine {
            driver: self.driver,
            throttler: self.throttler,
            state: PeerIdAwaiting {
                expected_tls_peer_id,
            },
        }
    }
}

// Typed flow helpers: transition from Hello to PeerIdAwaiting with optional TLS-expected peer id
impl<D: ProtocolDriver, T: Throttler> Engine<Hello, D, T> {
    pub fn into_peer_id_awaiting(
        self,
        expected_tls_peer_id: Option<crate::peer::PeerId>,
    ) -> Engine<PeerIdAwaiting, D, T> {
        Engine {
            driver: self.driver,
            throttler: self.throttler,
            state: PeerIdAwaiting {
                expected_tls_peer_id,
            },
        }
    }
}

impl<D: ProtocolDriver, T: Throttler> Engine<PeerIdAwaiting, D, T> {
    pub fn with_expected_tls_peer_id(mut self, expected: crate::peer::PeerId) -> Self {
        self.state.expected_tls_peer_id = Some(expected);
        self
    }

    pub fn on_incoming_peer_id(
        self,
        remote: PublicPeer,
    ) -> (Engine<PeerIdExchanged, D, T>, Action<PeerIdExchanged>) {
        if let Some(exp) = self.state.expected_tls_peer_id
            && remote.peer_id != exp
        {
            let next = Engine {
                driver: self.driver,
                throttler: self.throttler,
                state: PeerIdExchanged {
                    remote,
                    sent_ready: false,
                    got_ready: false,
                },
            };
            return (next, Action::CloseWithError("peerid-mismatch"));
        }
        if let Err(close) = self.driver.on_peer_identity(&remote) {
            let next = Engine {
                driver: self.driver,
                throttler: self.throttler,
                state: PeerIdExchanged {
                    remote,
                    sent_ready: false,
                    got_ready: false,
                },
            };
            let action = match close {
                Some(reason) => Action::CloseWithError(reason),
                None => Action::CloseQuietly,
            };
            return (next, action);
        }
        let next = Engine {
            driver: self.driver,
            throttler: self.throttler,
            state: PeerIdExchanged {
                remote,
                sent_ready: true,
                got_ready: false,
            },
        };
        (
            next,
            Action::Send(PeerIdStateMessage::PeerId(PeerIdMessage::Ready)),
        )
    }

    pub fn on_incoming_ready(self) -> (Engine<PeerIdAwaiting, D, T>, Action<PeerIdAwaiting>) {
        (self, Action::CloseWithError("peer-id-expected"))
    }
}

impl<D: ProtocolDriver, T: Throttler> Engine<PeerIdExchanged, D, T> {
    pub fn on_incoming_ready(self) -> (Engine<ReadyState, D, T>, Action<ReadyState>) {
        let remote = self.state.remote;
        let next = Engine {
            driver: self.driver,
            throttler: self.throttler,
            state: ReadyState {
                remote,
                sync: SyncPhase::Idle,
            },
        };
        // Give the driver a chance to send an initial READY message upon entering READY
        let act = match next.driver.on_ready_enter(&next.state.remote) {
            Some(msg) => Action::Send(ReadyStateMessage::Ready(msg)),
            None => Action::Noop,
        };
        (next, act)
    }
}

impl<D: ProtocolDriver, T: Throttler> Engine<ReadyState, D, T> {
    pub fn on_incoming_ready_msg(&self, msg: ReadyMessage) -> Action<ReadyState> {
        // First delegate to driver policy
        if let Some(action) = self.driver.on_ready_message(&self.state.remote, &msg) {
            return map_driver_ready_action(action);
        }
        // Minimal compliance fallback
        match msg {
            ReadyMessage::Ping(s) => Action::Send(ReadyStateMessage::Ready(ReadyMessage::Pong(s))),
            ReadyMessage::Pong(_) => Action::Noop,
            ReadyMessage::GetPeers => Action::Noop,
            ReadyMessage::Peers(_) => Action::Noop,
            _ => Action::Noop,
        }
    }

    pub fn on_incoming_sync_msg(&self, msg: SyncV2Message) -> Action<ReadyState> {
        // First delegate to driver policy
        if let Some(action) = self.driver.on_sync_message(&self.state.remote, &msg) {
            return map_driver_ready_action(action);
        }
        // Soft gating for now: ignore all sync messages while in Idle phase.
        match self.state.sync {
            SyncPhase::Idle => Action::Noop,
        }
    }
}

fn map_driver_ready_action(action: DriverAction) -> Action<ReadyState> {
    match action {
        DriverAction::SendReady(msg) => Action::Send(ReadyStateMessage::Ready(msg)),
        DriverAction::SendControl(msg) => Action::Send(ReadyStateMessage::Control(msg)),
        DriverAction::CloseWithError(reason) => Action::CloseWithError(reason),
        DriverAction::CloseQuietly => Action::CloseQuietly,
    }
}

type PeerIdResult<D, T> =
    Result<(Engine<PeerId, D, T>, Action<PeerId>), (Engine<Ready, D, T>, Action<Ready>)>;
impl<D: ProtocolDriver, T: Throttler> Engine<PeerId, D, T> {
    #[allow(clippy::result_large_err)]
    pub fn on_incoming(self, msg: PeerIdMessage) -> PeerIdResult<D, T> {
        match msg {
            PeerIdMessage::PeerId(_remote) => {
                let act = Action::<PeerId>::Send(PeerIdStateMessage::PeerId(PeerIdMessage::Ready));
                Ok((self, act))
            }
            PeerIdMessage::Ready => {
                let next = Engine::<Ready, D, T> {
                    driver: self.driver,
                    throttler: self.throttler,
                    state: Ready,
                };
                Err((next, Action::Noop))
            }
        }
    }
}

impl<D: ProtocolDriver, T: Throttler> Engine<Ready, D, T> {
    pub fn on_incoming(&self, msg: ReadyMessage) -> Action<Ready> {
        match msg {
            ReadyMessage::Ping(s) => Action::Send(ReadyStateMessage::Ready(ReadyMessage::Pong(s))),
            ReadyMessage::Pong(_) => Action::Noop,
            ReadyMessage::GetPeers => Action::Noop,
            ReadyMessage::Peers(_) => Action::Noop, // app-layer aggregation, ignore here
            _ => Action::Noop,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network_info::{NETWORK_INFO_TESTNET_HOTEL as INFO, NetworkInfo};
    use crate::peer::PrivatePeer;

    #[derive(Clone)]
    struct TestDriver {
        info: NetworkInfo<'static>,
        me: PublicPeer,
    }
    impl ProtocolDriver for TestDriver {
        fn make_hello(&self) -> HelloData {
            self.info.make_hello_data()
        }
        fn get_own_peer(&self) -> &PublicPeer {
            &self.me
        }
        fn get_own_network(&self) -> &NetworkInfo<'static> {
            &self.info
        }
    }

    #[test]
    fn handshake_happy_path() {
        let me = PrivatePeer::example();
        let e0 = Engine::<Hello, TestDriver, ()>::new(
            &me,
            TestDriver {
                info: INFO.clone(),
                me: me.clone().into(),
            },
        );
        let _hello = e0.outbound_hello();
        let (a1, act1) = e0.on_incoming(INFO.make_hello_data().into());
        match act1 {
            Action::Send(PeerIdStateMessage::PeerId(_)) => {}
            _ => panic!("expected to send PeerId"),
        }
        // Typed: receive peer-id
        let (x1, act2) = a1.on_incoming_peer_id(me.clone().into());
        match act2 {
            Action::Send(PeerIdStateMessage::PeerId(PeerIdMessage::Ready)) => {}
            _ => panic!("expected to send Ready"),
        }
        let (_ready, act3) = x1.on_incoming_ready();
        assert_eq!(act3, Action::Noop);
    }

    #[test]
    fn ready_get_peers_queries_provider() {
        let me = PrivatePeer::example();
        let e0 = Engine::<Hello, TestDriver, ()>::new(
            &me,
            TestDriver {
                info: INFO.clone(),
                me: me.clone().into(),
            },
        );
        let (a1, _) = e0.on_incoming(INFO.make_hello_data().into());
        let (x1, _) = a1.on_incoming_peer_id(me.clone().into());
        let (ready, _) = x1.on_incoming_ready();
        assert_eq!(
            ready.on_incoming_ready_msg(ReadyMessage::GetPeers),
            Action::Noop
        );
    }

    #[test]
    fn typed_handshake_happy_path() {
        let me = PrivatePeer::example();
        let e0 = Engine::<Hello, TestDriver, ()>::new(
            &me,
            TestDriver {
                info: INFO.clone(),
                me: me.clone().into(),
            },
        );
        let _hello = e0.outbound_hello();
        let (e1, act1) = e0.on_incoming(INFO.make_hello_data().into());
        match act1 {
            Action::Send(PeerIdStateMessage::PeerId(_)) => {}
            _ => panic!("expected PeerId"),
        }
        let (exchanged, act2) = e1.on_incoming_peer_id(me.clone().into());
        match act2 {
            Action::Send(PeerIdStateMessage::PeerId(PeerIdMessage::Ready)) => {}
            _ => panic!("expected Ready"),
        }
        let (ready, act3) = exchanged.on_incoming_ready();
        assert_eq!(act3, Action::Noop);
        assert_eq!(
            ready.on_incoming_ready_msg(ReadyMessage::GetPeers),
            Action::Noop
        );

        // Sync gating: out-of-phase sync messages are ignored in Idle
        use crate::protocol::message::StreamEnd;
        assert_eq!(
            ready.on_incoming_sync_msg(SyncV2Message::BlocksEnd(StreamEnd::NoMoreBlocks)),
            Action::Noop
        );
    }

    #[test]
    fn ready_enter_can_trigger_initial_query() {
        #[derive(Clone)]
        struct EnterDriver {
            info: NetworkInfo<'static>,
            me: PublicPeer,
        }
        impl ProtocolDriver for EnterDriver {
            fn make_hello(&self) -> HelloData {
                self.info.make_hello_data()
            }
            fn get_own_peer(&self) -> &PublicPeer {
                &self.me
            }
            fn get_own_network(&self) -> &NetworkInfo<'static> {
                &self.info
            }
            fn on_ready_enter(&self, _remote: &PublicPeer) -> Option<ReadyMessage> {
                Some(ReadyMessage::GetBestBlockchain(Some(16)))
            }
        }

        let me = PrivatePeer::example();
        let e0 = Engine::<Hello, EnterDriver, ()>::new(
            &me,
            EnterDriver {
                info: INFO.clone(),
                me: me.clone().into(),
            },
        );
        let (e1, _act1) = e0.on_incoming(INFO.make_hello_data().into());
        let (exchanged, _act2) = e1.on_incoming_peer_id(me.clone().into());
        let (_ready, act3) = exchanged.on_incoming_ready();
        assert_eq!(
            act3,
            Action::Send(ReadyStateMessage::Ready(ReadyMessage::GetBestBlockchain(
                Some(16)
            )))
        );
    }
    #[test]
    fn tls_expected_peer_id_mismatch_triggers_close() {
        use crate::crypto::PublicKey;
        let me = PrivatePeer::example();
        let e0 = Engine::<Hello, TestDriver, ()>::new(
            &me,
            TestDriver {
                info: INFO.clone(),
                me: me.clone().into(),
            },
        );
        let exp_id = me.peer_id;
        let (awaiting, _act1) =
            e0.on_incoming_with_tls(INFO.make_hello_data().into(), Some(exp_id));
        // Craft a remote with a different id
        let remote = crate::peer::PublicPeer {
            peer_id: (&[1u8; 32][..]).try_into().unwrap(),
            pub_key: PublicKey::from(rustls_pki_types::SubjectPublicKeyInfoDer::from(
                &[0x30, 0x82, 0x01, 0x0a][..],
            )),
            endpoints: vec![],
        };
        let (_exchanged, act2) = awaiting.on_incoming_peer_id(remote);
        assert_eq!(act2, Action::CloseWithError("peerid-mismatch"));
    }

    #[test]
    fn throttling_denies_when_capacity_exhausted() {
        #[derive(Clone)]
        struct ThrottleDriver {
            info: NetworkInfo<'static>,
            me: PublicPeer,
        }
        impl ProtocolDriver for ThrottleDriver {
            fn make_hello(&self) -> HelloData {
                self.info.make_hello_data()
            }
            fn get_own_peer(&self) -> &PublicPeer {
                &self.me
            }
            fn get_own_network(&self) -> &NetworkInfo<'static> {
                &self.info
            }
        }

        // shared throttler across potential connections
        let throttler = sync::Arc::new(sync::Mutex::new(ThrottleBucket::new(
            ThrottleRate::hits_per_minute(2),
        )));
        let me = PrivatePeer::example();
        let mut e0 = Engine::<Hello, _, _>::new_with_throttler(
            &me,
            ThrottleDriver {
                info: INFO.clone(),
                me: me.clone().into(),
            },
            throttler,
        );
        // Using the same instant, so allow two hits; the third should be throttled
        let t0 = Instant::now();
        assert!(e0.check_throttle(t0).is_none());
        assert!(e0.check_throttle(t0).is_none());
        match e0.check_throttle(t0) {
            Some(Action::Throttle(reason)) => {
                assert!(reason.contains("At most 2 hits"));
            }
            other => panic!("expected throttle, got {:?}", other),
        }
        // After 60s, bucket refills
        let t1 = t0 + Duration::from_secs(60);
        assert!(e0.check_throttle(t1).is_none());
    }
}
