// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

//! A sans-IO stepper over `htr-core`'s real protocol state machine, exposed to Python.
//!
//! `ProtocolPeer` wraps the type-state `Engine` from `htr_core::protocol::state` and drives it
//! one wire line at a time: Python plays the remote peer, feeding lines and observing the exact
//! outbound lines and state the Rust engine produces. This exercises the *real* handshake and
//! per-state message handling (not the codecs, not a mock) deterministically — no sockets, TLS,
//! async, or subprocess — so Python can assert the full per-state message matrix against the engine.

use htr_core::network_info::{
    NETWORK_INFO_MAINNET, NETWORK_INFO_TESTNET_GOLF, NETWORK_INFO_TESTNET_HOTEL,
    NETWORK_INFO_TESTNET_INDIA, NETWORK_INFO_UNITTESTS, NetworkInfo,
};
use htr_core::peer::{PrivatePeer, PublicPeer};
use htr_core::protocol::ProtocolDriver;
use htr_core::protocol::message::{
    ControlMessage, HelloData, HelloStateMessage, PeerIdMessage, PeerIdStateMessage,
    ReadyStateMessage,
};
use htr_core::protocol::state::{
    self, Action, Engine, Hello, PeerIdAwaiting, PeerIdExchanged, ReadyState,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

/// Minimal driver for the stepper: supplies our HELLO/peer/network and uses the engine's default
/// (passive) policy hooks, so the engine's own compliance behavior (e.g. PING -> PONG) is what gets
/// exercised.
#[derive(Clone)]
struct StepperDriver {
    info: NetworkInfo<'static>,
    me: PublicPeer,
}

impl ProtocolDriver for StepperDriver {
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

/// The current typed engine, one variant per protocol state (plus a terminal `Closed`).
enum EngineState {
    Hello(Engine<Hello, StepperDriver, ()>),
    Awaiting(Engine<PeerIdAwaiting, StepperDriver, ()>),
    Exchanged(Engine<PeerIdExchanged, StepperDriver, ()>),
    Ready(Engine<ReadyState, StepperDriver, ()>),
    Closed,
}

impl EngineState {
    fn name(&self) -> &'static str {
        match self {
            EngineState::Hello(_) => "hello",
            EngineState::Awaiting(_) | EngineState::Exchanged(_) => "peer-id",
            EngineState::Ready(_) => "ready",
            EngineState::Closed => "closed",
        }
    }
}

/// Render an engine `Action` into the wire lines it would emit and whether it closes the connection.
fn render_action<S>(action: Action<S>) -> (Vec<String>, bool)
where
    S: state::State,
    S::Message: std::fmt::Display,
{
    match action {
        Action::Send(msg) => (vec![msg.to_string()], false),
        Action::Throttle(reason) => (vec![format!("THROTTLE global {reason}")], false),
        Action::CloseWithError(reason) => (vec![format!("ERROR {reason}")], true),
        Action::CloseQuietly => (vec![], true),
        Action::Noop => (vec![], false),
    }
}

fn parse_error(line: &str) -> PyErr {
    PyValueError::new_err(format!("message not valid in current state: {line:?}"))
}

/// Advance the engine by one inbound line, returning the next engine and the outbound lines.
///
/// On a line that does not parse in the current state, the engine is returned unchanged with an
/// error, so the peer stays usable (the caller can assert the rejection). Control/handshake policy
/// (e.g. a control message ends the connection mid-handshake, an `ERROR` ends READY) mirrors the
/// async I/O engine in `htr_core::protocol::engine`.
fn step(state: EngineState, line: &str) -> (EngineState, PyResult<Vec<String>>) {
    match state {
        EngineState::Hello(engine) => match line.parse::<HelloStateMessage>() {
            Err(_) => (EngineState::Hello(engine), Err(parse_error(line))),
            Ok(HelloStateMessage::Hello(hello)) => {
                let (next, action) = engine.on_incoming_with_tls(hello, None);
                let (lines, closed) = render_action(action);
                let state = if closed {
                    EngineState::Closed
                } else {
                    EngineState::Awaiting(next)
                };
                (state, Ok(lines))
            }
            // A control message (ERROR/THROTTLE) before the handshake completes ends the connection.
            Ok(HelloStateMessage::Control(_)) => (EngineState::Closed, Ok(vec![])),
        },
        EngineState::Awaiting(engine) => match line.parse::<PeerIdStateMessage>() {
            Err(_) => (EngineState::Awaiting(engine), Err(parse_error(line))),
            Ok(PeerIdStateMessage::PeerId(PeerIdMessage::PeerId(peer))) => {
                let (next, action) = engine.on_incoming_peer_id(peer);
                let (lines, closed) = render_action(action);
                let state = if closed {
                    EngineState::Closed
                } else {
                    EngineState::Exchanged(next)
                };
                (state, Ok(lines))
            }
            Ok(PeerIdStateMessage::PeerId(PeerIdMessage::Ready)) => {
                let (_engine, action) = engine.on_incoming_ready();
                let (lines, _closed) = render_action(action);
                (EngineState::Closed, Ok(lines))
            }
            Ok(PeerIdStateMessage::Control(_)) => (EngineState::Closed, Ok(vec![])),
        },
        EngineState::Exchanged(engine) => match line.parse::<PeerIdStateMessage>() {
            Err(_) => (EngineState::Exchanged(engine), Err(parse_error(line))),
            Ok(PeerIdStateMessage::PeerId(PeerIdMessage::Ready)) => {
                let (next, action) = engine.on_incoming_ready();
                let (lines, closed) = render_action(action);
                let state = if closed {
                    EngineState::Closed
                } else {
                    EngineState::Ready(next)
                };
                (state, Ok(lines))
            }
            // A second PEER-ID where READY is expected is a protocol violation; the I/O engine
            // closes with ERROR "unexpected" here.
            Ok(PeerIdStateMessage::PeerId(PeerIdMessage::PeerId(_))) => (
                EngineState::Closed,
                Ok(vec!["ERROR unexpected".to_string()]),
            ),
            Ok(PeerIdStateMessage::Control(_)) => (EngineState::Closed, Ok(vec![])),
        },
        EngineState::Ready(engine) => match line.parse::<ReadyStateMessage>() {
            Err(_) => (EngineState::Ready(engine), Err(parse_error(line))),
            Ok(ReadyStateMessage::Ready(msg)) => {
                let action = engine.on_incoming_ready_msg(msg);
                let (lines, closed) = render_action(action);
                let state = if closed {
                    EngineState::Closed
                } else {
                    EngineState::Ready(engine)
                };
                (state, Ok(lines))
            }
            Ok(ReadyStateMessage::Sync(msg)) => {
                let action = engine.on_incoming_sync_msg(msg);
                let (lines, closed) = render_action(action);
                let state = if closed {
                    EngineState::Closed
                } else {
                    EngineState::Ready(engine)
                };
                (state, Ok(lines))
            }
            // An inbound ERROR ends the connection; a THROTTLE is advisory and keeps it open.
            Ok(ReadyStateMessage::Control(ControlMessage::Error(_))) => {
                (EngineState::Closed, Ok(vec![]))
            }
            Ok(ReadyStateMessage::Control(ControlMessage::Throttle { .. })) => {
                (EngineState::Ready(engine), Ok(vec![]))
            }
        },
        EngineState::Closed => (
            EngineState::Closed,
            Err(PyValueError::new_err("connection closed")),
        ),
    }
}

fn network_by_name(name: &str) -> Option<NetworkInfo<'static>> {
    let info = match name {
        "unittests" => &NETWORK_INFO_UNITTESTS,
        "mainnet" => &NETWORK_INFO_MAINNET,
        "testnet-golf" => &NETWORK_INFO_TESTNET_GOLF,
        "testnet-hotel" => &NETWORK_INFO_TESTNET_HOTEL,
        "testnet-india" => &NETWORK_INFO_TESTNET_INDIA,
        _ => return None,
    };
    Some(info.clone())
}

/// A scriptable peer that drives the real `htr-core` protocol state machine from Python.
#[pyclass]
pub struct ProtocolPeer {
    inner: EngineState,
}

#[pymethods]
impl ProtocolPeer {
    /// Build a peer on the named network (`"unittests"`, `"testnet-india"`, `"mainnet"`,
    /// `"testnet-golf"`, `"testnet-hotel"`). Raises `ValueError` on an unknown network.
    #[new]
    fn new(network: &str) -> PyResult<Self> {
        let info = network_by_name(network)
            .ok_or_else(|| PyValueError::new_err(format!("unknown network: {network}")))?;
        let me = PrivatePeer::generate_default()
            .map_err(|e| PyValueError::new_err(format!("peer generation failed: {e}")))?;
        let driver = StepperDriver {
            info,
            me: me.clone().into(),
        };
        let engine = Engine::<Hello, StepperDriver, ()>::new(&me, driver);
        Ok(Self {
            inner: EngineState::Hello(engine),
        })
    }

    /// The protocol state: `"hello"`, `"peer-id"`, `"ready"`, or `"closed"`.
    #[getter]
    fn state(&self) -> &'static str {
        self.inner.name()
    }

    /// Return the outbound HELLO line this peer sends first. Only valid before any line is fed.
    fn start(&self) -> PyResult<Vec<String>> {
        match &self.inner {
            EngineState::Hello(engine) => Ok(vec![engine.outbound_hello().to_string()]),
            _ => Err(PyValueError::new_err(
                "start() is only valid in the HELLO state",
            )),
        }
    }

    /// Feed one inbound wire line and return the lines the engine emits in response.
    ///
    /// Raises `ValueError` if the line is not valid in the current state (the peer stays usable) or
    /// if the connection is already closed.
    fn feed(&mut self, line: &str) -> PyResult<Vec<String>> {
        let current = std::mem::replace(&mut self.inner, EngineState::Closed);
        let (next, result) = step(current, line);
        self.inner = next;
        result
    }
}
