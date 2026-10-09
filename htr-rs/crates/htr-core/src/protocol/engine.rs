// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

// Engine I/O runner; core engine types live in `super::sans_io`

use super::state;
use super::*;
use futures::{SinkExt, StreamExt, future};
use std::fmt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;
use tokio_util::codec::{Framed, FramedParts};

#[derive(Clone, Debug)]
pub enum ProtocolCommand {
    SendReady(ReadyMessage),
    Close,
}

#[derive(Clone, Debug)]
pub enum ProtocolEvent {
    HelloReceived(HelloData),
    PeerIdentified(PublicPeer),
    ReadyEntered {
        remote: PublicPeer,
    },
    ReadyMessage {
        remote: PublicPeer,
        message: ReadyMessage,
    },
    SyncMessage {
        remote: PublicPeer,
        message: SyncV2Message,
    },
    Control {
        remote: Option<PublicPeer>,
        message: ControlMessage,
    },
    Disconnected {
        remote: Option<PublicPeer>,
    },
}

#[derive(Default)]
pub struct ProtocolHandle {
    event_tx: Option<mpsc::UnboundedSender<ProtocolEvent>>,
    command_rx: Option<mpsc::UnboundedReceiver<ProtocolCommand>>,
}

impl ProtocolHandle {
    pub fn new(
        event_tx: Option<mpsc::UnboundedSender<ProtocolEvent>>,
        command_rx: Option<mpsc::UnboundedReceiver<ProtocolCommand>>,
    ) -> Self {
        Self {
            event_tx,
            command_rx,
        }
    }

    pub fn with_channels(
        event_tx: mpsc::UnboundedSender<ProtocolEvent>,
        command_rx: mpsc::UnboundedReceiver<ProtocolCommand>,
    ) -> Self {
        Self {
            event_tx: Some(event_tx),
            command_rx: Some(command_rx),
        }
    }

    pub fn set_event_tx(&mut self, event_tx: mpsc::UnboundedSender<ProtocolEvent>) {
        self.event_tx = Some(event_tx);
    }

    pub fn set_command_rx(&mut self, command_rx: mpsc::UnboundedReceiver<ProtocolCommand>) {
        self.command_rx = Some(command_rx);
    }

    pub fn take_command_rx(&mut self) -> Option<mpsc::UnboundedReceiver<ProtocolCommand>> {
        self.command_rx.take()
    }

    fn emit(&self, event: ProtocolEvent) {
        if let Some(tx) = &self.event_tx {
            let _ = tx.send(event);
        }
    }
}

/// Run the protocol over an AsyncRead/AsyncWrite stream with the given driver.
pub async fn run<D, S>(driver: D, stream: S) -> Result<(), Error>
where
    D: ProtocolDriver,
    S: fmt::Debug + AsyncWrite + AsyncRead + std::marker::Unpin + TlsStreamExt,
{
    run_with_handle(driver, stream, ProtocolHandle::default()).await
}

/// Run the protocol with an explicit handle for commands and events.
pub async fn run_with_handle<D, S>(
    driver: D,
    mut stream: S,
    mut handle: ProtocolHandle,
) -> Result<(), Error>
where
    D: ProtocolDriver,
    S: fmt::Debug + AsyncWrite + AsyncRead + std::marker::Unpin + TlsStreamExt,
{
    let tls_peer_id = stream
        .gen_peer_id_from_conn_cert()
        .ok_or(Error::BadCertificate)?;
    let span = debug_span!("conn", %tls_peer_id);
    debug!(parent: &span, "connected");

    let mut remote_peer: Option<PublicPeer> = None;

    let hello_engine = state::Engine {
        driver,
        throttler: (),
        state: state::Hello,
    };

    let (peer_engine, mut framed_peer) = {
        let mut framed = Framed::with_capacity(&mut stream, codec::HelloCodec::new(), 1024);
        let span = debug_span!(parent: &span, "HELLO");
        let outbound = hello_engine.outbound_hello();
        debug!(parent: &span, ?outbound, "send");
        framed.send(HelloStateMessage::from(outbound)).await?;

        let incoming = match framed.next().await {
            Some(Ok(msg)) => msg,
            Some(Err(e)) => {
                handle.emit(ProtocolEvent::Disconnected { remote: None });
                return Err(e);
            }
            None => {
                handle.emit(ProtocolEvent::Disconnected { remote: None });
                return Ok(());
            }
        };

        match incoming {
            HelloStateMessage::Hello(HelloMessage::Hello(hello)) => {
                debug!(parent: &span, ?hello, "recv");
                handle.emit(ProtocolEvent::HelloReceived(hello.clone()));
                let (next_engine, action) = hello_engine
                    .on_incoming_with_tls(HelloMessage::Hello(hello), Some(tls_peer_id));
                let parts = framed.into_parts();
                let mut next_parts = FramedParts::new(parts.io, codec::PeerIdCodec::new());
                next_parts.read_buf = parts.read_buf;
                next_parts.write_buf = parts.write_buf;
                let mut framed_peer = Framed::from_parts(next_parts);
                if apply_peer_id_action(action, &mut framed_peer, &handle, None, &span).await? {
                    handle.emit(ProtocolEvent::Disconnected { remote: None });
                    return Ok(());
                }
                (next_engine, framed_peer)
            }
            HelloStateMessage::Control(msg) => {
                debug!(parent: &span, ?msg, "recv");
                handle.emit(ProtocolEvent::Control {
                    remote: None,
                    message: msg.clone(),
                });
                handle.emit(ProtocolEvent::Disconnected { remote: None });
                return Ok(());
            }
        }
    };

    let span_peer = debug_span!(parent: &span, "PEER-ID");
    let incoming = match framed_peer.next().await {
        Some(Ok(msg)) => msg,
        Some(Err(e)) => {
            handle.emit(ProtocolEvent::Disconnected {
                remote: remote_peer.clone(),
            });
            return Err(e);
        }
        None => {
            handle.emit(ProtocolEvent::Disconnected {
                remote: remote_peer.clone(),
            });
            return Ok(());
        }
    };

    let exchanged_engine = match incoming {
        PeerIdStateMessage::PeerId(PeerIdMessage::PeerId(peer)) => {
            debug!(parent: &span_peer, ?peer, "recv");
            let peer_for_events = peer.clone();
            handle.emit(ProtocolEvent::PeerIdentified(peer_for_events.clone()));
            remote_peer = Some(peer_for_events);
            let (next_engine, action) = peer_engine.on_incoming_peer_id(peer);
            if apply_peer_id_action(
                action,
                &mut framed_peer,
                &handle,
                remote_peer.as_ref(),
                &span_peer,
            )
            .await?
            {
                handle.emit(ProtocolEvent::Disconnected {
                    remote: remote_peer.clone(),
                });
                return Ok(());
            }
            next_engine
        }
        PeerIdStateMessage::PeerId(PeerIdMessage::Ready) => {
            debug!(parent: &span_peer, "recv-unexpected-ready");
            let action = state::Action::<state::PeerIdAwaiting>::CloseWithError("unexpected");
            if apply_peer_id_action(
                action,
                &mut framed_peer,
                &handle,
                remote_peer.as_ref(),
                &span_peer,
            )
            .await?
            {
                handle.emit(ProtocolEvent::Disconnected {
                    remote: remote_peer.clone(),
                });
            }
            return Ok(());
        }
        PeerIdStateMessage::Control(msg) => {
            debug!(parent: &span_peer, ?msg, "recv");
            handle.emit(ProtocolEvent::Control {
                remote: remote_peer.clone(),
                message: msg.clone(),
            });
            handle.emit(ProtocolEvent::Disconnected {
                remote: remote_peer.clone(),
            });
            return Ok(());
        }
    };

    let ready_trigger = match framed_peer.next().await {
        Some(Ok(msg)) => msg,
        Some(Err(e)) => {
            handle.emit(ProtocolEvent::Disconnected {
                remote: remote_peer.clone(),
            });
            return Err(e);
        }
        None => {
            handle.emit(ProtocolEvent::Disconnected {
                remote: remote_peer.clone(),
            });
            return Ok(());
        }
    };

    match ready_trigger {
        PeerIdStateMessage::PeerId(PeerIdMessage::Ready) => {}
        PeerIdStateMessage::PeerId(PeerIdMessage::PeerId(peer)) => {
            debug!(parent: &span_peer, ?peer, "recv-unexpected-peer-id");
            let action = state::Action::<state::PeerIdExchanged>::CloseWithError("unexpected");
            if apply_peer_id_action(
                action,
                &mut framed_peer,
                &handle,
                remote_peer.as_ref(),
                &span_peer,
            )
            .await?
            {
                handle.emit(ProtocolEvent::Disconnected {
                    remote: remote_peer.clone(),
                });
            }
            return Ok(());
        }
        PeerIdStateMessage::Control(msg) => {
            debug!(parent: &span_peer, ?msg, "recv");
            handle.emit(ProtocolEvent::Control {
                remote: remote_peer.clone(),
                message: msg.clone(),
            });
            handle.emit(ProtocolEvent::Disconnected {
                remote: remote_peer.clone(),
            });
            return Ok(());
        }
    }

    let (ready_engine, action) = exchanged_engine.on_incoming_ready();
    let parts = framed_peer.into_parts();
    let mut next_parts = FramedParts::new(parts.io, codec::ReadyCodec::new());
    next_parts.read_buf = parts.read_buf;
    next_parts.write_buf = parts.write_buf;
    let mut framed_ready = Framed::from_parts(next_parts);
    let ready_peer = ready_engine.state.remote.clone();
    handle.emit(ProtocolEvent::ReadyEntered {
        remote: ready_peer.clone(),
    });
    if apply_ready_action(action, &mut framed_ready, &handle, &ready_peer, &span).await? {
        handle.emit(ProtocolEvent::Disconnected {
            remote: Some(ready_peer),
        });
        return Ok(());
    }

    let mut command_rx = handle.take_command_rx();
    let mut should_break = false;
    {
        let span = debug_span!(parent: &span, "READY");
        info!(parent: &span, peer_id=%tls_peer_id, "new peer");
        while !should_break {
            tokio::select! {
                maybe_cmd = async {
                    match command_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => future::pending::<Option<ProtocolCommand>>().await,
                    }
                } => {
                    match maybe_cmd {
                        Some(ProtocolCommand::SendReady(msg)) => {
                            debug!(parent: &span, ?msg, "command-send-ready");
                            framed_ready.send(ReadyStateMessage::Ready(msg)).await?;
                        }
                        Some(ProtocolCommand::Close) => {
                            debug!(parent: &span, "command-close");
                            should_break = true;
                        }
                        None => {
                            command_rx = None;
                        }
                    }
                }
                maybe_msg = framed_ready.next() => {
                    let Some(result) = maybe_msg else {
                        debug!(parent: &span, "stream-closed");
                        break;
                    };
                    let msg = match result {
                        Ok(msg) => msg,
                        Err(e) => {
                            handle.emit(ProtocolEvent::Disconnected {
                                remote: Some(ready_peer.clone()),
                            });
                            return Err(e);
                        }
                    };
                    match msg {
                        ReadyStateMessage::Ready(msg) => {
                            debug!(parent: &span, ?msg, "recv-ready");
                            handle.emit(ProtocolEvent::ReadyMessage {
                                remote: ready_peer.clone(),
                                message: msg.clone(),
                            });
                            let action = ready_engine.on_incoming_ready_msg(msg);
                            if apply_ready_action(action, &mut framed_ready, &handle, &ready_peer, &span).await? {
                                should_break = true;
                            }
                        }
                        ReadyStateMessage::Sync(msg) => {
                            debug!(parent: &span, ?msg, "recv-sync");
                            handle.emit(ProtocolEvent::SyncMessage {
                                remote: ready_peer.clone(),
                                message: msg.clone(),
                            });
                            let action = ready_engine.on_incoming_sync_msg(msg);
                            if apply_ready_action(action, &mut framed_ready, &handle, &ready_peer, &span).await? {
                                should_break = true;
                            }
                        }
                        ReadyStateMessage::Control(msg @ ControlMessage::Error(_)) => {
                            debug!(parent: &span, ?msg, "recv-control");
                            handle.emit(ProtocolEvent::Control {
                                remote: Some(ready_peer.clone()),
                                message: msg.clone(),
                            });
                            should_break = true;
                        }
                        ReadyStateMessage::Control(msg @ ControlMessage::Throttle { .. }) => {
                            debug!(parent: &span, ?msg, "recv-control");
                            handle.emit(ProtocolEvent::Control {
                                remote: Some(ready_peer.clone()),
                                message: msg.clone(),
                            });
                        }
                    }
                }
            }
        }
    }

    handle.emit(ProtocolEvent::Disconnected {
        remote: Some(ready_peer),
    });
    Ok(())
}

async fn apply_peer_id_action<S, IO>(
    action: state::Action<S>,
    framed: &mut Framed<IO, codec::PeerIdCodec>,
    handle: &ProtocolHandle,
    remote: Option<&PublicPeer>,
    span: &tracing::Span,
) -> Result<bool, Error>
where
    S: state::State<Message = PeerIdStateMessage>,
    IO: fmt::Debug + AsyncWrite + AsyncRead + std::marker::Unpin,
{
    match action {
        state::Action::Send(msg) => {
            match &msg {
                PeerIdStateMessage::PeerId(inner) => {
                    debug!(parent: span, msg=?inner, "send");
                    framed.send(msg).await?;
                }
                PeerIdStateMessage::Control(control) => {
                    debug!(parent: span, msg=?control, "send");
                    framed.send(msg.clone()).await?;
                    handle.emit(ProtocolEvent::Control {
                        remote: remote.cloned(),
                        message: control.clone(),
                    });
                }
            }
            Ok(false)
        }
        state::Action::Throttle(reason) => {
            let msg = ControlMessage::Throttle {
                key: ThrottleScope::Global,
                reason,
            };
            debug!(parent: span, ?msg, "state-throttle");
            framed
                .send(PeerIdStateMessage::Control(msg.clone()))
                .await?;
            handle.emit(ProtocolEvent::Control {
                remote: remote.cloned(),
                message: msg,
            });
            Ok(false)
        }
        state::Action::CloseWithError(reason) => {
            let msg = ControlMessage::Error(reason.to_string());
            debug!(parent: span, ?msg, "state-close-error");
            framed
                .send(PeerIdStateMessage::Control(msg.clone()))
                .await?;
            handle.emit(ProtocolEvent::Control {
                remote: remote.cloned(),
                message: msg,
            });
            Ok(true)
        }
        state::Action::CloseQuietly => {
            debug!(parent: span, "state-close-quiet");
            Ok(true)
        }
        state::Action::Noop => Ok(false),
    }
}

async fn apply_ready_action<IO>(
    action: state::Action<state::ReadyState>,
    framed: &mut Framed<IO, codec::ReadyCodec>,
    handle: &ProtocolHandle,
    remote: &PublicPeer,
    span: &tracing::Span,
) -> Result<bool, Error>
where
    IO: fmt::Debug + AsyncWrite + AsyncRead + std::marker::Unpin,
{
    match action {
        state::Action::Send(msg) => {
            match &msg {
                ReadyStateMessage::Ready(inner) => {
                    debug!(parent: span, ?inner, "state-send-ready");
                    framed.send(msg).await?;
                }
                ReadyStateMessage::Sync(sync) => {
                    debug!(parent: span, ?sync, "state-send-sync");
                    framed.send(msg).await?;
                }
                ReadyStateMessage::Control(control) => {
                    debug!(parent: span, ?control, "state-send-control");
                    framed.send(msg.clone()).await?;
                    handle.emit(ProtocolEvent::Control {
                        remote: Some(remote.clone()),
                        message: control.clone(),
                    });
                }
            }
            Ok(false)
        }
        state::Action::Throttle(reason) => {
            let msg = ControlMessage::Throttle {
                key: ThrottleScope::Global,
                reason,
            };
            debug!(parent: span, ?msg, "state-throttle");
            framed.send(ReadyStateMessage::Control(msg.clone())).await?;
            handle.emit(ProtocolEvent::Control {
                remote: Some(remote.clone()),
                message: msg,
            });
            Ok(false)
        }
        state::Action::CloseWithError(reason) => {
            let msg = ControlMessage::Error(reason.to_string());
            debug!(parent: span, ?msg, "state-close-error");
            framed.send(ReadyStateMessage::Control(msg.clone())).await?;
            handle.emit(ProtocolEvent::Control {
                remote: Some(remote.clone()),
                message: msg,
            });
            Ok(true)
        }
        state::Action::CloseQuietly => {
            debug!(parent: span, "state-close-quiet");
            Ok(true)
        }
        state::Action::Noop => Ok(false),
    }
}
