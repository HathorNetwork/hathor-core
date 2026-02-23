# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import time
from enum import Enum
from typing import TYPE_CHECKING, Optional, cast

from structlog import get_logger
from twisted.internet import defer
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IDelayedCall, ITCPTransport, ITransport
from twisted.internet.protocol import connectionDone
from twisted.protocols.basic import LineReceiver
from twisted.python.failure import Failure

from hathor.conf.settings import HathorSettings
from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.peer import PrivatePeer, PublicPeer, UnverifiedPeer
from hathor.p2p.peer_endpoint import PeerEndpoint
from hathor.p2p.peer_id import PeerId
from hathor.p2p.peer_storage import UnverifiedPeerStorage
from hathor.p2p.rate_limiter import RateLimiter
from hathor.p2p.states import BaseState, HelloState, PeerIdState, ReadyState
from hathor.p2p.sync_version import SyncVersion
from hathor.p2p.utils import format_address
from hathor.profiler import get_cpu_profiler

if TYPE_CHECKING:
    from hathor.manager import HathorManager  # noqa: F401
    from hathor.p2p.manager import ConnectionsManager  # noqa: F401

logger = get_logger()
cpu = get_cpu_profiler()

MISBEHAVIOR_KEY = 'misbehavior'
MISBEHAVIOR_THRESHOLD = 100
MISBEHAVIOR_WINDOW = 3600  # decay in 1h


class HathorProtocol:
    """ Implements Hathor Peer-to-Peer Protocol. An instance of this class is
    created for each connection.

    When the connection is established, the protocol waits for a
    HELLO message, which will identify the application and give a
    nonce value.

    After receiving a HELLO message, the peer must reply with a PEER-ID
    message, which will identify the peer through its id, public key,
    and endpoints. The connection is encrypted and its public key in the
    certificate must be equal to the given public key.

    After the PEER-ID message, the peer is ready to communicate.

    The available states are listed in PeerState class.
    The available commands are listed in the ProtocolMessages class.
    """

    class PeerState(Enum):
        HELLO = HelloState
        PEER_ID = PeerIdState
        READY = ReadyState

    class ConnectionType(Enum):
        """ Types of Connection as inputs for an instance of the Hathor Protocol. """
        OUTGOING = 0
        INCOMING = 1
        DISCOVERED = 2
        CHECK_ENTRYPOINTS = 3

    class ConnectionState(Enum):
        """ State of connection of two peers - either in a slot queue or active. """
        CREATED = 0
        CONNECTING = 1
        READY = 2

    class RateLimitKeys(str, Enum):
        GLOBAL = 'global'

    class WarningFlags(str, Enum):
        NO_ENTRYPOINTS = 'no_entrypoints'

    my_peer: PrivatePeer
    connections: 'ConnectionsManager'
    node: 'HathorManager'
    app_version: str
    last_message: float
    _peer: Optional[PublicPeer]
    transport: Optional[ITransport]
    state: Optional[BaseState]
    connection_time: float
    _state_instances: dict[PeerState, BaseState]
    entrypoint: Optional[PeerEndpoint]
    warning_flags: set[str]
    aborting: bool
    diff_timestamp: Optional[int]
    idle_timeout: int
    sync_version: Optional[SyncVersion]  # version chosen to be used on this connection
    capabilities: set[str]  # capabilities received from the peer in HelloState
    connection_state: ConnectionState  # in slot queue, connecting or ready/in-slot.

    @property
    def peer(self) -> PublicPeer:
        assert self._peer is not None, 'self.peer must be initialized'
        return self._peer

    def __init__(
        self,
        my_peer: PrivatePeer,
        p2p_manager: 'ConnectionsManager',
        *,
        settings: HathorSettings,
        use_ssl: bool,
        connection_type: ConnectionType,
    ) -> None:
        self._settings = settings
        self.my_peer = my_peer
        self.connections = p2p_manager

        assert p2p_manager.manager is not None
        self.node = p2p_manager.manager

        assert self.connections.reactor is not None
        self.reactor = self.connections.reactor

        # Type of Connection
        # 0 == Outgoing, 1 == Incoming, 2 == Discovered, 3 == For Checking Entrypoints.
        self.connection_type = connection_type

        # Connection State
        self.connection_state = HathorProtocol.ConnectionState.INIT

        # Maximum period without receiving any messages.
        self.idle_timeout = self._settings.PEER_IDLE_TIMEOUT
        self._idle_timeout_call_later: Optional[IDelayedCall] = None

        self._state_instances = {}

        self.app_version = 'Unknown'
        self.diff_timestamp = None

        # The peer on the other side of the connection.
        self._peer = None

        # The last time a message has been received from this peer.
        self.last_message = 0
        self.metrics: 'ConnectionMetrics' = ConnectionMetrics()

        # The last time a request was send to this peer.
        self.last_request = 0

        # The time in which the connection was established.
        self.connection_time = 0.0

        # The current state of the connection.
        self.state: Optional[BaseState] = None

        # Default rate limit
        self.ratelimit: RateLimiter = RateLimiter(self.reactor)
        # self.ratelimit.set_limit(self.RateLimitKeys.GLOBAL, 120, 60)

        # Connection string of the peer
        # Used to validate if entrypoints has this string
        self.entrypoint: Optional[PeerEndpoint] = None

        # Peer id sent in the connection url that is expected to connect (optional)
        self.expected_peer_id: PeerId | None = None

        # Set of warning flags that may be added during the connection process
        self.warning_flags: set[str] = set()

        # This property is used to indicate the connection is being dropped (either because of a prototcol error or
        # because the remote disconnected), and the following buffered lines are ignored.
        # See `HathorLineReceiver.lineReceived`
        self.aborting = False

        self.use_ssl: bool = use_ssl

        # List of peers received from the network.
        # We cannot trust their identity before we connect to them.
        self.unverified_peer_storage = UnverifiedPeerStorage(
            rng=self.connections.rng,
            max_size=self._settings.MAX_UNVERIFIED_PEERS_PER_CONN,
        )

        # Misbehavior score that is increased after protocol violations.
        self._misbehavior_score = RateLimiter(self.reactor)
        self._misbehavior_score.set_limit(MISBEHAVIOR_KEY, MISBEHAVIOR_THRESHOLD, MISBEHAVIOR_WINDOW)

        # Protocol version is initially unset
        self.sync_version = None

        self.log = logger.new()

        self.capabilities = set()

    def change_state(self, state_enum: PeerState) -> None:
        """Called to change the state of the connection."""
        if state_enum not in self._state_instances:
            state_cls = state_enum.value
            instance = state_cls(self, self._settings)
            instance.state_name = state_enum.name
            self._state_instances[state_enum] = instance
        new_state = self._state_instances[state_enum]
        if new_state != self.state:
            if self.state:
                self.state.on_exit()
            self.state = new_state
            if self.state:
                self.state.on_enter()

    def is_state(self, state_enum: PeerState) -> bool:
        """Checks whether current state is `state_enum`."""
        return isinstance(self.state, state_enum.value)

    def get_short_remote(self) -> str:
        """Get remote for logging."""
        assert self.transport is not None
        return format_address(self.transport.getPeer())

    def get_peer_id(self) -> Optional[PeerId]:
        """Get peer id for logging."""
        if self._peer is not None:
            return self.peer.id
        return None

    def get_short_peer_id(self) -> Optional[str]:
        """Get short peer id for logging."""
        if self._peer and self._peer.id:
            return str(self.peer.id)[:7]
        return None

    def get_logger_context(self) -> dict[str, Optional[str]]:
        """Return the context for logging."""
        return {
            'remote': self.get_short_remote(),
            'peer_id': self.get_short_peer_id(),
        }

    def update_log_context(self) -> None:
        self.log = self.log.bind(**self.get_logger_context())

    def disable_idle_timeout(self) -> None:
        """Disable idle timeout. Used for testing."""
        self.idle_timeout = -1
        self.reset_idle_timeout()

    def reset_idle_timeout(self) -> None:
        """Reset idle timeout."""
        if self._idle_timeout_call_later is not None:
            self._idle_timeout_call_later.cancel()
            self._idle_timeout_call_later = None
        if self.idle_timeout > 0:
            self._idle_timeout_call_later = self.reactor.callLater(self.idle_timeout, self.on_idle_timeout)

    def on_idle_timeout(self) -> None:
        """Called when a connection is idle for too long."""
        self._idle_timeout_call_later = None
        self.log.warn('Connection closed for idle timeout.')
        # We cannot use self.disconnect() because it will wait to send pending data.
        self.disconnect(force=True)

    def increase_misbehavior_score(self, *, weight: int) -> None:
        """Increase misbehavior score and acts if the threshold is reached."""
        if not self._misbehavior_score.add_hit(MISBEHAVIOR_KEY, weight):
            score = self._misbehavior_score.get_limit(MISBEHAVIOR_KEY)
            self.log.warn('connection closed due to misbehavior', score=score)
            self.send_error_and_close_connection('Misbehavior score is too high')

    def on_connect(self) -> None:
        """ Executed when the connection is established.
        """
        assert not self.aborting
        self.update_log_context()
        self.log.debug('new connection')

        self.connection_time = time.time()

        self.reset_idle_timeout()

        # The initial state is HELLO.
        self.change_state(self.PeerState.HELLO)

        if self.connections:
            self.connections.on_peer_connect(self)

    def on_outbound_connect(self, entrypoint: PeerEndpoint, peer: UnverifiedPeer | PublicPeer | None) -> None:
        """Called when we successfully establish an outbound connection to a peer."""
        # Save the used entrypoint in protocol so we can validate that it matches the entrypoints data
        if entrypoint.peer_id is not None and peer is not None:
            assert entrypoint.peer_id == peer.id

        self.expected_peer_id = peer.id if peer else entrypoint.peer_id
        self.entrypoint = entrypoint

    def on_peer_ready(self) -> None:
        assert self.connections is not None
        assert self.peer is not None
        self.update_log_context()
        self.connections.on_peer_ready(self)
        self.log.info('peer connected', peer_id=self.peer.id)

    def on_disconnect(self, reason: Failure) -> None:
        """ Executed when the connection is lost.
        """
        if self.is_state(self.PeerState.READY):
            self.log.info('disconnected', reason=reason.getErrorMessage())
        else:
            self.log.debug('disconnected', reason=reason.getErrorMessage())
        if self._idle_timeout_call_later:
            self._idle_timeout_call_later.cancel()
            self._idle_timeout_call_later = None
        self.aborting = True
        self.update_log_context()
        if self.state:
            self.state.on_exit()
            self.state = None
        if self.connections:
            self.connections.on_peer_disconnect(self)

    def send_message(self, cmd: ProtocolMessages, payload: Optional[str] = None) -> None:
        """ A generic message which must be implemented to send a message
        to the peer. It depends on the underlying protocol in which
        HathorProtocol is running.
        """
        raise NotImplementedError

    @cpu.profiler(key=lambda self, cmd: 'p2p-cmd!{}'.format(str(cmd)))
    def recv_message(self, cmd: ProtocolMessages, payload: str) -> None:
        """ Executed when a new message arrives.
        """
        assert self.state is not None

        now = self.reactor.seconds()
        self.last_message = now
        if self._peer is not None:
            self.peer.info.last_seen = now

        if not self.ratelimit.add_hit(self.RateLimitKeys.GLOBAL):
            self.state.send_throttle(self.RateLimitKeys.GLOBAL.value)
            return

        cmd_handler = self.state.cmd_map.get(cmd)
        if cmd_handler is None:
            self.log.debug('cmd not found', cmd=cmd, payload=payload, available=list(self.state.cmd_map.keys()))
            self.send_error_and_close_connection('Invalid Command: {} {}'.format(cmd, payload))
            return

        deferred_result: Deferred[None] = defer.maybeDeferred(cmd_handler, payload)
        deferred_result \
            .addCallback(lambda _: self.reset_idle_timeout()) \
            .addErrback(self._on_cmd_handler_error, cmd)

    def _on_cmd_handler_error(self, failure: Failure, cmd: ProtocolMessages) -> None:
        self.log.error(f'recv_message processing error:\n{failure.getTraceback()}', reason=failure.getErrorMessage())
        self.send_error_and_close_connection(f'Error processing "{cmd.value}" command')

    def send_error(self, msg: str) -> None:
        """ Send an error message to the peer.
        """
        if self.is_state(self.PeerState.READY):
            self.log.warn('send error', msg=msg)
        else:
            self.log.debug('send error', msg=msg)
        self.send_message(ProtocolMessages.ERROR, msg)

    def send_error_and_close_connection(self, msg: str) -> None:
        """ Send an ERROR message to the peer, and then closes the connection.
        """
        self.send_error(msg)
        self.disconnect()

    def disconnect(self, reason: str = '', *, force: bool = False) -> None:
        """Close connection."""
        assert self.transport is not None
        # from hathor.simulator.fake_connection import HathorStringTransport
        # assert isinstance(self.transport, (ITCPTransport, HathorStringTransport))
        # FIXME: we can't easily use the above strategy because ITCPTransport is a zope.interface and thus won't have
        #        an "isinstance" relation, and HathorStringTransport does not implement the zope.interface, but does
        #        implement the needed "sub-interface" for this method, a typing.cast is being used to fool mypy, but we
        #        should come up with a proper solution
        transport = cast(ITCPTransport, self.transport)

        # from twisted docs: "If a producer is being used with the transport, loseConnection will only close
        # the connection once the producer is unregistered." We call on_exit to make sure any producers (like
        # the one from node_sync) are unregistered
        if self.state:
            self.state.prepare_to_disconnect()
        self.log.debug('disconnecting', reason=reason, force=force)
        if not force:
            transport.loseConnection()
            self.aborting = True
        else:
            transport.abortConnection()

    def on_receive_peer(self, peer: UnverifiedPeer) -> None:
        """ Update a peer information in our storage, the manager's connection loop will pick it later.
        """
        # ignore when the remote echo backs our own peer
        if peer.id == self.my_peer.id:
            return
        # ignore peers we've already connected to
        if peer.id in self.connections.verified_peer_storage:
            return
        # merge with known previous information received from this peer since we don't know what's right (a peer can
        # change their entrypoints, but the old could still echo, since we haven't connected yet don't assume anything
        # and just merge them)
        self.unverified_peer_storage.add_or_merge(peer)

    def handle_error(self, payload: str) -> None:
        """ Executed when an ERROR command is received.
        """
        self.log.warn('remote error', payload=payload)

    def is_sync_enabled(self) -> bool:
        """Return true if sync is enabled for this connection."""
        if not self.is_state(self.PeerState.READY):
            return False
        assert isinstance(self.state, ReadyState)
        return self.state.sync_agent.is_sync_enabled()

    def enable_sync(self) -> None:
        """Enable sync for this connection."""
        assert self.is_state(self.PeerState.READY)
        assert isinstance(self.state, ReadyState)
        self.log.info('enable sync')
        self.state.sync_agent.enable_sync()

    def disable_sync(self) -> None:
        """Disable sync for this connection."""
        assert self.is_state(self.PeerState.READY)
        assert isinstance(self.state, ReadyState)
        self.log.info('disable sync')
        self.state.sync_agent.disable_sync()


class HathorLineReceiver(LineReceiver, HathorProtocol):
    """ Implements HathorProtocol in a LineReceiver protocol.
    It is simply a TCP connection which sends one message per line.
    """
    MAX_LENGTH = 65536

    def connectionMade(self) -> None:
        super(HathorLineReceiver, self).connectionMade()
        self.setLineMode()
        self.on_connect()

    def connectionLost(self, reason: Failure = connectionDone) -> None:
        super(HathorLineReceiver, self).connectionLost()
        self.on_disconnect(reason)

    def lineLengthExceeded(self, line: str) -> None:
        self.log.warn('line length exceeded', line=line, line_len=len(line), max_line_len=self.MAX_LENGTH)
        super(HathorLineReceiver, self).lineLengthExceeded(line)

    @cpu.profiler(key=lambda self: 'p2p!{}'.format(self.get_short_remote()))
    def lineReceived(self, line: bytes) -> None:
        assert self.transport is not None

        if self.aborting:
            # XXX: this can happen when we receive more than one line at once (normally happens when the remote buffers
            # and the next datagram contains several lines) and for any reason (like a protocol error) we decide to
            # abort and close the connection, HathorLineReceive.lineReceived will still be called for the buffered
            # lines. If that happens we just ignore those messages.
            self.log.debug('ignore received messager after abort')
            return

        self.metrics.received_messages += 1
        self.metrics.received_bytes += len(line)

        try:
            sline = line.decode('utf-8')
        except UnicodeDecodeError:
            self.transport.loseConnection()
            return

        msgtype, _, msgdata = sline.partition(' ')
        try:
            cmd = ProtocolMessages(msgtype)
        except ValueError:
            self.transport.loseConnection()
            return

        self.recv_message(cmd, msgdata)

    def send_message(self, cmd_enum: ProtocolMessages, payload: Optional[str] = None) -> None:
        cmd = cmd_enum.value
        if payload:
            line = '{} {}'.format(cmd, payload).encode('utf-8')
        else:
            line = cmd.encode('utf-8')
        self.metrics.sent_messages += 1
        self.metrics.sent_bytes += len(line)
        self.sendLine(line)


class ConnectionMetrics:
    def __init__(self) -> None:
        self.received_messages: int = 0
        self.sent_messages: int = 0
        self.received_bytes: int = 0
        self.sent_bytes: int = 0
        self.received_txs: int = 0
        self.discarded_txs: int = 0
        self.received_blocks: int = 0
        self.discarded_blocks: int = 0

    def format_bytes(self, value: int) -> str:
        """ Format bytes in MB and kB.
        """
        if value > 1024*1024:
            return '{:11.2f} MB'.format(value / 1024 / 1024)
        elif value > 1024:
            return '{:11.2f} kB'.format(value / 1024)
        else:
            return '{} B'.format(value)

    def print_stats(self, prefix: str = '') -> None:
        """ Print a status of the metrics in stdout.
        """
        print('----')
        print('{}Received:       {:8d} messages  {}'.format(
            prefix,
            self.received_messages,
            self.format_bytes(self.received_bytes))
        )
        print('{}Sent:           {:8d} messages  {}'.format(
            prefix,
            self.sent_messages,
            self.format_bytes(self.sent_bytes))
        )
        print('{}Blocks:         {:8d} received  {:8d} discarded ({:2.0f}%)'.format(
            prefix,
            self.received_blocks,
            self.discarded_blocks,
            100.0 * self.discarded_blocks / (self.received_blocks + self.discarded_blocks)
        ))
        print('{}Transactions:   {:8d} received  {:8d} discarded ({:2.0f}%)'.format(
            prefix,
            self.received_txs,
            self.discarded_txs,
            100.0 * self.discarded_txs / (self.received_txs + self.discarded_txs)
        ))
        print('----')
