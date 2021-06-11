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
from typing import TYPE_CHECKING, Any, Dict, Generator, Optional, Set

from structlog import get_logger
from twisted.internet.interfaces import IDelayedCall, ITransport
from twisted.protocols.basic import LineReceiver
from twisted.python.failure import Failure

from hathor.conf import HathorSettings
from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.peer_id import PeerId
from hathor.p2p.rate_limiter import RateLimiter
from hathor.p2p.states import BaseState, HelloState, PeerIdState, ReadyState
from hathor.profiler import get_cpu_profiler

if TYPE_CHECKING:
    from hathor.manager import HathorManager  # noqa: F401
    from hathor.p2p.manager import ConnectionsManager  # noqa: F401

settings = HathorSettings()
logger = get_logger()
cpu = get_cpu_profiler()


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

    class RateLimitKeys(str, Enum):
        GLOBAL = 'global'

    class WarningFlags(str, Enum):
        NO_PEER_ID_URL = 'no_peer_id_url'
        NO_ENTRYPOINTS = 'no_entrypoints'

    network: str
    my_peer: PeerId
    connections: Optional['ConnectionsManager']
    node: 'HathorManager'
    app_version: str
    last_message: float
    peer: Optional[PeerId]
    transport: ITransport
    state: Optional[BaseState]
    connection_time: float
    _state_instances: Dict[PeerState, BaseState]
    connection_string: Optional[str]
    expected_peer_id: Optional[str]
    warning_flags: Set[str]
    aborting: bool
    diff_timestamp: Optional[int]
    idle_timeout: int

    def __init__(self, network: str, my_peer: PeerId, connections: Optional['ConnectionsManager'] = None, *,
                 node: 'HathorManager', use_ssl: bool, inbound: bool) -> None:
        self.network = network
        self.my_peer = my_peer
        self.connections = connections
        self.node = node

        if self.connections is not None:
            assert self.connections.reactor is not None
            self.reactor = self.connections.reactor
        else:
            from twisted.internet import reactor
            self.reactor = reactor

        # Indicate whether it is an inbound connection (true) or an outbound connection (false).
        self.inbound = inbound

        # Maximum period without receiving any messages.
        self.idle_timeout = settings.PEER_IDLE_TIMEOUT
        self._idle_timeout_call_later: Optional[IDelayedCall] = None

        self._state_instances = {}

        self.app_version = 'Unknown'
        self.diff_timestamp = None

        # The peer on the other side of the connection.
        self.peer = None

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
        self.ratelimit: RateLimiter = RateLimiter()
        # self.ratelimit.set_limit(self.RateLimitKeys.GLOBAL, 120, 60)

        # Connection string of the peer
        # Used to validate if entrypoints has this string
        self.connection_string: Optional[str] = None

        # Peer id sent in the connection url that is expected to connect (optional)
        self.expected_peer_id: Optional[str] = None

        # Set of warning flags that may be added during the connection process
        self.warning_flags: Set[str] = set()

        # This property is used to indicate the connection is being dropped (either because of a prototcol error or
        # because the remote disconnected), and the following buffered lines are ignored.
        # See `HathorLineReceiver.lineReceived`
        self.aborting = False

        self.use_ssl: bool = use_ssl

        self.log = logger.new()

    def change_state(self, state_enum: PeerState) -> None:
        """Called to change the state of the connection."""
        if state_enum not in self._state_instances:
            state_cls = state_enum.value
            instance = state_cls(self)
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
        parts = []

        remote = self.transport.getPeer()
        if hasattr(remote, 'host'):
            parts.append(remote.host)
        parts.append(':')

        if hasattr(remote, 'port'):
            parts.append(remote.port)

        return ''.join(str(x) for x in parts)

    def get_short_peer_id(self) -> Optional[str]:
        """Get peer id for logging."""
        if self.peer and self.peer.id:
            return self.peer.id[:7]
        return None

    def get_logger_context(self) -> Dict[str, Optional[str]]:
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

    def on_outbound_connect(self, url_peer_id: Optional[str], connection_string: str) -> None:
        """Called when we successfully establish an outbound connection to a peer."""
        if url_peer_id:
            # Set in protocol the peer id extracted from the URL that must be validated
            self.expected_peer_id = url_peer_id
        else:
            # Add warning flag
            self.warning_flags.add(self.WarningFlags.NO_PEER_ID_URL)

        # Setting connection string in protocol, so we can validate it matches the entrypoints data
        self.connection_string = connection_string

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
    def recv_message(self, cmd: ProtocolMessages, payload: str) -> Optional[Generator[Any, Any, None]]:
        """ Executed when a new message arrives.
        """
        assert self.state is not None

        self.last_message = self.node.reactor.seconds()
        self.reset_idle_timeout()

        if not self.ratelimit.add_hit(self.RateLimitKeys.GLOBAL):
            self.state.send_throttle(self.RateLimitKeys.GLOBAL)
            return None

        fn = self.state.cmd_map.get(cmd)
        if fn is not None:
            try:
                return fn(payload)
            except Exception:
                self.log.warn('recv_message processing error', exc_info=True)
                raise
        else:
            self.send_error_and_close_connection('Invalid Command: {}'.format(cmd))

        return None

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
        # from twisted docs: "If a producer is being used with the transport, loseConnection will only close
        # the connection once the producer is unregistered." We call on_exit to make sure any producers (like
        # the one from node_sync) are unregistered
        if self.state:
            self.state.prepare_to_disconnect()
        self.log.debug('disconnecting', reason=reason, force=force)
        if not force:
            self.transport.loseConnection()
            self.aborting = True
        else:
            self.transport.abortConnection()

    def handle_error(self, payload: str) -> None:
        """ Executed when an ERROR command is received.
        """
        self.log.warn('remote error', payload=payload)


class HathorLineReceiver(HathorProtocol, LineReceiver):
    """ Implements HathorProtocol in a LineReceiver protocol.
    It is simply a TCP connection which sends one message per line.
    """
    MAX_LENGTH = 65536

    def connectionMade(self) -> None:
        super(HathorLineReceiver, self).connectionMade()
        self.setLineMode()
        self.on_connect()

    def connectionLost(self, reason: Failure) -> None:
        super(HathorLineReceiver, self).connectionLost()
        self.on_disconnect(reason)

    def lineLengthExceeded(self, line: str) -> None:
        self.log.warn('line length exceeded', line=line, line_len=len(line), max_line_len=self.MAX_LENGTH)
        super(HathorLineReceiver, self).lineLengthExceeded(line)

    @cpu.profiler(key=lambda self: 'p2p!{}'.format(self.get_short_remote()))
    def lineReceived(self, line: bytes) -> Optional[Generator[Any, Any, None]]:
        if self.aborting:
            # XXX: this can happen when we receive more than one line at once (normally happens when the remote buffers
            # and the next datagram contains several lines) and for any reason (like a protocol error) we decide to
            # abort and close the connection, HathorLineReceive.lineReceived will still be called for the buffered
            # lines. If that happens we just ignore those messages.
            self.log.debug('ignore received messager after abort')
            return None

        self.metrics.received_messages += 1
        self.metrics.received_bytes += len(line)

        try:
            sline = line.decode('utf-8')
        except UnicodeDecodeError:
            self.transport.loseConnection()
            return None

        msgtype, _, msgdata = sline.partition(' ')
        try:
            cmd = ProtocolMessages(msgtype)
        except ValueError:
            self.transport.loseConnection()
            return None
        else:
            self.recv_message(cmd, msgdata)
            return None

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
