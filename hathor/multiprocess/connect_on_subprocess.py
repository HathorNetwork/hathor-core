#  Copyright 2024 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import os
import pickle
import signal
import sys
from pathlib import Path
from typing import Callable, Generic, TypeVar

from structlog import get_logger
from twisted.internet import tcp
from twisted.internet.error import ProcessExitedAlready
from twisted.internet.interfaces import IAddress, ITransport
from twisted.internet.protocol import ProcessProtocol, Protocol, ServerFactory
from twisted.protocols.policies import ProtocolWrapper
from twisted.protocols.tls import BufferingTLSTransport
from twisted.python.failure import Failure

from hathor.cli.util import LoggingOptions, LoggingOutput
from hathor.multiprocess.subprocess_runner import SubprocessSpawnArgs
from hathor.multiprocess.utils import log_connection_closed
from hathor.p2p.peer_endpoint import PeerAddress
from hathor.reactor import ReactorProtocol
from hathor.utils.pydantic import BaseModel

logger = get_logger()

T = TypeVar('T', bound=BaseModel)


class ConnectOnSubprocessFactory(ServerFactory, Generic[T]):
    """
    This class is a Twisted factory for delegating protocol connections to subprocesses. When a connection is made,
    the protocol spawns a subprocess and transfers the connection's file descriptor to it. That subprocess runs code
    specified in a `main_file` defined when the factory is constructed.
    """

    __slots__ = (
        'reactor',
        '_main_file',
        '_serialized_logging_args',
        '_custom_args',
        '_built_protocol_callback'
    )

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        main_file: Path,
        logging_args: tuple[LoggingOutput, LoggingOptions, bool],
        custom_args: T,
        built_protocol_callback: Callable[[PeerAddress], None] | None,
    ) -> None:
        """
        The `main_file` parameter should be a `__main__` file that calls the `setup_subprocess_runner` function.

        Example:

        ```
        def build_my_factory(reactor: ReactorProtocol) -> Factory:
            raise NotImplementedError

        if __name__ == '__main__':
            setup_subprocess_runner(build_my_factory)
        ```
        """
        self.reactor = reactor
        self._main_file = main_file
        self._serialized_logging_args = pickle.dumps(logging_args).hex()
        self._custom_args = custom_args
        self._built_protocol_callback = built_protocol_callback

    def buildProtocol(self, addr: IAddress) -> Protocol | None:
        peer_addr = PeerAddress.from_address(addr)
        if self._built_protocol_callback:
            self._built_protocol_callback(peer_addr)

        return _ConnectOnSubprocessProtocol(
            reactor=self.reactor,
            main_file=self._main_file,
            addr=peer_addr,
            logging_args=self._serialized_logging_args,
            custom_args=self._custom_args,
        )


class _ConnectOnSubprocessProtocol(Protocol, Generic[T]):
    """
    This class is a Twisted protocol to delegate connections to subprocesses. When a connection is made, the
    protocol spawns a subprocess and transfers the connection's file descriptor to it. That subprocess runs code
    specified in a `main_file` defined in its factory, above.
    """

    __slots__ = ('log', 'reactor', '_main_file', '_addr', '_logging_args', '_custom_args')

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        main_file: Path,
        addr: PeerAddress,
        logging_args: str,
        custom_args: T,
    ) -> None:
        self.log = logger.new(addr=addr)
        self.reactor = reactor
        self._main_file = main_file
        self._addr = addr
        self._logging_args = logging_args
        self._custom_args = custom_args

    def makeConnection(self, transport: ITransport) -> None:
        """Spawn a subprocess and transfer the connection's file descriptor to it."""
        assert isinstance(transport, ProtocolWrapper)
        wrapped_transport = transport.transport
        if isinstance(transport, BufferingTLSTransport):
            assert isinstance(wrapped_transport, ProtocolWrapper)
            connection = wrapped_transport.transport
        else:
            connection = wrapped_transport

        assert isinstance(connection, tcp.Connection), connection
        assert self._addr == PeerAddress.from_address(transport.getPeer())

        fileno = connection.fileno()
        self.log.info('spawning new subprocess for connection', fileno=fileno, main_pid=os.getpid())
        main_file_path = str(self._main_file.absolute())
        subprocess_args = SubprocessSpawnArgs(
            addr=self._addr,
            fileno=fileno,
            custom_args=self._custom_args,
        )

        # - We spawn the new subprocess by running python on `self._main_file` using the same python executable
        #   as us (the main process).
        # - We pass the addr and fileno of the connection to argv, together with custom args.
        # - We execute with the same env vars and working path from us (the main process).
        # - We configure direct mapping to the following file descriptors: stdout (1), stderr (2), and fileno.
        subprocess_transport = self.reactor.spawnProcess(
            processProtocol=_SubprocessProtocol(addr=self._addr),
            executable=sys.executable,
            args=[sys.executable, main_file_path, self._logging_args, subprocess_args.json_dumpb().hex()],
            env=os.environ,
            path=os.getcwd(),
            childFDs={1: 1, 2: 2, fileno: fileno},
        )

        # Just after spawning the subprocess, the socket associated with the connection is made available in the
        # subprocess through its file descriptor. We must close it here as we (the main process) must never read
        # from it.
        connection.socket.close()

        self.log.info(
            'spawned subprocess for connection',
            fileno=fileno,
            subprocess_pid=subprocess_transport.pid,
        )

    def dataReceived(self, data: bytes) -> None:
        """Data must never be received in this protocol since its spawned subprocess is intercepting all messages."""
        self.log.error('subprocess data received on the main process', data=data)
        raise AssertionError('ConnectOnSubprocessProtocol.dataReceived should never be called!')


class _SubprocessProtocol(ProcessProtocol):
    """
    This class is a twisted ProcessProtocol subclass to be used in the _ConnectOnSubprocessProtocol.

    When _ConnectOnSubprocessProtocol spawns a new subprocess, it does so using this class as its
    communication handle to the subprocess.
    """

    __slots__ = ('log', '_addr')

    def __init__(self, *, addr: PeerAddress) -> None:
        self.log = logger.new(addr=str(addr))
        self._addr = addr

    def connectionMade(self) -> None:
        assert self.transport and self.transport.pid is not None
        self.log = self.log.bind(subprocess_pid=self.transport.pid)
        self.log.debug('subprocess connection made')
        # TODO: Setup RPC here? And then ping/wait for ping?

    def childDataReceived(self, childFD: int, data: bytes) -> None:
        """
        This method is Twisted default way of communicating with a subprocess created by `reactor.spawnProcess()`.
        It uses file descriptors to share data between the main process and the subprocess.

        We are not using it, instead we use our own custom IPC. Therefore, we must not receive
        any messages through this method.
        """
        self.log.error(
            'subprocess data received through pipes',
            childFD=childFD,
            data=data,
        )
        raise AssertionError('SubprocessProtocol.childDataReceived should never be called!')

    def childConnectionLost(self, childFD: int) -> None:
        """It's an error if we lose connection to our subprocess' pipes, so we terminate it."""
        assert self.transport is not None
        self.log.error(
            'subprocess pipe unexpectedly closed, terminating...',
            childFD=childFD,
        )
        try:
            self.transport.signalProcess(signal.SIGTERM)
        except ProcessExitedAlready:
            pass

    def processExited(self, reason: Failure) -> None:
        log_connection_closed(log=self.log, reason=reason, message='subprocess exited')
