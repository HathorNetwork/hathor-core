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

import json
import os
import sys
from pathlib import Path
from typing import Callable

from structlog import get_logger
from twisted.internet import tcp
from twisted.internet.interfaces import IAddress, ITransport
from twisted.internet.protocol import Protocol, ServerFactory
from twisted.protocols.policies import ProtocolWrapper
from twisted.protocols.tls import BufferingTLSTransport
from twisted.internet.address import IPv4Address

from hathor.cli.util import LoggingOptions, LoggingOutput
from hathor.multiprocess.subprocess_protocol import SubprocessProtocol
from hathor.reactor import ReactorProtocol
from hathor.utils.pydantic import BaseModel

logger = get_logger()


class ConnectOnSubprocessProtocol(Protocol):
    __slots__ = ('log', 'reactor', '_main_file', '_addr', '_logging_args', '_subprocess_args', '_host_on')

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        main_file: Path,
        addr: IAddress,
        logging_args: str,
        subprocess_args: str,
        host_on: str,
    ) -> None:
        self.log = logger.new(addr=addr)
        self.reactor = reactor
        self._main_file = main_file
        self._addr = addr
        self._logging_args = logging_args
        self._subprocess_args = subprocess_args
        self._host_on = host_on

    def makeConnection(self, transport: ITransport) -> None:
        if isinstance(transport, BufferingTLSTransport):
            wrapped_transport = transport.transport
            assert isinstance(wrapped_transport, ProtocolWrapper)
            connection = wrapped_transport.transport
        else:
            connection = transport

        assert isinstance(connection, tcp.Connection)
        assert self._addr == connection.getPeer()

        fileno = connection.fileno()
        self.log.info('spawning new subprocess for connection', fileno=fileno, main_pid=os.getpid())

        # - We spawn the new subprocess by running python on self._main_file using the same python executable
        #   as us (the main process).
        # - We pass the addr and fileno of the connection to argv.
        # - We execute with the same env vars and working path from us (the main process).
        # - We configure direct mapping to the following file descriptors: stdout (1), stderr (2), and fileno.
        subprocess_transport = self.reactor.spawnProcess(
            processProtocol=SubprocessProtocol(addr=self._addr),
            executable=sys.executable,
            args=[
                sys.executable,
                str(self._main_file.absolute()),
                # TODO: Serialize all args together in a single class
                str(self._addr),
                str(fileno),
                self._logging_args,
                self._subprocess_args,
                self._host_on,
            ],
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
        self.log.error('subprocess data received on the main process', addr=self._addr, data=data)
        raise AssertionError('ConnectOnSubprocessProtocol.dataReceived should never be called!')


class ConnectOnSubprocessFactory(ServerFactory):
    __slots__ = (
        'reactor',
        '_main_file',
        '_serialized_logging_args',
        '_serialized_subprocess_args',
        '_build_protocol_callback'
    )

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        main_file: Path,
        logging_args: tuple[LoggingOutput, LoggingOptions, bool],
        subprocess_args: BaseModel,
        build_protocol_callback: Callable[[IAddress, str], None] | None,
    ) -> None:
        self.reactor = reactor
        self._main_file = main_file
        self._serialized_logging_args = json.dumps(logging_args)
        self._serialized_subprocess_args = subprocess_args.json_dumpb().hex()
        self._build_protocol_callback = build_protocol_callback

    def buildProtocol(self, addr: IAddress) -> Protocol | None:
        # TODO: Use temp file and cleanup. Maybe use a socket and pass FD instead?
        assert isinstance(addr, IPv4Address)
        host_on = f'/tmp/p2p_connection:{addr.type}:{addr.host}:{addr.port}.sock'

        if self._build_protocol_callback:
            self._build_protocol_callback(addr, host_on)

        return ConnectOnSubprocessProtocol(
            reactor=self.reactor,
            main_file=self._main_file,
            addr=addr,
            logging_args=self._serialized_logging_args,
            subprocess_args=self._serialized_subprocess_args,
            host_on=host_on,
        )
