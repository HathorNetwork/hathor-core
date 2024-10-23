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

import signal

from structlog import get_logger
from twisted.internet.error import ProcessExitedAlready
from twisted.internet.interfaces import IAddress
from twisted.internet.protocol import ProcessProtocol
from twisted.python.failure import Failure

from hathor.multiprocess.utils import log_connection_closed

logger = get_logger()


class SubprocessProtocol(ProcessProtocol):
    __slots__ = ('log', '_addr')

    def __init__(self, *, addr: IAddress) -> None:
        self.log = logger.new(addr=addr)
        self._addr = addr

    def connectionMade(self) -> None:
        assert self.transport and self.transport.pid is not None
        self.log = self.log.bind(subprocess_pid=self.transport.pid)
        self.log.debug('subprocess connection made')
        # TODO: Setup RPC here? And then ping/wait for ping?

    def childDataReceived(self, childFD: int, data: bytes) -> None:
        self.log.error(
            'subprocess data received through pipes',
            childFD=childFD,
            data=data,
        )
        raise AssertionError('SubprocessProtocol.childDataReceived should never be called!')

    def childConnectionLost(self, childFD: int) -> None:
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
