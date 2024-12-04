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
import sys
from dataclasses import dataclass
from socket import AF_INET
from typing import Callable, Generic, TypeVar

from structlog import get_logger
from twisted.internet.interfaces import IAddress, IProtocol
from twisted.internet.protocol import Factory, Protocol
from twisted.protocols.policies import ProtocolWrapper, WrappingFactory
from twisted.python.failure import Failure

from hathor.cli.util import LoggingOptions, LoggingOutput, setup_logging
from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import HathorSettings
from hathor.multiprocess.utils import log_connection_closed
from hathor.p2p.peer_endpoint import PeerAddress
from hathor.reactor import ReactorProtocol, initialize_global_reactor
from hathor.util import json_loadb
from hathor.utils.pydantic import BaseModel, GenericModel

logger = get_logger()

T = TypeVar('T', bound=BaseModel)


class SubprocessSpawnArgs(GenericModel, Generic[T]):
    addr: PeerAddress
    fileno: int
    custom_args: T


@dataclass(slots=True, kw_only=True, frozen=True)
class SubprocessBuildArgs(Generic[T]):
    reactor: ReactorProtocol
    settings: HathorSettings
    addr: PeerAddress
    custom_args: T


@dataclass(slots=True, kw_only=True, frozen=True)
class SubprocessBuildArtifacts:
    factory: Factory
    exit_callback: Callable[[], None]


def setup_subprocess_runner(
    build: Callable[[SubprocessBuildArgs[T]], SubprocessBuildArtifacts],
    custom_args_type: type[T],
) -> None:
    """
    Helper function to setup a subprocess connection runner as created by a ConnectOnSubprocessFactory.
    It takes a function that receives the subprocess reactor, settings, and custom arguments, and should
    return a dataclass with two fields:

    - A twisted Factory that will be used to create the actual underlying protocol in the subprocess.
    - A callback to be called when the subprocess exits.
    """
    _file_name, serialized_logging_args, serialized_subprocess_args = sys.argv
    logging_output, logging_options, capture_stdout = pickle.loads(bytes.fromhex(serialized_logging_args))
    subprocess_args_dict = json_loadb(bytes.fromhex(serialized_subprocess_args))
    subprocess_args = SubprocessSpawnArgs[custom_args_type](**subprocess_args_dict)  # type: ignore[valid-type]

    assert isinstance(logging_output, LoggingOutput)
    assert isinstance(logging_options, LoggingOptions)
    assert isinstance(capture_stdout, bool)
    assert isinstance(subprocess_args.custom_args, custom_args_type)

    setup_logging(
        logging_output=logging_output,
        logging_options=logging_options,
        capture_stdout=capture_stdout,
    )

    log = logger.new(addr=str(subprocess_args.addr), fileno=subprocess_args.fileno, subprocess_pid=os.getpid())
    log.debug('running subprocess for connection')

    reactor = initialize_global_reactor()
    settings = get_global_settings()
    factory_args = SubprocessBuildArgs(
        reactor=reactor,
        settings=settings,
        addr=subprocess_args.addr,
        custom_args=subprocess_args.custom_args,
    )

    artifacts = build(factory_args)
    wrapping_factory = _SubprocessWrappingFactory(
        reactor=reactor,
        addr=subprocess_args.addr,
        wrapped_factory=artifacts.factory,
    )

    reactor.callWhenRunning(
        callable=reactor.adoptStreamConnection,
        fileDescriptor=subprocess_args.fileno,
        addressFamily=AF_INET,
        factory=wrapping_factory,
    )
    reactor.run()
    artifacts.exit_callback()


class _SubprocessWrappingFactory(WrappingFactory):
    """
    This class is a Twisted factory to wrap the actual protocol that runs in a subprocess as created by
    ConnectOnSubprocessFactory. It exists simply for creating the respective _SubprocessProtocolWrapper.

    This factory is created in the `setup_subprocess_runner` function and is used to build a single
    _SubprocessProtocolWrapper instance, wrapping the actual underlying protocol that will connect to the file
    descriptor transferred to the subprocess.
    """

    __slots__ = ('log', 'reactor', '_addr', '_built_protocol')

    def __init__(self, *, reactor: ReactorProtocol, addr: PeerAddress, wrapped_factory: Factory) -> None:
        super().__init__(wrapped_factory)
        self.log = logger.new(addr=str(addr), subprocess_pid=os.getpid())
        self.reactor = reactor
        self._addr = addr
        self._built_protocol = False

    def buildProtocol(self, addr: IAddress) -> Protocol | None:
        assert not self._built_protocol, 'there must be only one subprocess protocol per factory'
        peer_addr = PeerAddress.from_address(addr)
        assert self._addr == peer_addr
        self.log.debug('building protocol for subprocess wrapper')

        try:
            wrapped_protocol = self.wrappedFactory.buildProtocol(addr)
        except Exception:
            self.log.exception('exception while calling wrapped buildProtocol')
            if self.reactor.running:
                self.reactor.stop()
            return None

        self._built_protocol = True
        return _SubprocessProtocolWrapper(
            reactor=self.reactor,
            factory=self,
            addr=self._addr,
            wrapped_protocol=wrapped_protocol,
        )


class _SubprocessProtocolWrapper(ProtocolWrapper):
    """
    This class is a Twisted protocol that wraps the actual protocol that runs in a subprocess as created by
    ConnectOnSubprocessFactory. It exists simply for logging and intercepting `connectionLost`.
    """

    __slots__ = ('log', 'reactor' '_addr')

    def __init__(
        self,
        *,
        reactor: ReactorProtocol,
        factory: WrappingFactory,
        addr: PeerAddress,
        wrapped_protocol: IProtocol,
    ) -> None:
        super().__init__(factory, wrapped_protocol)
        self.log = logger.new(addr=str(addr), subprocess_pid=os.getpid())
        self.reactor = reactor
        self._addr = addr

    def connectionMade(self) -> None:
        self.log.debug('subprocess connection made')
        super().connectionMade()

    def dataReceived(self, data: bytes) -> None:
        # This is too verbose even for debug mode, but I'm leaving it here as it may be useful sometimes
        # self.log.debug('data received', data=data)
        super().dataReceived(data)

    def connectionLost(self, reason: Failure) -> None:  # type: ignore[override]
        """When the underlying protocol loses connection, we stop our subprocess reactor, exiting the subprocess."""
        try:
            super().connectionLost(reason)
        except Exception:
            self.log.exception('exception while calling wrapped connectionLost')

        if self.reactor.running:
            self.reactor.stop()

        log_connection_closed(log=self.log, reason=reason, message='connection lost, exiting subprocess')
