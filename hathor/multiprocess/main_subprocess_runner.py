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
from socket import AF_INET
from typing import Callable

from structlog import get_logger
from twisted.internet.protocol import Factory

from hathor.cli.util import LoggingOptions, LoggingOutput, setup_logging
from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import HathorSettings
from hathor.multiprocess.subprocess_wrapper import SubprocessWrappingFactory
from hathor.reactor import ReactorProtocol, initialize_global_reactor

logger = get_logger()


def main_subprocess_runner(factory: Callable[[ReactorProtocol, HathorSettings, bytes], Factory]) -> None:
    _, addr, fileno_str, serialized_logging_args, serialized_subprocess_args = sys.argv
    logging_output, logging_options, capture_stdout = json.loads(serialized_logging_args)
    fileno = int(fileno_str)

    setup_logging(
        logging_output=LoggingOutput(logging_output),
        logging_options=LoggingOptions(*logging_options),
        capture_stdout=capture_stdout,
    )

    log = logger.new(addr=addr, fileno=fileno, subprocess_pid=os.getpid())
    log.debug('running subprocess for connection')

    reactor = initialize_global_reactor()
    settings = get_global_settings()
    wrapping_factory = SubprocessWrappingFactory(
        reactor=reactor,
        addr_str=addr,
        wrapped_factory=factory(reactor, settings, bytes.fromhex(serialized_subprocess_args)),
    )

    reactor.callWhenRunning(
        callable=reactor.adoptStreamConnection,
        fileDescriptor=fileno,
        addressFamily=AF_INET,
        factory=wrapping_factory,
    )
    reactor.run()
