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

from structlog import get_logger

from fake_main_p2p import MAIN_P2P_FILE
from hathor.cli.util import setup_logging, LoggingOutput, LoggingOptions
from hathor.multiprocess.connect_on_subprocess import ConnectOnSubprocessFactory
from hathor.reactor import initialize_global_reactor


def main() -> None:
    log = get_logger()
    log.info('running', main_pid=os.getpid())
    reactor = initialize_global_reactor()
    reactor.listenTCP(40403, ConnectOnSubprocessFactory(
        reactor=reactor,
        main_file=MAIN_P2P_FILE,
    ))
    reactor.run()
    log.info('done.')


if __name__ == '__main__':
    setup_logging(
        logging_output=LoggingOutput.PRETTY,
        logging_options=LoggingOptions(debug=False, sentry=False)
    )
    main()
