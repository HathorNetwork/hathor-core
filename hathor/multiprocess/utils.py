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

from structlog import BoundLogger
from twisted.internet.error import ConnectionDone, ConnectionLost
from twisted.python.failure import Failure


def log_connection_closed(*, log: BoundLogger, reason: Failure, message: str) -> None:
    """Utility to log a closed connection with different log level depending on the reason."""
    if isinstance(reason.value, ConnectionDone):
        log_func = log.info
    else:
        assert isinstance(reason.value, ConnectionLost)
        log_func = log.error

    log_func(message, reason=reason.getErrorMessage())
