#  Copyright 2023 Hathor Labs
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
from typing import NoReturn

from structlog import get_logger

from hathor.event import EventManager
from hathor.transaction.storage import TransactionStorage

logger = get_logger()


class ExecutionManager:
    """Class to manage actions related to full node execution."""
    __slots__ = ('_log', '_tx_storage', '_event_manager')

    def __init__(self, *, tx_storage: TransactionStorage, event_manager: EventManager) -> None:
        self._log = logger.new()
        self._tx_storage = tx_storage
        self._event_manager = event_manager

    def crash_and_exit(self, *, reason: str) -> NoReturn:
        """
        Calling this function is a very extreme thing to do, so be careful. It should only be called when a
        critical, unrecoverable failure happens. It crashes and exits the full node, rendering the database
        corrupted, and requiring manual intervention. In other words, a restart with a clean database (from scratch
        or a snapshot) will be required.
        """
        self._tx_storage.full_node_crashed()
        self._event_manager.full_node_crashed()
        self._log.critical(
            'Critical failure occurred, causing the full node to halt execution. Manual intervention is required.',
            reason=reason,
            exc_info=True
        )
        # We use os._exit() instead of sys.exit() or any other approaches because this is the only one Twisted
        # doesn't catch.
        os._exit(-1)
