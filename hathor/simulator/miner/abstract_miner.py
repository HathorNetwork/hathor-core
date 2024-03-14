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

from abc import ABC, abstractmethod
from typing import Optional

from structlog import get_logger
from twisted.internet.interfaces import IDelayedCall

from hathor.manager import HathorManager
from hathor.pubsub import EventArguments, HathorEvents
from hathor.util import Random

logger = get_logger()


class AbstractMiner(ABC):
    """Abstract class to represent miner simulators."""

    _manager: HathorManager
    _rng: Random
    _delayed_call: Optional[IDelayedCall] = None

    def __init__(self, manager: HathorManager, rng: Random):
        self._manager = manager
        self._rng = rng

        self._clock = self._manager.reactor

        self.log = logger.new()

    def start(self) -> None:
        """Start mining blocks."""
        self._manager.pubsub.subscribe(HathorEvents.NETWORK_NEW_TX_ACCEPTED, self._on_new_tx)

        self._schedule_next_block()

    def stop(self) -> None:
        """Stop mining blocks."""
        if self._delayed_call:
            self._delayed_call.cancel()
            self._delayed_call = None

        self._manager.pubsub.unsubscribe(HathorEvents.NETWORK_NEW_TX_ACCEPTED, self._on_new_tx)

    @abstractmethod
    async def _on_new_tx(self, key: HathorEvents, args: EventArguments) -> None:
        """Called when a new tx or block is received."""
        raise NotImplementedError

    @abstractmethod
    def _schedule_next_block(self):
        """Schedule the propagation of the next block, and propagate a block if it has been found."""
        raise NotImplementedError

    @abstractmethod
    def get_blocks_found(self) -> int:
        raise NotImplementedError
