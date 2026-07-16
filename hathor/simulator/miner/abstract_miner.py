# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
    def _on_new_tx(self, key: HathorEvents, args: EventArguments) -> None:
        """Called when a new tx or block is received."""
        raise NotImplementedError

    @abstractmethod
    def _schedule_next_block(self):
        """Schedule the propagation of the next block, and propagate a block if it has been found."""
        raise NotImplementedError

    @abstractmethod
    def get_blocks_found(self) -> int:
        raise NotImplementedError
