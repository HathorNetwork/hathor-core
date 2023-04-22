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

from typing import List

from structlog import get_logger

from hathor.conf import HathorSettings
from hathor.manager import HathorEvents, HathorManager
from hathor.pubsub import EventArguments
from hathor.simulator.miner.abstract_miner import AbstractMiner
from hathor.util import Random

settings = HathorSettings()
logger = get_logger()


class DummyMiner(AbstractMiner):
    """Simulate blocks mined at pre-determined times."""

    _start_time: int

    def __init__(self, manager: HathorManager, rng: Random, *, block_times: List[int]):
        super().__init__(manager, rng)

        self._block_times: List[int] = block_times

    def start(self) -> None:
        self._start_time = int(self._clock.seconds())
        super().start()

    def _on_new_tx(self, key: HathorEvents, args: EventArguments) -> None:
        # DummyMiner currently doesn't support receiving new transactions and ignores them.
        pass

    def _schedule_next_block(self):
        if not self._block_times:
            return

        next_block_time = self._start_time + self._block_times[0]

        if self._clock.seconds() >= next_block_time:
            time = self._block_times.pop(0)
            block = self._manager.generate_mining_block()
            block.nonce = self._rng.getrandbits(32)
            block.update_hash()

            self.log.debug('new pre-determined block', hash=block.hash_hex, nonce=block.nonce, time=time)
            self._manager.propagate_tx(block, fails_silently=False)

        self.delayed_call = self._clock.callLater(1, self._schedule_next_block)
