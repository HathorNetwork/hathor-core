# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import math
from typing import TYPE_CHECKING, Optional

from hathor.conf.get_settings import get_global_settings
from hathor.exception import BlockTemplateTimestampError
from hathor.manager import HathorEvents
from hathor.simulator.miner.abstract_miner import AbstractMiner
from hathor.util import Random

if TYPE_CHECKING:
    from hathor.manager import HathorManager
    from hathor.pubsub import EventArguments
    from hathor.transaction import Block


class GeometricMiner(AbstractMiner):
    """ Simulate block mining with actually solving the block. It is supposed to be used
    with Simulator class. The mining part is simulated using the geometrical distribution.
    """
    def __init__(
        self,
        manager: 'HathorManager',
        rng: Random,
        *,
        hashpower: float,
        signal_bits: Optional[list[int]] = None
    ) -> None:
        """
        :param: hashpower: Number of hashes per second
        :param: signal_bits: a list of signal_bits to be used in each mined block, in order. If there are more mined
            blocks than values provided, 0 is used.
        """
        super().__init__(manager, rng)
        self._settings = get_global_settings()

        self._hashpower = hashpower
        self._signal_bits = signal_bits or []
        self._block: Optional[Block] = None
        self._blocks_found: int = 0
        self._blocks_before_pause: float = math.inf

    def _on_new_tx(self, key: HathorEvents, args: 'EventArguments') -> None:
        """ Called when a new tx or block is received. It updates the current mining to the
        new block.
        """
        tx = args.tx
        if not tx.is_block:
            return
        if not self._block:
            return

        assert tx.storage is not None
        if self._block.parents[0] != tx.storage.get_best_block_hash():
            # Head changed
            self._block = None
            self._schedule_next_block()

    def _generate_mining_block(self) -> 'Block':
        """Generates a block ready to be mined."""
        try:
            signal_bits = self._signal_bits.pop(0)
        except IndexError:
            signal_bits = 0

        block = self._manager.generate_mining_block()
        block.signal_bits = signal_bits

        return block

    def _schedule_next_block(self):
        if self._blocks_before_pause <= 0:
            self._delayed_call = None
            return

        if self._block:
            self._block.nonce = self._rng.getrandbits(32)
            self._block.update_hash()
            self.log.debug('randomized step: found new block', hash=self._block.hash_hex, nonce=self._block.nonce)
            self._manager.propagate_tx(self._block)
            self._blocks_found += 1
            self._blocks_before_pause -= 1
            self._block = None

        if self._manager.can_start_mining():
            try:
                block = self._generate_mining_block()
            except BlockTemplateTimestampError:
                dt = 5  # Try again in 5 seconds.
            else:
                geometric_p = 2**(-block.weight)
                trials = self._rng.geometric(geometric_p)
                dt = 1.0 * trials / self._hashpower
                self._block = block
                self.log.debug('randomized step: start mining new block',
                               dt=dt,
                               parents=[h.hex() for h in block.parents],
                               block_timestamp=block.timestamp)
        else:
            dt = 60

        if dt > self._settings.WEIGHT_DECAY_ACTIVATE_DISTANCE:
            self._block = None
            dt = self._settings.WEIGHT_DECAY_ACTIVATE_DISTANCE

        if self._delayed_call and self._delayed_call.active():
            self._delayed_call.cancel()
        self._delayed_call = self._clock.callLater(dt, self._schedule_next_block)

    def get_blocks_found(self) -> int:
        return self._blocks_found

    def pause_after_exactly(self, *, n_blocks: int) -> None:
        """
        Configure the miner to pause mining blocks after exactly `n_blocks` are propagated. If called more than once,
        will unpause the miner and pause again according to the new argument.

        Use this instead of the `StopAfterNMinedBlocks` trigger if you need "exactly N blocks" behavior, instead of
        "at least N blocks".
        """
        self._blocks_before_pause = n_blocks

        if not self._delayed_call:
            self._delayed_call = self._clock.callLater(0, self._schedule_next_block)
