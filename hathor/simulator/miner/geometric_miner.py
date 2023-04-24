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

from typing import TYPE_CHECKING

from hathor.conf import HathorSettings
from hathor.manager import HathorEvents
from hathor.simulator.miner.abstract_miner import AbstractMiner
from hathor.util import Random

if TYPE_CHECKING:
    from hathor.manager import HathorManager
    from hathor.pubsub import EventArguments

settings = HathorSettings()


class GeometricMiner(AbstractMiner):
    """ Simulate block mining with actually solving the block. It is supposed to be used
    with Simulator class. The mining part is simulated using the geometrical distribution.
    """
    def __init__(self, manager: 'HathorManager', rng: Random, *, hashpower: float):
        """
        :param: hashpower: Number of hashes per second
        """
        super().__init__(manager, rng)

        self._hashpower = hashpower
        self._block = None

    def _on_new_tx(self, key: HathorEvents, args: 'EventArguments') -> None:
        """ Called when a new tx or block is received. It updates the current mining to the
        new block.
        """
        tx = args.tx
        if not tx.is_block:
            return
        if not self._block:
            return

        tips = tx.storage.get_best_block_tips()
        if self._block.parents[0] not in tips:
            # Head changed
            self._block = None
            self._schedule_next_block()

    def _schedule_next_block(self):
        if self._block:
            self._block.nonce = self._rng.getrandbits(32)
            self._block.update_hash()
            self.log.debug('randomized step: found new block', hash=self._block.hash_hex, nonce=self._block.nonce)
            self._manager.propagate_tx(self._block, fails_silently=False)
            self._block = None

        if self._manager.can_start_mining():
            block = self._manager.generate_mining_block()
            geometric_p = 2**(-block.weight)
            trials = self._rng.geometric(geometric_p)
            dt = 1.0 * trials / self._hashpower
            self._block = block
            self.log.debug('randomized step: start mining new block', dt=dt, parents=[h.hex() for h in block.parents],
                           block_timestamp=block.timestamp)
        else:
            dt = 60

        if dt > settings.WEIGHT_DECAY_ACTIVATE_DISTANCE:
            self._block = None
            dt = settings.WEIGHT_DECAY_ACTIVATE_DISTANCE

        if self._delayed_call and self._delayed_call.active():
            self._delayed_call.cancel()
        self._delayed_call = self._clock.callLater(dt, self._schedule_next_block)
