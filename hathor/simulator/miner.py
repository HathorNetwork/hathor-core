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

from structlog import get_logger

from hathor.conf import HathorSettings
from hathor.manager import HathorEvents
from hathor.util import Random

if TYPE_CHECKING:
    from hathor.manager import HathorManager
    from hathor.pubsub import EventArguments

settings = HathorSettings()
logger = get_logger()


class MinerSimulator:
    """ Simulate block mining with actually solving the block. It is supposed to be used
    with Simulator class. The mining part is simulated using the geometrical distribution.
    """
    def __init__(self, manager: 'HathorManager', rng: Random, *, hashpower: float):
        """
        :param: hashpower: Number of hashes per second
        """
        self.blocks_found = 0
        self.manager = manager
        self.hashpower = hashpower
        self.clock = manager.reactor
        self.block = None
        self.delayedcall = None
        self.log = logger.new()
        self.rng = rng

    def start(self) -> None:
        """ Start mining blocks.
        """
        self.manager.pubsub.subscribe(HathorEvents.NETWORK_NEW_TX_ACCEPTED, self.on_new_tx)
        self.schedule_next_block()

    def stop(self) -> None:
        """ Stop mining blocks.
        """
        if self.delayedcall:
            self.delayedcall.cancel()
            self.delayedcall = None
        self.manager.pubsub.unsubscribe(HathorEvents.NETWORK_NEW_TX_ACCEPTED, self.on_new_tx)

    def on_new_tx(self, key: HathorEvents, args: 'EventArguments') -> None:
        """ Called when a new tx or block is received. It updates the current mining to the
        new block.
        """
        tx = args.tx  # type: ignore
        if not tx.is_block:
            return
        if not self.block:
            return

        tips = tx.storage.get_best_block_tips()
        if self.block.parents[0] not in tips:
            # Head changed
            self.block = None
            self.schedule_next_block()

    def schedule_next_block(self):
        """ Schedule the propagation of the next block, and propagate a block if it has been found.
        """
        if self.block:
            self.block.nonce = self.rng.getrandbits(32)
            self.block.update_hash()
            self.blocks_found += 1
            self.log.debug('randomized step: found new block', hash=self.block.hash_hex, nonce=self.block.nonce)
            self.manager.propagate_tx(self.block, fails_silently=False)
            self.block = None

        if self.manager.can_start_mining():
            block = self.manager.generate_mining_block()
            geometric_p = 2**(-block.weight)
            trials = self.rng.geometric(geometric_p)
            dt = 1.0 * trials / self.hashpower
            self.block = block
            self.log.debug('randomized step: start mining new block', dt=dt, parents=[h.hex() for h in block.parents],
                           block_timestamp=block.timestamp)
        else:
            dt = 60

        if dt > settings.WEIGHT_DECAY_ACTIVATE_DISTANCE:
            self.block = None
            dt = settings.WEIGHT_DECAY_ACTIVATE_DISTANCE

        if self.delayedcall and self.delayedcall.active():
            self.delayedcall.cancel()
        self.delayedcall = self.clock.callLater(dt, self.schedule_next_block)
