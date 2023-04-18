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

from typing import TYPE_CHECKING, Optional

from structlog import get_logger

from hathor.conf import HathorSettings
from hathor.daa import get_tokens_issued_per_block, calculate_next_weight
from hathor.transaction import Block, TxOutput, sum_weights
from hathor.manager import HathorEvents
from hathor.util import Random

if TYPE_CHECKING:
    from hathor.manager import HathorManager
    from hathor.pubsub import EventArguments

settings = HathorSettings()
logger = get_logger()


class AttackerSimulator:
    """ Simulate block mining with actually solving the block. It is supposed to be used
    with Simulator class. The mining part is simulated using the geometrical distribution.
    """
    def __init__(self, manager: 'HathorManager', rng: Random, *, first_block: Block, hashpower: float):
        """
        :param: hashpower: Number of hashes per second
        """
        self.blocks_found = 0
        self.manager = manager
        self.hashpower = hashpower
        self.clock = manager.reactor
        self.block = None
        self.delayedcall = None
        self.log = logger.new(name='attacker')
        self.rng = rng
        self.hidden_blocks: List[Block] = []
        self.latest_block = first_block
        self.first_block = first_block

    def start(self) -> None:
        """ Start mining blocks.
        """
        self.schedule_next_block()

    def stop(self) -> None:
        """ Stop mining blocks.
        """
        if self.delayedcall:
            self.delayedcall.cancel()
            self.delayedcall = None

    def get_next_block(self) -> Block:
        parents = [self.latest_block.hash] + self.latest_block.parents[1:]

        height = self.first_block.get_metadata().height + len(self.hidden_blocks) + 1
        value = get_tokens_issued_per_block(height)
        script = b''
        outputs = [TxOutput(value, script)]

        blk = Block(parents=parents, outputs=outputs)
        blk.timestamp = int(self.manager.reactor.seconds())
        # blk.weight = calculate_next_weight(self.latest_block, blk.timestamp)
        blk.weight = 40
        return blk

    def propagate_if_winner(self) -> bool:
        score = self.first_block.get_metadata().score
        for blk in self.hidden_blocks:
            score = sum_weights(score, blk.weight)

        network_score = self.manager.tx_storage.get_best_block().get_metadata().score

        self.log.debug('randomized step: found new block', hash=self.block.hash_hex, weight=self.block.weight, score=score, nonce=self.block.nonce, network_score=network_score, hidden_blocks=len(self.hidden_blocks))

        winner = False
        if score > network_score and len(self.hidden_blocks) > 3:
            winner = True

        self.hidden_blocks.append(self.block)

        if winner:
            self.log.info('winner winner chicken dinner... \o/')
            return True
        return False

    def _propagate_hidden_blocks(self):
        for blk in self.hidden_blocks:
            self.manager.on_new_tx(blk, fails_silently=False)

    def schedule_next_block(self):
        """ Schedule the propagation of the next block, and propagate a block if it has been found.
        """
        if self.block:
            self.block.nonce = self.rng.getrandbits(32)
            self.block.update_hash()
            self.blocks_found += 1
            if self.propagate_if_winner():
                return
            self.latest_block = self.block
            self.block = None

        block = self.get_next_block()
        geometric_p = 2**(-block.weight)
        trials = self.rng.geometric(geometric_p)
        dt = 1.0 * trials / self.hashpower
        self.block = block
        self.log.debug('randomized step: start mining new block', dt=dt, parents=[h.hex() for h in block.parents],
                       block_timestamp=block.timestamp)

        if dt > settings.WEIGHT_DECAY_ACTIVATE_DISTANCE:
            self.block = None
            dt = settings.WEIGHT_DECAY_ACTIVATE_DISTANCE

        if self.delayedcall and self.delayedcall.active():
            self.delayedcall.cancel()
        self.delayedcall = self.clock.callLater(dt, self.schedule_next_block)
