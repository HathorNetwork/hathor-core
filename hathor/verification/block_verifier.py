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

from hathor.profiler import get_cpu_profiler
from hathor.transaction import BaseTransaction, Block
from hathor.verification.vertex_verifier import VertexVerifier

cpu = get_cpu_profiler()


class BlockVerifier(VertexVerifier):
    __slots__ = ()

    def verify_basic(self, block: Block, *, skip_block_weight_verification: bool = False) -> None:
        """Partially run validations, the ones that need parents/inputs are skipped."""
        if not skip_block_weight_verification:
            self.verify_weight(block)
        self.verify_reward(block)

    @cpu.profiler(key=lambda _, block: 'block-verify!{}'.format(block.hash.hex()))
    def verify(self, block: Block) -> None:
        """
            (1) confirms at least two pending transactions and references last block
            (2) solves the pow with the correct weight (done in HathorManager)
            (3) creates the correct amount of tokens in the output (done in HathorManager)
            (4) all parents must exist and have timestamp smaller than ours
            (5) data field must contain at most BLOCK_DATA_MAX_SIZE bytes
        """
        # TODO Should we validate a limit of outputs?
        if block.is_genesis:
            # TODO do genesis validation
            return

        self.verify_without_storage(block)

        # (1) and (4)
        self.verify_parents(block)

        self.verify_height(block)

    def verify_without_storage(self, block: Block) -> None:
        """ Run all verifications that do not need a storage.
        """
        block.verify_without_storage()

    @staticmethod
    def verify_height(block: Block) -> None:
        """Validate that the block height is enough to confirm all transactions being confirmed."""
        block.verify_height()

    def verify_weight(self, block: Block) -> None:
        """Validate minimum block difficulty."""
        block.verify_weight()

    @staticmethod
    def verify_reward(block: Block) -> None:
        """Validate reward amount."""
        block.verify_reward()

    @staticmethod
    def verify_no_inputs(block: Block) -> None:
        block.verify_no_inputs()

    def verify_outputs(self, block: BaseTransaction) -> None:
        block.verify_outputs()

    def verify_data(self, block: Block) -> None:
        block.verify_data()
