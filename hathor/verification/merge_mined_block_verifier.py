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

from hathor.transaction import Block, MergeMinedBlock
from hathor.verification.block_verifier import BlockVerifier


class MergeMinedBlockVerifier(BlockVerifier):
    __slots__ = ()

    def verify_without_storage(self, block: Block) -> None:
        assert isinstance(block, MergeMinedBlock)
        self.verify_aux_pow(block)
        super().verify_without_storage(block)

    def verify_aux_pow(self, block: MergeMinedBlock) -> None:
        """ Verify auxiliary proof-of-work (for merged mining).
        """
        assert block.aux_pow is not None
        block.aux_pow.verify(block.get_base_hash())
