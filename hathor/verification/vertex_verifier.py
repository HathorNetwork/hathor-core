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

from typing import Optional

from hathor.conf.settings import HathorSettings
from hathor.transaction import BaseTransaction


class VertexVerifier:
    __slots__ = ('_settings', )

    def __init__(self, *, settings: HathorSettings):
        self._settings = settings

    def verify_parents(self, vertex: BaseTransaction) -> None:
        """All parents must exist and their timestamps must be smaller than ours.

        Also, txs should have 2 other txs as parents, while blocks should have 2 txs + 1 block.

        Parents must be ordered with blocks first, followed by transactions.

        :raises TimestampError: when our timestamp is less or equal than our parent's timestamp
        :raises ParentDoesNotExist: when at least one of our parents does not exist
        :raises IncorrectParents: when tx does not confirm the correct number/type of parent txs
        """
        vertex.verify_parents()

    @classmethod
    def verify_pow(cls, vertex: BaseTransaction, *, override_weight: Optional[float] = None) -> None:
        """Verify proof-of-work

        :raises PowError: when the hash is equal or greater than the target
        """
        vertex.verify_pow(override_weight)

    def verify_outputs(self, vertex: BaseTransaction) -> None:
        """Verify there are no hathor authority UTXOs and outputs are all positive

        :raises InvalidToken: when there's a hathor authority utxo
        :raises InvalidOutputValue: output has negative value
        :raises TooManyOutputs: when there are too many outputs
        """
        vertex.verify_outputs()

    def verify_number_of_outputs(self, vertex: BaseTransaction) -> None:
        """Verify number of outputs does not exceeds the limit"""
        vertex.verify_number_of_outputs()

    def verify_sigops_output(self, vertex: BaseTransaction) -> None:
        """ Count sig operations on all outputs and verify that the total sum is below the limit
        """
        vertex.verify_sigops_output()
