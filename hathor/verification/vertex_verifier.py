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
from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.transaction import BaseTransaction
from hathor.transaction.exceptions import (
    DuplicatedParents,
    IncorrectParents,
    InvalidOutputScriptSize,
    InvalidOutputValue,
    InvalidToken,
    ParentDoesNotExist,
    PowError,
    TimestampError,
    TooManyOutputs,
    TooManySigOps,
)

# tx should have 2 parents, both other transactions
_TX_PARENTS_TXS = 2
_TX_PARENTS_BLOCKS = 0

# blocks have 3 parents, 2 txs and 1 block
_BLOCK_PARENTS_TXS = 2
_BLOCK_PARENTS_BLOCKS = 1


class VertexVerifier:
    __slots__ = ('_settings', '_daa')

    def __init__(self, *, settings: HathorSettings, daa: DifficultyAdjustmentAlgorithm):
        self._settings = settings
        self._daa = daa

    def verify_parents(self, vertex: BaseTransaction) -> None:
        """All parents must exist and their timestamps must be smaller than ours.

        Also, txs should have 2 other txs as parents, while blocks should have 2 txs + 1 block.

        Parents must be ordered with blocks first, followed by transactions.

        :raises TimestampError: when our timestamp is less or equal than our parent's timestamp
        :raises ParentDoesNotExist: when at least one of our parents does not exist
        :raises IncorrectParents: when tx does not confirm the correct number/type of parent txs
        """
        from hathor.transaction.storage.exceptions import TransactionDoesNotExist

        assert vertex.storage is not None

        # check if parents are duplicated
        parents_set = set(vertex.parents)
        if len(vertex.parents) > len(parents_set):
            raise DuplicatedParents('Tx has duplicated parents: {}', [tx_hash.hex() for tx_hash in vertex.parents])

        my_parents_txs = 0      # number of tx parents
        my_parents_blocks = 0   # number of block parents
        min_timestamp: Optional[int] = None

        for parent_hash in vertex.parents:
            try:
                parent = vertex.storage.get_transaction(parent_hash)
                if vertex.timestamp <= parent.timestamp:
                    raise TimestampError('tx={} timestamp={}, parent={} timestamp={}'.format(
                        vertex.hash_hex,
                        vertex.timestamp,
                        parent.hash_hex,
                        parent.timestamp,
                    ))

                if parent.is_block:
                    if vertex.is_block and not parent.is_genesis:
                        if vertex.timestamp - parent.timestamp > self._settings.MAX_DISTANCE_BETWEEN_BLOCKS:
                            raise TimestampError('Distance between blocks is too big'
                                                 ' ({} seconds)'.format(vertex.timestamp - parent.timestamp))
                    if my_parents_txs > 0:
                        raise IncorrectParents('Parents which are blocks must come before transactions')
                    for pi_hash in parent.parents:
                        pi = vertex.storage.get_transaction(parent_hash)
                        if not pi.is_block:
                            min_timestamp = (
                                min(min_timestamp, pi.timestamp) if min_timestamp is not None
                                else pi.timestamp
                            )
                    my_parents_blocks += 1
                else:
                    if min_timestamp and parent.timestamp < min_timestamp:
                        raise TimestampError('tx={} timestamp={}, parent={} timestamp={}, min_timestamp={}'.format(
                            vertex.hash_hex,
                            vertex.timestamp,
                            parent.hash_hex,
                            parent.timestamp,
                            min_timestamp
                        ))
                    my_parents_txs += 1
            except TransactionDoesNotExist:
                raise ParentDoesNotExist('tx={} parent={}'.format(vertex.hash_hex, parent_hash.hex()))

        # check for correct number of parents
        if vertex.is_block:
            parents_txs = _BLOCK_PARENTS_TXS
            parents_blocks = _BLOCK_PARENTS_BLOCKS
        else:
            parents_txs = _TX_PARENTS_TXS
            parents_blocks = _TX_PARENTS_BLOCKS
        if my_parents_blocks != parents_blocks:
            raise IncorrectParents('wrong number of parents (block type): {}, expecting {}'.format(
                my_parents_blocks, parents_blocks))
        if my_parents_txs != parents_txs:
            raise IncorrectParents('wrong number of parents (tx type): {}, expecting {}'.format(
                my_parents_txs, parents_txs))

    def verify_pow(self, vertex: BaseTransaction, *, override_weight: Optional[float] = None) -> None:
        """Verify proof-of-work

        :raises PowError: when the hash is equal or greater than the target
        """
        numeric_hash = int(vertex.hash_hex, vertex.HEX_BASE)
        minimum_target = vertex.get_target(override_weight)
        if numeric_hash >= minimum_target:
            raise PowError(f'Transaction has invalid data ({numeric_hash} < {minimum_target})')

    def verify_outputs(self, vertex: BaseTransaction) -> None:
        """Verify there are no hathor authority UTXOs and outputs are all positive

        :raises InvalidToken: when there's a hathor authority utxo
        :raises InvalidOutputValue: output has negative value
        :raises TooManyOutputs: when there are too many outputs
        """
        self.verify_number_of_outputs(vertex)
        for index, output in enumerate(vertex.outputs):
            # no hathor authority UTXO
            if (output.get_token_index() == 0) and output.is_token_authority():
                raise InvalidToken('Cannot have authority UTXO for hathor tokens: {}'.format(
                    output.to_human_readable()))

            # output value must be positive
            if output.value <= 0:
                raise InvalidOutputValue('Output value must be a positive integer. Value: {} and index: {}'.format(
                    output.value, index))

            if len(output.script) > self._settings.MAX_OUTPUT_SCRIPT_SIZE:
                raise InvalidOutputScriptSize('size: {} and max-size: {}'.format(
                    len(output.script), self._settings.MAX_OUTPUT_SCRIPT_SIZE
                ))

    def verify_number_of_outputs(self, vertex: BaseTransaction) -> None:
        """Verify number of outputs does not exceeds the limit"""
        if len(vertex.outputs) > self._settings.MAX_NUM_OUTPUTS:
            raise TooManyOutputs('Maximum number of outputs exceeded')

    def verify_sigops_output(self, vertex: BaseTransaction) -> None:
        """ Count sig operations on all outputs and verify that the total sum is below the limit
        """
        from hathor.transaction.scripts import get_sigops_count
        n_txops = 0

        for tx_output in vertex.outputs:
            n_txops += get_sigops_count(tx_output.script)

        if n_txops > self._settings.MAX_TX_SIGOPS_OUTPUT:
            raise TooManySigOps('TX[{}]: Maximum number of sigops for all outputs exceeded ({})'.format(
                vertex.hash_hex, n_txops))
