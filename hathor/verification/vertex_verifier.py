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
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.transaction import BaseTransaction, Block, Transaction
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


class VertexVerifier:
    __slots__ = ('_settings', '_daa', '_feature_service')

    def __init__(
        self,
        *,
        settings: HathorSettings,
        daa: DifficultyAdjustmentAlgorithm,
        feature_service: FeatureService | None,
    ) -> None:
        self._settings = settings
        self._daa = daa
        self._feature_service = feature_service

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

        self._verify_duplicate_parents(vertex)

        try:
            parents = [vertex.storage.get_transaction(parent_hash) for parent_hash in vertex.parents]
        except TransactionDoesNotExist as e:
            raise ParentDoesNotExist(f'tx={vertex.hash_hex} parent={e.args[0]}')

        self._verify_parent_timestamps(vertex, parents)

        parent_blocks = [parent for parent in parents if isinstance(parent, Block)]
        parent_txs = [parent for parent in parents if isinstance(parent, Transaction)]

        self._verify_parent_ordering(parents, parent_blocks, parent_txs)
        self._verify_number_of_parents(vertex, parent_blocks, parent_txs)

    def _verify_duplicate_parents(self, vertex: BaseTransaction) -> None:
        """Check if parents are duplicate."""
        parents_set = set(vertex.parents)
        if len(vertex.parents) > len(parents_set):
            raise DuplicatedParents('Tx has duplicated parents: {}', [tx_hash.hex() for tx_hash in vertex.parents])

    def _verify_parent_timestamps(self, vertex: BaseTransaction, parents: list[BaseTransaction]) -> None:
        """Check for timestamp rules."""
        for parent in parents:
            if vertex.timestamp <= parent.timestamp:
                raise TimestampError(
                    f'tx={vertex.hash_hex} timestamp={vertex.timestamp}, '
                    f'parent={parent.hash_hex} timestamp={parent.timestamp}'
                )

            if vertex.is_block and parent.is_block and not parent.is_genesis:
                if vertex.timestamp - parent.timestamp > self._settings.MAX_DISTANCE_BETWEEN_BLOCKS:
                    raise TimestampError(
                        f'Distance between blocks is too big ({vertex.timestamp - parent.timestamp} seconds)'
                    )

    def _verify_parent_ordering(
        self,
        parents: list[BaseTransaction],
        parent_blocks: list[Block],
        parent_txs: list[Transaction],
    ) -> None:
        """Check for parent ordering."""
        if parent_blocks + parent_txs != parents:
            raise IncorrectParents('Parents which are blocks must come before transactions')

    def _verify_number_of_parents(
        self,
        vertex: BaseTransaction,
        parent_blocks: list[Block],
        parent_txs: list[Transaction]
    ) -> None:
        """Check for correct number of parents."""
        num_parent_txs = self._settings.PARENT_TXS_FOR_BLOCK if vertex.is_block else self._settings.PARENT_TXS_FOR_TX
        if len(parent_txs) != num_parent_txs:
            raise IncorrectParents(f'wrong number of parents (tx type): {len(parent_txs)}, expecting {num_parent_txs}')

        num_parent_blocks = (
            self._settings.PARENT_BLOCKS_FOR_BLOCK if vertex.is_block else self._settings.OLD_PARENT_BLOCKS_FOR_TX
        )

        if vertex.is_transaction and len(parent_blocks) == self._settings.NEW_PARENT_BLOCKS_FOR_TX:
            assert self._feature_service is not None
            is_feature_active = self._feature_service.is_feature_active_for_block(
                block=parent_blocks[0],
                feature=Feature.PARENT_BLOCK_FOR_TRANSACTIONS
            )

            if is_feature_active:
                num_parent_blocks = self._settings.NEW_PARENT_BLOCKS_FOR_TX

        if len(parent_blocks) != num_parent_blocks:
            raise IncorrectParents(
                f'wrong number of parents (block type): {len(parent_blocks)}, expecting {num_parent_blocks}'
            )

    def verify_pow(self, vertex: BaseTransaction, *, override_weight: Optional[float] = None) -> None:
        """Verify proof-of-work

        :raises PowError: when the hash is equal or greater than the target
        """
        assert vertex.hash is not None
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
