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

from hathor.conf.settings import HathorSettings
from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.profiler import get_cpu_profiler
from hathor.reward_lock import get_spent_reward_locked_info
from hathor.reward_lock.reward_lock import get_minimum_best_height
from hathor.transaction import BaseTransaction, Transaction
from hathor.transaction.exceptions import (
    ConflictingInputs,
    DuplicatedParents,
    IncorrectParents,
    InexistentInput,
    InputOutputMismatch,
    InvalidInputData,
    InvalidInputDataSize,
    InvalidToken,
    NoInputError,
    OutputNotSelected,
    RewardLocked,
    ScriptError,
    TimestampError,
    TooManyInputs,
    TooManySigOps,
    WeightError,
)
from hathor.transaction.scripts.script_context import ScriptContext
from hathor.transaction.transaction import TokenInfo
from hathor.transaction.util import get_deposit_amount, get_withdraw_amount
from hathor.types import TokenUid, VertexId

cpu = get_cpu_profiler()


class TransactionVerifier:
    __slots__ = ('_settings', '_daa')

    def __init__(self, *, settings: HathorSettings, daa: DifficultyAdjustmentAlgorithm) -> None:
        self._settings = settings
        self._daa = daa

    def verify_parents_basic(self, tx: Transaction) -> None:
        """Verify number and non-duplicity of parents."""
        assert tx.storage is not None

        # check if parents are duplicated
        parents_set = set(tx.parents)
        if len(tx.parents) > len(parents_set):
            raise DuplicatedParents('Tx has duplicated parents: {}', [tx_hash.hex() for tx_hash in tx.parents])

        if len(tx.parents) != 2:
            raise IncorrectParents(f'wrong number of parents (tx type): {len(tx.parents)}, expecting 2')

    def verify_weight(self, tx: Transaction) -> None:
        """Validate minimum tx difficulty."""
        assert self._settings.CONSENSUS_ALGORITHM.is_pow()
        min_tx_weight = self._daa.minimum_tx_weight(tx)
        max_tx_weight = min_tx_weight + self._settings.MAX_TX_WEIGHT_DIFF
        if tx.weight < min_tx_weight - self._settings.WEIGHT_TOL:
            raise WeightError(f'Invalid new tx {tx.hash_hex}: weight ({tx.weight}) is '
                              f'smaller than the minimum weight ({min_tx_weight})')
        elif min_tx_weight > self._settings.MAX_TX_WEIGHT_DIFF_ACTIVATION and tx.weight > max_tx_weight:
            raise WeightError(f'Invalid new tx {tx.hash_hex}: weight ({tx.weight}) is '
                              f'greater than the maximum allowed ({max_tx_weight})')

    def verify_sigops_input(self, tx: Transaction) -> None:
        """ Count sig operations on all inputs and verify that the total sum is below the limit
        """
        from hathor.transaction.scripts import get_sigops_count
        from hathor.transaction.storage.exceptions import TransactionDoesNotExist
        n_txops = 0
        for tx_input in tx.inputs:
            try:
                spent_tx = tx.get_spent_tx(tx_input)
            except TransactionDoesNotExist:
                raise InexistentInput('Input tx does not exist: {}'.format(tx_input.tx_id.hex()))
            if tx_input.index >= len(spent_tx.outputs):
                raise InexistentInput('Output spent by this input does not exist: {} index {}'.format(
                    tx_input.tx_id.hex(), tx_input.index))
            n_txops += get_sigops_count(tx_input.data, spent_tx.outputs[tx_input.index].script)

        if n_txops > self._settings.MAX_TX_SIGOPS_INPUT:
            raise TooManySigOps(
                'TX[{}]: Max number of sigops for inputs exceeded ({})'.format(tx.hash_hex, n_txops))

    def verify_inputs(self, tx: Transaction, *, skip_script: bool = False) -> None:
        """Verify inputs signatures and ownership and all inputs actually exist"""
        from hathor.transaction.storage.exceptions import TransactionDoesNotExist

        spent_outputs: set[tuple[VertexId, int]] = set()
        all_selected_outputs: set[int] = set()

        for input_index, input_tx in enumerate(tx.inputs):
            if len(input_tx.data) > self._settings.MAX_INPUT_DATA_SIZE:
                raise InvalidInputDataSize('size: {} and max-size: {}'.format(
                    len(input_tx.data), self._settings.MAX_INPUT_DATA_SIZE
                ))

            try:
                spent_tx = tx.get_spent_tx(input_tx)
                if input_tx.index >= len(spent_tx.outputs):
                    raise InexistentInput('Output spent by this input does not exist: {} index {}'.format(
                        input_tx.tx_id.hex(), input_tx.index))
            except TransactionDoesNotExist:
                raise InexistentInput('Input tx does not exist: {}'.format(input_tx.tx_id.hex()))

            if tx.timestamp <= spent_tx.timestamp:
                raise TimestampError('tx={} timestamp={}, spent_tx={} timestamp={}'.format(
                    tx.hash.hex() if tx.hash else None,
                    tx.timestamp,
                    spent_tx.hash.hex(),
                    spent_tx.timestamp,
                ))

            if not skip_script:
                script_context = self.verify_script(tx=tx, spent_tx=spent_tx, input_index=input_index)
                selected_outputs = script_context.get_selected_outputs()
                all_selected_outputs = all_selected_outputs.union(selected_outputs)

            # check if any other input in this tx is spending the same output
            key = (input_tx.tx_id, input_tx.index)
            if key in spent_outputs:
                raise ConflictingInputs('tx {} inputs spend the same output: {} index {}'.format(
                    tx.hash_hex, input_tx.tx_id.hex(), input_tx.index))
            spent_outputs.add(key)

        if not skip_script:
            for index, _ in enumerate(tx.outputs):
                if index not in all_selected_outputs:
                    raise OutputNotSelected(f'Output at index {index} is not signed by any input.')

    def verify_script(
        self,
        *,
        tx: Transaction,
        spent_tx: BaseTransaction,
        input_index: int
    ) -> ScriptContext:
        """
        :type tx: Transaction
        :type spent_tx: Transaction
        :type input_index: int
        """
        from hathor.transaction.scripts import script_eval
        try:
            return script_eval(tx=tx, spent_tx=spent_tx, input_index=input_index)
        except ScriptError as e:
            raise InvalidInputData(e) from e

    def verify_reward_locked(self, tx: Transaction) -> None:
        """Will raise `RewardLocked` if any reward is spent before the best block height is enough, considering both
        the block rewards spent by this tx itself, and the inherited `min_height`."""
        assert tx.storage is not None
        best_height = get_minimum_best_height(tx.storage)
        self.verify_reward_locked_for_height(self._settings, tx, best_height)

    @staticmethod
    def verify_reward_locked_for_height(
        settings: HathorSettings,
        tx: Transaction,
        best_height: int,
        *,
        assert_min_height_verification: bool = True
    ) -> None:
        """
        Will raise `RewardLocked` if any reward is spent before the best block height is enough, considering both
        the block rewards spent by this tx itself, and the inherited `min_height`.

        Args:
            tx: the transaction to be verified.
            best_height: the height of the best chain to be used for verification.
            assert_min_height_verification: whether the inherited `min_height` verification must pass.

        Note: for verification of new transactions, `assert_min_height_verification` must be `True`. This
        verification is always expected to pass for new txs, as a failure would mean one of its dependencies would
        have failed too. So an `AssertionError` is raised if it fails.

        However, when txs are being re-verified for Reward Lock during a reorg, it's possible that txs may fail
        their inherited `min_height` verification. So in that case `assert_min_height_verification` is `False`,
        and a normal `RewardLocked` exception is raised instead.
        """
        assert tx.storage is not None
        info = get_spent_reward_locked_info(settings, tx, tx.storage)
        if info is not None:
            raise RewardLocked(f'Reward {info.block_hash.hex()} still needs {info.blocks_needed} to be unlocked.')

        min_height = tx.static_metadata.min_height
        # We use +1 here because a tx is valid if it can be confirmed by the next block
        if best_height + 1 < min_height:
            if assert_min_height_verification:
                raise AssertionError('a new tx should never be invalid by its inherited min_height.')
            raise RewardLocked(
                f'Tx {tx.hash_hex} has min_height={min_height}, but the best_height={best_height}.'
            )

    def verify_number_of_inputs(self, tx: Transaction) -> None:
        """Verify number of inputs is in a valid range"""
        if len(tx.inputs) > self._settings.MAX_NUM_INPUTS:
            raise TooManyInputs('Maximum number of inputs exceeded')

        if len(tx.inputs) == 0:
            if not tx.is_genesis:
                raise NoInputError('Transaction must have at least one input')

    def verify_output_token_indexes(self, tx: Transaction) -> None:
        """Verify outputs reference an existing token uid in the tokens list

        :raises InvalidToken: output references non existent token uid
        """
        for output in tx.outputs:
            # check index is valid
            if output.get_token_index() > len(tx.tokens):
                raise InvalidToken('token uid index not available: index {}'.format(output.get_token_index()))

    def verify_sum(self, token_dict: dict[TokenUid, TokenInfo]) -> None:
        """Verify that the sum of outputs is equal of the sum of inputs, for each token. If sum of inputs
        and outputs is not 0, make sure inputs have mint/melt authority.

        token_dict sums up all tokens present in the tx and their properties (amount, can_mint, can_melt)
        amount = outputs - inputs, thus:
        - amount < 0 when melting
        - amount > 0 when minting

        :raises InputOutputMismatch: if sum of inputs is not equal to outputs and there's no mint/melt
        """
        withdraw = 0
        deposit = 0
        for token_uid, token_info in token_dict.items():
            if token_uid == self._settings.HATHOR_TOKEN_UID:
                continue

            if token_info.amount == 0:
                # that's the usual behavior, nothing to do
                pass
            elif token_info.amount < 0:
                # tokens have been melted
                if not token_info.can_melt:
                    raise InputOutputMismatch('{} {} tokens melted, but there is no melt authority input'.format(
                        token_info.amount, token_uid.hex()))
                withdraw += get_withdraw_amount(self._settings, token_info.amount)
            else:
                # tokens have been minted
                if not token_info.can_mint:
                    raise InputOutputMismatch('{} {} tokens minted, but there is no mint authority input'.format(
                        (-1) * token_info.amount, token_uid.hex()))
                deposit += get_deposit_amount(self._settings, token_info.amount)

        # check whether the deposit/withdraw amount is correct
        htr_expected_amount = withdraw - deposit
        htr_info = token_dict[self._settings.HATHOR_TOKEN_UID]
        if htr_info.amount != htr_expected_amount:
            raise InputOutputMismatch('HTR balance is different than expected. (amount={}, expected={})'.format(
                htr_info.amount,
                htr_expected_amount,
            ))
