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

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, assert_never

from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.feature_activation.feature_service import FeatureService
from hathor.profiler import get_cpu_profiler
from hathor.reward_lock import get_spent_reward_locked_info
from hathor.reward_lock.reward_lock import get_minimum_best_height
from hathor.transaction import BaseTransaction, Transaction, TxInput, TxVersion
from hathor.transaction.exceptions import (
    ConflictingInputs,
    DuplicatedParents,
    ForbiddenMelt,
    ForbiddenMint,
    IncorrectParents,
    InexistentInput,
    InputOutputMismatch,
    InvalidInputData,
    InvalidInputDataSize,
    InvalidToken,
    InvalidVersionError,
    RewardLocked,
    ScriptError,
    TimestampError,
    TooFewInputs,
    TooManyInputs,
    TooManySigOps,
    WeightError,
)
from hathor.transaction.token_info import TokenInfo, TokenInfoDict, TokenVersion
from hathor.transaction.util import get_deposit_token_deposit_amount, get_deposit_token_withdraw_amount
from hathor.types import TokenUid, VertexId

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings

cpu = get_cpu_profiler()


class TransactionVerifier:
    __slots__ = ('_settings', '_daa', '_feature_service')

    def __init__(
        self,
        *,
        settings: HathorSettings,
        daa: DifficultyAdjustmentAlgorithm,
        feature_service: FeatureService,
    ) -> None:
        self._settings = settings
        self._daa = daa
        self._feature_service = feature_service

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

    def verify_sigops_input(self, tx: Transaction, enable_checkdatasig_count: bool = True) -> None:
        """ Count sig operations on all inputs and verify that the total sum is below the limit
        """
        from hathor.transaction.scripts import SigopCounter
        from hathor.transaction.storage.exceptions import TransactionDoesNotExist

        counter = SigopCounter(
            max_multisig_pubkeys=self._settings.MAX_MULTISIG_PUBKEYS,
            enable_checkdatasig_count=enable_checkdatasig_count,
        )

        n_txops = 0
        for tx_input in tx.inputs:
            try:
                spent_tx = tx.get_spent_tx(tx_input)
            except TransactionDoesNotExist:
                raise InexistentInput('Input tx does not exist: {}'.format(tx_input.tx_id.hex()))
            if tx_input.index >= len(spent_tx.outputs):
                raise InexistentInput('Output spent by this input does not exist: {} index {}'.format(
                    tx_input.tx_id.hex(), tx_input.index))
            n_txops += counter.get_sigops_count(tx_input.data, spent_tx.outputs[tx_input.index].script)

        if n_txops > self._settings.MAX_TX_SIGOPS_INPUT:
            raise TooManySigOps(
                'TX[{}]: Max number of sigops for inputs exceeded ({})'.format(tx.hash_hex, n_txops))

    def verify_inputs(self, tx: Transaction, *, skip_script: bool = False) -> None:
        """Verify inputs signatures and ownership and all inputs actually exist"""
        spent_outputs: set[tuple[VertexId, int]] = set()
        for input_tx in tx.inputs:
            if len(input_tx.data) > self._settings.MAX_INPUT_DATA_SIZE:
                raise InvalidInputDataSize('size: {} and max-size: {}'.format(
                    len(input_tx.data), self._settings.MAX_INPUT_DATA_SIZE
                ))

            spent_tx = tx.get_spent_tx(input_tx)
            assert input_tx.index < len(spent_tx.outputs)

            if tx.timestamp <= spent_tx.timestamp:
                raise TimestampError('tx={} timestamp={}, spent_tx={} timestamp={}'.format(
                    tx.hash.hex() if tx.hash else None,
                    tx.timestamp,
                    spent_tx.hash.hex(),
                    spent_tx.timestamp,
                ))

            if not skip_script:
                self.verify_script(tx=tx, input_tx=input_tx, spent_tx=spent_tx)

            # check if any other input in this tx is spending the same output
            key = (input_tx.tx_id, input_tx.index)
            if key in spent_outputs:
                raise ConflictingInputs('tx {} inputs spend the same output: {} index {}'.format(
                    tx.hash_hex, input_tx.tx_id.hex(), input_tx.index))
            spent_outputs.add(key)

    def verify_script(self, *, tx: Transaction, input_tx: TxInput, spent_tx: BaseTransaction) -> None:
        """
        :type tx: Transaction
        :type input_tx: TxInput
        :type spent_tx: Transaction
        """
        from hathor.transaction.scripts import script_eval
        try:
            script_eval(tx, input_tx, spent_tx)
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

        minimum = tx.get_minimum_number_of_inputs()
        if len(tx.inputs) < minimum:
            if not tx.is_genesis:
                raise TooFewInputs(f'Transaction must have at least {minimum} input(s)')

    def verify_output_token_indexes(self, tx: Transaction) -> None:
        """Verify outputs reference an existing token uid in the tokens list

        :raises InvalidToken: output references non existent token uid
        """
        for output in tx.outputs:
            # check index is valid
            if output.get_token_index() > len(tx.tokens):
                raise InvalidToken('token uid index not available: index {}'.format(output.get_token_index()))

    def verify_sum(self, token_dict: TokenInfoDict) -> None:
        """Verify that the sum of outputs is equal of the sum of inputs, for each token. If sum of inputs
        and outputs is not 0, make sure inputs have mint/melt authority.

        token_dict sums up all tokens present in the tx and their properties (amount, can_mint, can_melt)
        amount = outputs - inputs, thus:
        - amount < 0 when melting
        - amount > 0 when minting

        :raises InputOutputMismatch: if sum of inputs is not equal to outputs and there's no mint/melt
        """
        deposit = 0
        withdraw = 0
        withdraw_without_authority = 0
        fee = token_dict.calculate_fee(self._settings)

        for token_uid, token_info in token_dict.items():
            match token_info.version:
                case TokenVersion.NATIVE:
                    continue
                case TokenVersion.DEPOSIT:
                    result = self._verify_deposit_token(fee, token_uid, token_info)
                    deposit += result.deposit
                    withdraw += result.withdraw
                    withdraw_without_authority += result.withdraw_without_authority
                case TokenVersion.FEE:
                    self._verify_fee_token(token_uid, token_info)
                case _:
                    assert_never(token_info)

        is_melting_without_authority = withdraw_without_authority - fee > 0
        if is_melting_without_authority:
            raise ForbiddenMelt('Melting tokens without a melt authority is forbidden')

        # check whether the deposit/withdraw amount is correct
        htr_expected_amount = withdraw + withdraw_without_authority - deposit - fee
        htr_info = token_dict[self._settings.HATHOR_TOKEN_UID]
        if htr_info.amount != htr_expected_amount:
            raise InputOutputMismatch('HTR balance is different than expected. (amount={}, expected={})'.format(
                htr_info.amount,
                htr_expected_amount,
            ))

    def _verify_fee_token(self, token_uid: TokenUid, token_info: TokenInfo) -> None:
        """Verify fee token can be minted/melted based on its authority."""
        if token_info.has_been_melted() and not token_info.can_melt:
            raise ForbiddenMelt.from_token(token_info.amount, token_uid)
        if token_info.has_been_minted() and not token_info.can_mint:
            raise ForbiddenMint(token_info.amount, token_uid)

    def _verify_deposit_token(self, fee: int, token_uid: TokenUid, token_info: TokenInfo) -> DepositTokenVerifyResult:
        """Verify deposit token operations and calculate withdrawal/deposit amounts."""
        result = DepositTokenVerifyResult()
        if token_info.has_been_melted():
            withdraw_amount = get_deposit_token_withdraw_amount(self._settings, token_info.amount)
            if token_info.can_melt:
                result.withdraw += withdraw_amount
            else:
                # Any melting operation without authority is forbidden.
                # It includes trying to pay fee with non-integer amounts.
                # For example (DBT - Deposit based token)
                # 1.99 DBT results in 0.01 HTR and (0.99 DBT melted) => this one is forbidden
                if fee == 0:
                    raise ForbiddenMelt.from_token(token_info.amount, token_uid)
                is_integer_amount = (
                    token_info.amount * self._settings.TOKEN_DEPOSIT_PERCENTAGE).is_integer()
                if not is_integer_amount:
                    raise ForbiddenMelt(
                        "Paying fees with non integer amount is forbidden"
                    )

                result.withdraw_without_authority += withdraw_amount

        if token_info.has_been_minted():
            if not token_info.can_mint:
                raise ForbiddenMint(token_info.amount, token_uid)

            result.deposit += get_deposit_token_deposit_amount(self._settings, token_info.amount)

        return result

    def verify_version(self, tx: Transaction) -> None:
        """Verify that the vertex version is valid."""
        from hathor.nanocontracts.utils import is_nano_active
        allowed_tx_versions = {
            TxVersion.REGULAR_TRANSACTION,
            TxVersion.TOKEN_CREATION_TRANSACTION,
        }

        if is_nano_active(self._settings, tx, self._feature_service):
            allowed_tx_versions.add(TxVersion.ON_CHAIN_BLUEPRINT)

        if tx.version not in allowed_tx_versions:
            raise InvalidVersionError(f'invalid vertex version: {tx.version}')


@dataclass(kw_only=True, slots=True)
class DepositTokenVerifyResult:
    deposit: int = 0
    withdraw_without_authority: int = 0
    withdraw: int = 0
