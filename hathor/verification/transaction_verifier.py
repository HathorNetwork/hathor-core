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

from typing import TYPE_CHECKING, assert_never

from structlog import get_logger

from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.feature_activation.feature_service import FeatureService
from hathor.profiler import get_cpu_profiler
from hathor.reward_lock import get_spent_reward_locked_info
from hathor.reward_lock.reward_lock import get_minimum_best_height
from hathor.transaction import BaseTransaction, Transaction, TxInput, TxVersion
from hathor.transaction.exceptions import (
    ConflictingInputs,
    ConflictWithConfirmedTxError,
    DuplicatedParents,
    ForbiddenMelt,
    ForbiddenMint,
    IncorrectParents,
    InexistentInput,
    InputOutputMismatch,
    InputVoidedAndConfirmed,
    InvalidInputData,
    InvalidInputDataSize,
    InvalidRangeProofError,
    InvalidShieldedOutputError,
    InvalidSurjectionProofError,
    InvalidToken,
    InvalidVersionError,
    RewardLocked,
    ScriptError,
    ShieldedAuthorityError,
    ShieldedBalanceMismatchError,
    ShieldedMintMeltForbiddenError,
    TimestampError,
    TokenNotFound,
    TooFewInputs,
    TooManyBetweenConflicts,
    TooManyInputs,
    TooManySigOps,
    TooManyTokens,
    TooManyWithinConflicts,
    TrivialCommitmentError,
    UnusedTokensError,
    WeightError,
)
from hathor.transaction.scripts.opcode import OpcodesVersion
from hathor.transaction.token_info import TokenInfo, TokenInfoDict, TokenVersion
from hathor.transaction.util import get_deposit_token_deposit_amount, get_deposit_token_withdraw_amount
from hathor.types import TokenUid, VertexId
from hathor.verification.verification_params import VerificationParams

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings

cpu = get_cpu_profiler()

logger = get_logger()

MAX_TOKENS_LENGTH: int = 16
MAX_WITHIN_CONFLICTS: int = 8
MAX_BETWEEN_CONFLICTS: int = 8


class TransactionVerifier:
    __slots__ = ('_settings', '_daa', '_feature_service', 'log')

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
        self.log = logger.new()

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
            # Handle shielded output references
            if tx_input.index < len(spent_tx.outputs):
                script = spent_tx.outputs[tx_input.index].script
            elif spent_tx.shielded_outputs:
                shielded_idx = tx_input.index - len(spent_tx.outputs)
                if shielded_idx < len(spent_tx.shielded_outputs):
                    script = spent_tx.shielded_outputs[shielded_idx].script
                else:
                    raise InexistentInput('Output spent by this input does not exist: {} index {}'.format(
                        tx_input.tx_id.hex(), tx_input.index))
            else:
                raise InexistentInput('Output spent by this input does not exist: {} index {}'.format(
                    tx_input.tx_id.hex(), tx_input.index))
            n_txops += counter.get_sigops_count(tx_input.data, script)

        if n_txops > self._settings.MAX_TX_SIGOPS_INPUT:
            raise TooManySigOps(
                'TX[{}]: Max number of sigops for inputs exceeded ({})'.format(tx.hash_hex, n_txops))

    def verify_inputs(self, tx: Transaction, params: VerificationParams, *, skip_script: bool = False) -> None:
        """Verify inputs signatures and ownership and all inputs actually exist"""
        self._verify_inputs(self._settings, tx, params.features.opcodes_version, skip_script=skip_script)

    @classmethod
    def _verify_inputs(
        cls,
        settings: HathorSettings,
        tx: Transaction,
        opcodes_version: OpcodesVersion,
        *,
        skip_script: bool,
    ) -> None:
        spent_outputs: set[tuple[VertexId, int]] = set()
        for input_tx in tx.inputs:
            if len(input_tx.data) > settings.MAX_INPUT_DATA_SIZE:
                raise InvalidInputDataSize('size: {} and max-size: {}'.format(
                    len(input_tx.data), settings.MAX_INPUT_DATA_SIZE
                ))

            spent_tx = tx.get_spent_tx(input_tx)

            # Handle shielded output references instead of asserting
            if input_tx.index < len(spent_tx.outputs):
                # Standard transparent output
                pass
            elif spent_tx.shielded_outputs:
                shielded_idx = input_tx.index - len(spent_tx.outputs)
                if shielded_idx >= len(spent_tx.shielded_outputs):
                    raise InexistentInput('Output spent by this input does not exist: {} index {}'.format(
                        input_tx.tx_id.hex(), input_tx.index))
            else:
                raise InexistentInput('Output spent by this input does not exist: {} index {}'.format(
                    input_tx.tx_id.hex(), input_tx.index))

            if tx.timestamp <= spent_tx.timestamp:
                raise TimestampError('tx={} timestamp={}, spent_tx={} timestamp={}'.format(
                    tx.hash.hex() if tx.hash else None,
                    tx.timestamp,
                    spent_tx.hash.hex(),
                    spent_tx.timestamp,
                ))

            if not skip_script:
                cls.verify_script(tx=tx, input_tx=input_tx, spent_tx=spent_tx, opcodes_version=opcodes_version)

            # check if any other input in this tx is spending the same output
            key = (input_tx.tx_id, input_tx.index)
            if key in spent_outputs:
                raise ConflictingInputs('tx {} inputs spend the same output: {} index {}'.format(
                    tx.hash_hex, input_tx.tx_id.hex(), input_tx.index))
            spent_outputs.add(key)

    @staticmethod
    def verify_script(
        *,
        tx: Transaction,
        input_tx: TxInput,
        spent_tx: BaseTransaction,
        opcodes_version: OpcodesVersion,
    ) -> None:
        """
        :type tx: Transaction
        :type input_tx: TxInput
        :type spent_tx: Transaction
        """
        from hathor.transaction.scripts import script_eval
        try:
            script_eval(tx, input_tx, spent_tx, opcodes_version)
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

    @classmethod
    def _check_token_permissions_and_deposits(
        cls,
        settings: HathorSettings,
        token_dict: TokenInfoDict,
        *,
        allow_nonexistent_tokens: bool = False,
    ) -> tuple[int, bool]:
        """Check token permissions and compute deposit/withdraw balance.

        Shared logic between verify_sum and verify_token_rules.

        Returns:
            (htr_expected_amount, has_nonexistent_tokens)
        """
        deposit = 0
        withdraw = 0
        has_nonexistent_tokens = False

        for token_uid, token_info in token_dict.items():
            cls._check_token_permissions(token_uid, token_info)
            match token_info.version:
                case None:
                    if not allow_nonexistent_tokens:
                        raise TokenNotFound(f'token uid {token_uid.hex()} not found.')
                    has_nonexistent_tokens = True

                case TokenVersion.NATIVE:
                    continue

                case TokenVersion.DEPOSIT:
                    if token_info.has_been_melted():
                        withdraw += get_deposit_token_withdraw_amount(settings, token_info.amount)
                    if token_info.has_been_minted():
                        deposit += get_deposit_token_deposit_amount(settings, token_info.amount)

                case TokenVersion.FEE:
                    continue

                case _:
                    assert_never(token_info.version)

        htr_expected_amount = withdraw - deposit
        htr_info = token_dict[settings.HATHOR_TOKEN_UID]
        if htr_info.amount > htr_expected_amount:
            raise InputOutputMismatch('There\'s an invalid surplus of HTR. (amount={}, expected={})'.format(
                htr_info.amount,
                htr_expected_amount,
            ))

        return htr_expected_amount, has_nonexistent_tokens

    @classmethod
    def verify_sum(
        cls,
        settings: HathorSettings,
        tx: Transaction,
        token_dict: TokenInfoDict,
        allow_nonexistent_tokens: bool = False,
        *,
        shielded_fee: int = 0,
    ) -> None:
        """Verify that the sum of outputs is equal of the sum of inputs, for each token. If sum of inputs
        and outputs is not 0, make sure inputs have mint/melt authority.

        When `allow_nonexistent_tokens` flag is set to `True` and a nonexistent token is provided,
        this method will skip the fee and HTR balance checks.

        token_dict sums up all tokens present in the tx and their properties (amount, can_mint, can_melt)
        amount = outputs - inputs, thus:
        - amount < 0 when melting
        - amount > 0 when minting

        :raises InputOutputMismatch: if sum of inputs is not equal to outputs and there's no mint/melt
        """
        htr_expected_amount, has_nonexistent_tokens = cls._check_token_permissions_and_deposits(
            settings, token_dict, allow_nonexistent_tokens=allow_nonexistent_tokens,
        )

        if has_nonexistent_tokens:
            # In a partial verification, it's not possible to check fees and
            # HTR amount since it depends on knowledge of all token versions.
            # The skipped checks below are simply postponed to execution-time
            # and run when a block confirms the nano tx.
            assert tx.is_nano_contract()
            return

        expected_fee = token_dict.calculate_fee(settings, shielded_fee=shielded_fee)
        if expected_fee != token_dict.fees_from_fee_header:
            raise InputOutputMismatch(f"Fee amount is different than expected. "
                                      f"(amount={token_dict.fees_from_fee_header}, expected={expected_fee})")

        htr_info = token_dict[settings.HATHOR_TOKEN_UID]
        if htr_info.amount < htr_expected_amount:
            raise InputOutputMismatch('There\'s an invalid deficit of HTR. (amount={}, expected={})'.format(
                htr_info.amount,
                htr_expected_amount,
            ))

        assert htr_info.amount == htr_expected_amount

    @classmethod
    def verify_token_rules(
        cls,
        settings: HathorSettings,
        token_dict: TokenInfoDict,
        *,
        shielded_fee: int = 0,
    ) -> None:
        """Verify token authority permissions, deposit requirements, and fee correctness.

        Uses _check_token_permissions_and_deposits for shared permission/deposit logic,
        then checks fee amounts. Used for shielded transactions where verify_sum's balance
        equation is replaced by verify_shielded_balance.

        :raises ForbiddenMint: if tokens were minted without authority
        :raises ForbiddenMelt: if tokens were melted without authority
        :raises InputOutputMismatch: if fee amounts are incorrect
        """
        cls._check_token_permissions_and_deposits(settings, token_dict)

        expected_fee = token_dict.calculate_fee(settings, shielded_fee=shielded_fee)
        if expected_fee != token_dict.fees_from_fee_header:
            raise InputOutputMismatch(f"Fee amount is different than expected. "
                                      f"(amount={token_dict.fees_from_fee_header}, expected={expected_fee})")

    @staticmethod
    def _check_token_permissions(token_uid: TokenUid, token_info: TokenInfo) -> None:
        """Verify whether token can be minted/melted based on its authority."""
        from hathor.conf.settings import HATHOR_TOKEN_UID
        if token_info.version == TokenVersion.NATIVE:
            assert token_uid == HATHOR_TOKEN_UID
            assert not token_info.can_mint
            assert not token_info.can_melt
            return
        assert token_uid != HATHOR_TOKEN_UID
        if token_info.has_been_melted() and not token_info.can_melt:
            raise ForbiddenMelt.from_token(token_info.amount, token_uid)
        if token_info.has_been_minted() and not token_info.can_mint:
            raise ForbiddenMint(token_info.amount, token_uid)

    def verify_version(self, tx: Transaction, params: VerificationParams) -> None:
        """Verify that the vertex version is valid."""
        allowed_tx_versions = {
            TxVersion.REGULAR_TRANSACTION,
            TxVersion.TOKEN_CREATION_TRANSACTION,
        }

        if params.features.nanocontracts:
            allowed_tx_versions.add(TxVersion.ON_CHAIN_BLUEPRINT)

        if tx.version not in allowed_tx_versions:
            raise InvalidVersionError(f'invalid vertex version: {tx.version}')

    def verify_tokens(self, tx: Transaction, params: VerificationParams) -> None:
        """Verify that all tokens are used and unique."""
        if not params.harden_token_restrictions:
            return

        if len(tx.tokens) > MAX_TOKENS_LENGTH:
            raise TooManyTokens('too many tokens')

        if len(tx.tokens) != len(set(tx.tokens)):
            raise InvalidToken('repeated tokens are not allowed')

        seen_token_indexes = set()
        for txout in tx.outputs:
            seen_token_indexes.add(txout.get_token_index())

        # Consider shielded output token indexes
        from hathor.transaction.shielded_tx_output import AmountShieldedOutput
        for shielded_out in tx.shielded_outputs:
            if isinstance(shielded_out, AmountShieldedOutput):
                seen_token_indexes.add(shielded_out.token_data & 0x7F)

        if tx.is_nano_contract():
            nano_header = tx.get_nano_header()
            for action in nano_header.nc_actions:
                seen_token_indexes.add(action.token_index)

        seen_token_indexes.discard(0)
        if sorted(seen_token_indexes) != list(range(1, len(tx.tokens) + 1)):
            raise UnusedTokensError('unused tokens are not allowed')

    def verify_conflict(self, tx: Transaction, params: VerificationParams) -> None:
        """Verify that this transaction has no conflicts with confirmed transactions."""
        assert tx.storage is not None

        if not params.reject_conflicts_with_confirmed_txs:
            return

        between_counter = 0
        for txin in tx.inputs:
            spent_tx = tx.get_spent_tx(txin)
            spent_tx_meta = spent_tx.get_metadata()
            if spent_tx_meta.first_block is not None and spent_tx_meta.voided_by:
                # spent_tx has been confirmed by a block and is voided, so its
                # outputs cannot be spent.
                raise InputVoidedAndConfirmed(spent_tx.hash.hex())
            if txin.index not in spent_tx_meta.spent_outputs:
                continue
            spent_by_list = spent_tx_meta.spent_outputs[txin.index]
            within_counter = 0
            for h in spent_by_list:
                if h == tx.hash:
                    # Skip tx itself.
                    continue
                conflict_tx = tx.storage.get_transaction(h)
                conflict_meta = conflict_tx.get_metadata()
                if conflict_meta.first_block is not None and not conflict_meta.voided_by:
                    # only mempool conflicts are allowed or failed nano executions
                    raise ConflictWithConfirmedTxError('transaction has a conflict with a confirmed transaction')
                if within_counter == 0:
                    # Only increment once per input.
                    between_counter += 1
                within_counter += 1

            if within_counter >= MAX_WITHIN_CONFLICTS:
                raise TooManyWithinConflicts

        if between_counter > MAX_BETWEEN_CONFLICTS:
            raise TooManyBetweenConflicts

    # --- Shielded transaction verification methods ---

    @staticmethod
    def _normalize_token_uid(token_uid: bytes) -> bytes:
        """Normalize a token UID to 32 bytes for the crypto library."""
        from hathor.crypto.shielded.asset_tag import normalize_token_uid
        try:
            return normalize_token_uid(token_uid)
        except ValueError as e:
            raise InvalidShieldedOutputError(str(e)) from e

    @staticmethod
    def calculate_shielded_fee(settings: HathorSettings, tx: Transaction) -> int:
        """Calculate the total fee required for shielded outputs."""
        from hathor.transaction.shielded_tx_output import AmountShieldedOutput, FullShieldedOutput
        fee = 0
        for output in tx.shielded_outputs:
            if isinstance(output, AmountShieldedOutput):
                fee += settings.FEE_PER_AMOUNT_SHIELDED_OUTPUT
            elif isinstance(output, FullShieldedOutput):
                fee += settings.FEE_PER_FULL_SHIELDED_OUTPUT
        return fee

    def verify_shielded_fee(self, tx: Transaction) -> None:
        """Verify the transaction declares sufficient fees for its shielded outputs."""
        if not tx.has_fees():
            raise InvalidShieldedOutputError('shielded transactions require a fee header')
        fee_header = tx.get_fee_header()
        expected_shielded_fee = self.calculate_shielded_fee(self._settings, tx)
        total_declared_fee = fee_header.total_fee_amount()
        if total_declared_fee < expected_shielded_fee:
            raise InvalidShieldedOutputError(
                f'insufficient fee for shielded outputs: declared {total_declared_fee}, '
                f'minimum shielded fee is {expected_shielded_fee}'
            )

    def verify_no_mint_melt(self, token_dict: TokenInfoDict) -> None:
        """Reject mint/melt operations in transactions with shielded outputs."""
        for token_uid, token_info in token_dict.items():
            if token_info.version == TokenVersion.NATIVE:
                continue
            if token_info.can_mint and token_info.has_been_minted():
                raise ShieldedMintMeltForbiddenError(
                    f'token {token_uid.hex()}: minting is not allowed in transactions '
                    f'with shielded outputs (transparent surplus: {token_info.amount})'
                )
            if token_info.can_melt and token_info.has_been_melted():
                raise ShieldedMintMeltForbiddenError(
                    f'token {token_uid.hex()}: melting is not allowed in transactions '
                    f'with shielded outputs (transparent deficit: {token_info.amount})'
                )

    def verify_shielded_outputs(self, tx: Transaction) -> None:
        """Top-level: calls all basic shielded checks."""
        self.verify_commitments_valid(tx)
        self.verify_authority_restriction(tx)
        self.verify_range_proofs(tx)
        self.verify_trivial_commitment_protection(tx)
        self.verify_shielded_fee(tx)

    def verify_shielded_outputs_with_storage(self, tx: Transaction) -> None:
        """Shielded verifications that need storage (balance, surjection).

        Builds shared caches for spent transactions and asset tags to avoid
        redundant storage lookups and crypto operations across sub-methods.
        """
        assert tx.storage is not None

        # Build spent_txs cache once — shared by surjection, balance, and trivial commitment
        spent_txs: dict[bytes, BaseTransaction] = {}
        for tx_input in tx.inputs:
            if tx_input.tx_id not in spent_txs:
                spent_txs[tx_input.tx_id] = tx.storage.get_transaction(tx_input.tx_id)

        # Build asset_tag cache once — shared by surjection and balance
        asset_tag_cache: dict[bytes, bytes] = {}

        self.verify_surjection_proofs(tx, spent_txs=spent_txs, asset_tag_cache=asset_tag_cache)
        self.verify_shielded_balance(tx, spent_txs=spent_txs, asset_tag_cache=asset_tag_cache)

    def verify_commitments_valid(self, tx: Transaction) -> None:
        """Validate all commitments are exactly 33 bytes, valid curve points, and count is within limits."""
        from hathor.crypto.shielded import validate_commitment, validate_generator
        from hathor.crypto.util import get_public_key_from_bytes_compressed
        from hathor.transaction.shielded_tx_output import (
            ASSET_COMMITMENT_SIZE,
            COMMITMENT_SIZE,
            EPHEMERAL_PUBKEY_SIZE,
            MAX_SHIELDED_OUTPUTS,
            FullShieldedOutput,
        )

        if len(tx.shielded_outputs) > MAX_SHIELDED_OUTPUTS:
            raise InvalidShieldedOutputError(
                f'too many shielded outputs: {len(tx.shielded_outputs)} exceeds maximum {MAX_SHIELDED_OUTPUTS}'
            )
        for i, output in enumerate(tx.shielded_outputs):
            if len(output.commitment) != COMMITMENT_SIZE:
                raise InvalidShieldedOutputError(
                    f'shielded output {i}: commitment must be {COMMITMENT_SIZE} bytes, '
                    f'got {len(output.commitment)}'
                )
            if not validate_commitment(output.commitment):
                raise InvalidShieldedOutputError(
                    f'shielded output {i}: invalid commitment (not a valid curve point)'
                )
            if isinstance(output, FullShieldedOutput):
                if len(output.asset_commitment) != ASSET_COMMITMENT_SIZE:
                    raise InvalidShieldedOutputError(
                        f'shielded output {i}: asset_commitment must be {ASSET_COMMITMENT_SIZE} bytes, '
                        f'got {len(output.asset_commitment)}'
                    )
                if not validate_generator(output.asset_commitment):
                    raise InvalidShieldedOutputError(
                        f'shielded output {i}: invalid asset_commitment (not a valid curve point)'
                    )

            if output.ephemeral_pubkey:
                if len(output.ephemeral_pubkey) != EPHEMERAL_PUBKEY_SIZE:
                    raise InvalidShieldedOutputError(
                        f'shielded output {i}: ephemeral_pubkey must be {EPHEMERAL_PUBKEY_SIZE} bytes, '
                        f'got {len(output.ephemeral_pubkey)}'
                    )
                try:
                    get_public_key_from_bytes_compressed(output.ephemeral_pubkey)
                except (ValueError, TypeError):
                    raise InvalidShieldedOutputError(
                        f'shielded output {i}: invalid ephemeral_pubkey (not a valid secp256k1 point)'
                    )

    def verify_range_proofs(self, tx: Transaction) -> None:
        """Every shielded output must have valid Bulletproof range proof."""
        from hathor.crypto.shielded import verify_range_proof
        from hathor.transaction.shielded_tx_output import AmountShieldedOutput, FullShieldedOutput

        asset_tag_cache: dict[bytes, bytes] = {}
        for i, output in enumerate(tx.shielded_outputs):
            if isinstance(output, AmountShieldedOutput):
                token_index = output.token_data & 0x7F
                if token_index > len(tx.tokens):
                    raise InvalidShieldedOutputError(
                        f'shielded output {i}: token_data index {token_index} '
                        f'exceeds token list length {len(tx.tokens)}'
                    )
                token_uid = tx.get_token_uid(token_index)
                generator = self._get_or_derive_asset_tag(token_uid, asset_tag_cache)
            elif isinstance(output, FullShieldedOutput):
                generator = output.asset_commitment
            else:
                raise InvalidShieldedOutputError(f'shielded output {i}: unknown type')

            try:
                if not verify_range_proof(output.range_proof, output.commitment, generator):
                    raise InvalidRangeProofError(
                        f'shielded output {i}: range proof verification failed'
                    )
            except ValueError as e:
                raise InvalidRangeProofError(f'shielded output {i}: {e}') from e

    def _get_or_derive_asset_tag(
        self,
        token_uid: bytes,
        asset_tag_cache: dict[bytes, bytes] | None,
    ) -> bytes:
        """Derive an asset tag, using the cache if available."""
        from hathor.crypto.shielded import derive_asset_tag
        normalized = self._normalize_token_uid(token_uid)
        if asset_tag_cache is not None:
            if normalized not in asset_tag_cache:
                asset_tag_cache[normalized] = derive_asset_tag(normalized)
            return asset_tag_cache[normalized]
        return derive_asset_tag(normalized)

    def verify_surjection_proofs(
        self,
        tx: Transaction,
        *,
        spent_txs: dict[bytes, BaseTransaction] | None = None,
        asset_tag_cache: dict[bytes, bytes] | None = None,
    ) -> None:
        """Only FullShieldedOutput instances require surjection proofs."""
        from hathor.crypto.shielded import verify_surjection_proof
        from hathor.transaction.shielded_tx_output import AmountShieldedOutput, FullShieldedOutput

        assert tx.storage is not None
        domain_generators: list[bytes] = []
        for tx_input in tx.inputs:
            spent_tx = spent_txs[tx_input.tx_id] if spent_txs else tx.storage.get_transaction(tx_input.tx_id)
            spent_index = tx_input.index
            if spent_index < len(spent_tx.outputs):
                spent_output = spent_tx.outputs[spent_index]
                if spent_output.is_token_authority():
                    continue
                token_uid = spent_tx.get_token_uid(spent_output.get_token_index())
                domain_generators.append(self._get_or_derive_asset_tag(token_uid, asset_tag_cache))
            else:
                shielded_index = spent_index - len(spent_tx.outputs)
                if shielded_index >= len(spent_tx.shielded_outputs):
                    raise InvalidShieldedOutputError(
                        f'input references non-existent shielded output index {spent_index}'
                    )
                shielded_out = spent_tx.shielded_outputs[shielded_index]
                if isinstance(shielded_out, FullShieldedOutput):
                    domain_generators.append(shielded_out.asset_commitment)
                elif isinstance(shielded_out, AmountShieldedOutput):
                    token_index = shielded_out.token_data & 0x7F
                    try:
                        token_uid = spent_tx.get_token_uid(token_index)
                    except (IndexError, NotImplementedError) as e:
                        raise InvalidShieldedOutputError(
                            f'spent shielded output token_data index {token_index} '
                            f'is invalid for the spent transaction'
                        ) from e
                    domain_generators.append(self._get_or_derive_asset_tag(token_uid, asset_tag_cache))

        has_full_shielded = any(isinstance(o, FullShieldedOutput) for o in tx.shielded_outputs)
        if has_full_shielded and not domain_generators:
            raise InvalidSurjectionProofError(
                'FullShieldedOutput requires at least one input to form a surjection proof domain'
            )

        for i, output in enumerate(tx.shielded_outputs):
            if isinstance(output, FullShieldedOutput):
                if not output.surjection_proof:
                    raise InvalidSurjectionProofError(
                        f'shielded output {i}: FullShieldedOutput requires surjection proof'
                    )
                try:
                    if not verify_surjection_proof(
                        output.surjection_proof,
                        output.asset_commitment,
                        domain_generators,
                    ):
                        raise InvalidSurjectionProofError(
                            f'shielded output {i}: surjection proof verification failed'
                        )
                except ValueError as e:
                    raise InvalidSurjectionProofError(f'shielded output {i}: {e}') from e

    def verify_shielded_balance(
        self,
        tx: Transaction,
        *,
        spent_txs: dict[bytes, BaseTransaction] | None = None,
        asset_tag_cache: dict[bytes, bytes] | None = None,
    ) -> None:
        """Homomorphic balance verification: sum(C_in) == sum(C_out) + fee*H_HTR."""
        from hathor.crypto.shielded import verify_balance

        assert tx.storage is not None
        transparent_inputs: list[tuple[int, bytes]] = []
        shielded_inputs: list[bytes] = []

        for tx_input in tx.inputs:
            spent_tx = spent_txs[tx_input.tx_id] if spent_txs else tx.storage.get_transaction(tx_input.tx_id)
            spent_index = tx_input.index
            if spent_index < len(spent_tx.outputs):
                spent_output = spent_tx.outputs[spent_index]
                if not spent_output.is_token_authority():
                    token_uid = self._normalize_token_uid(spent_tx.get_token_uid(spent_output.get_token_index()))
                    transparent_inputs.append((spent_output.value, token_uid))
            else:
                shielded_index = spent_index - len(spent_tx.outputs)
                if shielded_index >= len(spent_tx.shielded_outputs):
                    raise InvalidShieldedOutputError(
                        f'input references non-existent shielded output index {spent_index}'
                    )
                shielded_out = spent_tx.shielded_outputs[shielded_index]
                shielded_inputs.append(shielded_out.commitment)

        transparent_outputs: list[tuple[int, bytes]] = []
        shielded_outputs: list[bytes] = []

        for output in tx.outputs:
            if output.is_token_authority():
                continue
            token_uid = self._normalize_token_uid(tx.get_token_uid(output.get_token_index()))
            transparent_outputs.append((output.value, token_uid))

        for shielded_output in tx.shielded_outputs:
            shielded_outputs.append(shielded_output.commitment)

        if tx.has_fees():
            for fee_entry in tx.get_fee_header().get_fees():
                token_uid = self._normalize_token_uid(fee_entry.token_uid)
                transparent_outputs.append((fee_entry.amount, token_uid))

        try:
            if not verify_balance(
                transparent_inputs,
                shielded_inputs,
                transparent_outputs,
                shielded_outputs,
            ):
                raise ShieldedBalanceMismatchError(
                    'shielded balance equation does not hold'
                )
        except ValueError as e:
            raise ShieldedBalanceMismatchError(f'balance verification error: {e}') from e

    def verify_authority_restriction(self, tx: Transaction) -> None:
        """Shielded outputs cannot be authority (mint/melt) outputs."""
        from hathor.transaction.shielded_tx_output import AmountShieldedOutput, FullShieldedOutput
        for i, output in enumerate(tx.shielded_outputs):
            if isinstance(output, AmountShieldedOutput):
                from hathor.transaction import TxOutput
                if output.token_data & TxOutput.TOKEN_AUTHORITY_MASK:
                    raise ShieldedAuthorityError(
                        f'shielded output {i}: authority outputs cannot be shielded'
                    )
            elif isinstance(output, FullShieldedOutput):
                pass  # FullShieldedOutput has no token_data field, so no authority risk
            else:
                raise InvalidShieldedOutputError(f'shielded output {i}: unknown output type')

    def verify_trivial_commitment_protection(self, tx: Transaction) -> None:
        """Without storage, conservatively require >= 2 shielded outputs always."""
        if not tx.shielded_outputs:
            return
        if len(tx.shielded_outputs) < 2:
            raise TrivialCommitmentError(
                'at least 2 shielded outputs are required '
                f'to prevent trivial commitment matching (got {len(tx.shielded_outputs)})'
            )
