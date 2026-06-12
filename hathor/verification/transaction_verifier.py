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

from hathor.daa import DAAFactory
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
    InvalidMintMeltHeaderError,
    InvalidToken,
    InvalidVersionError,
    RewardLocked,
    ScriptError,
    ShieldedMintMeltForbiddenError,
    TimestampError,
    TokenNotFound,
    TooFewInputs,
    TooManyBetweenConflicts,
    TooManyInputs,
    TooManySigOps,
    TooManyTokens,
    TooManyWithinConflicts,
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

MAX_TOKENS_LENGTH: int = 16
MAX_WITHIN_CONFLICTS: int = 8
MAX_BETWEEN_CONFLICTS: int = 8


class TransactionVerifier:
    __slots__ = ('_settings', '_daa_factory', '_feature_service')

    def __init__(
        self,
        *,
        settings: HathorSettings,
        daa_factory: DAAFactory,
        feature_service: FeatureService,
    ) -> None:
        self._settings = settings
        self._daa_factory = daa_factory
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
        min_tx_weight = self._daa_factory.minimum_tx_weight(tx)
        max_tx_weight = min_tx_weight + self._settings.MAX_TX_WEIGHT_DIFF
        if tx.weight < min_tx_weight - self._settings.WEIGHT_TOL:
            raise WeightError(f'Invalid new tx {tx.hash_hex}: weight ({tx.weight}) is '
                              f'smaller than the minimum weight ({min_tx_weight})')
        elif tx.weight > self._settings.MAX_TX_WEIGHT_DIFF_ACTIVATION and tx.weight > max_tx_weight:
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
            n_txops += counter.get_sigops_count(tx_input.data, spent_tx.resolve_spent_output(tx_input.index).script)

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
            assert input_tx.index < len(spent_tx.outputs)

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
    def verify_transparent_balance(
        cls,
        settings: HathorSettings,
        tx: Transaction,
        token_dict: TokenInfoDict,
        allow_nonexistent_tokens: bool = False,
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
        deposit = 0
        withdraw = 0
        has_nonexistent_tokens = False

        for token_uid, token_info in token_dict.items():
            cls._check_token_permissions(token_uid, token_info)
            match token_info.version:
                case None:
                    # When a token is not found, we can't assert the HTR value since we don't know the token version.
                    # This is only possible for nanos, because they may create the missing token in execution-time.
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

        # check whether the deposit/withdraw amount is correct
        htr_expected_amount = withdraw - deposit
        htr_info = token_dict[settings.HATHOR_TOKEN_UID]
        if htr_info.amount > htr_expected_amount:
            raise InputOutputMismatch('There\'s an invalid surplus of HTR. (amount={}, expected={})'.format(
                htr_info.amount,
                htr_expected_amount,
            ))

        if has_nonexistent_tokens:
            # In a partial verification, it's not possible to check fees and
            # HTR amount since it depends on knowledge of all token versions.
            # The skipped checks below are simply postponed to execution-time
            # and run when a block confirms the nano tx.
            assert tx.is_nano_contract()
            return

        expected_fee = token_dict.calculate_fee(settings)
        if expected_fee != token_dict.fees_from_fee_header:
            raise InputOutputMismatch(f"Fee amount is different than expected. "
                                      f"(amount={token_dict.fees_from_fee_header}, expected={expected_fee})")

        if htr_info.amount < htr_expected_amount:
            raise InputOutputMismatch('There\'s an invalid deficit of HTR. (amount={}, expected={})'.format(
                htr_info.amount,
                htr_expected_amount,
            ))

        assert htr_info.amount == htr_expected_amount

    @staticmethod
    def _check_token_permissions(token_uid: TokenUid, token_info: TokenInfo) -> None:
        """Verify whether token can be minted/melted based on its authority."""
        from hathorlib.conf.settings import HATHOR_TOKEN_UID
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

    def verify_mint_melt_basic(self, tx: Transaction) -> None:
        """Top-level: basic (no-storage) verification for MintHeader/MeltHeader.

        Fires whenever either header is present. Covers Rules M1 and M3, the
        well-formedness checks against tx.tokens length, and the NanoHeader
        same-token guard. The authority (Rule M2) and undeclared-supply (Rule M4)
        checks need storage and run later in `verify`.
        """
        if not tx.has_mint_header() and not tx.has_melt_header():
            return
        self.verify_mint_melt_headers_well_formed(tx)
        self.verify_mint_melt_requires_shielded(tx)
        self.verify_mint_melt_nano_compatibility(tx)

    def verify_mint_melt_headers_well_formed(self, tx: Transaction) -> None:
        """Per-entry shape and Rule M3 (a token may not appear in both headers).

        Wire-format constraints (count bounds, per-entry token_index in [1, 16],
        amount >= 1, uniqueness within a header) are enforced at deserialize-time.
        Here we additionally bound token_index against tx.tokens length and
        cross-check that no token appears in both MintHeader and MeltHeader.
        """
        mint_indexes: set[int] = set()
        melt_indexes: set[int] = set()
        n_tokens = len(tx.tokens)

        if tx.has_mint_header():
            for entry in tx.get_mint_header().entries:
                if entry.token_index > n_tokens:
                    raise InvalidMintMeltHeaderError(
                        f'MintHeader: token_index {entry.token_index} exceeds '
                        f'tx.tokens length {n_tokens}'
                    )
                mint_indexes.add(entry.token_index)

        if tx.has_melt_header():
            for entry in tx.get_melt_header().entries:
                if entry.token_index > n_tokens:
                    raise InvalidMintMeltHeaderError(
                        f'MeltHeader: token_index {entry.token_index} exceeds '
                        f'tx.tokens length {n_tokens}'
                    )
                melt_indexes.add(entry.token_index)

        # Rule M3: a token cannot appear in both headers.
        overlap = mint_indexes & melt_indexes
        if overlap:
            raise InvalidMintMeltHeaderError(
                f'MintHeader and MeltHeader share token_index(es) {sorted(overlap)}; '
                f'a token cannot be both minted and melted in the same transaction'
            )

    def verify_mint_melt_requires_shielded(self, tx: Transaction) -> None:
        """Rule M1: MintHeader/MeltHeader is valid only on shielded transactions.

        No-storage: "shielded" is detected via header presence —
        ShieldedOutputsHeader covers the mixed/partial-unshield case, and
        UnshieldBalanceHeader covers the full-unshield case. A tx that carries
        shielded inputs with neither header would also fail here; that case is
        independently rejected by the shielded balance verification (PR landing
        the augmented balance equation).
        """
        if not tx.has_mint_header() and not tx.has_melt_header():
            return
        if tx.has_shielded_outputs() or tx.has_unshield_balance_header():
            return
        raise ShieldedMintMeltForbiddenError(
            'MintHeader/MeltHeader requires the transaction to carry a '
            'ShieldedOutputsHeader or UnshieldBalanceHeader (Rule M1)'
        )

    def verify_mint_melt_nano_compatibility(self, tx: Transaction) -> None:
        """Reject the same token minted/melted via both a NanoHeader action and a Mint/Melt header.

        A NanoHeader may coexist with Mint/Melt headers. Cross-token combinations
        are fine, but a single token cannot be minted (or melted) through both
        channels at once — the amount would be ambiguous and the augmented balance
        equation would double-count.
        """
        if not tx.is_nano_contract():
            return
        if not tx.has_mint_header() and not tx.has_melt_header():
            return

        nano_header = tx.get_nano_header()
        nano_action_token_uids: set[bytes] = {action.token_uid for action in nano_header.get_actions()}

        if tx.has_mint_header():
            for entry in tx.get_mint_header().entries:
                token_uid = tx.get_token_uid(entry.token_index)
                if token_uid in nano_action_token_uids:
                    raise InvalidMintMeltHeaderError(
                        f'token {token_uid.hex()}: declared in both MintHeader and a '
                        f'NanoHeader action; supply changes must use a single channel per token'
                    )
        if tx.has_melt_header():
            for entry in tx.get_melt_header().entries:
                token_uid = tx.get_token_uid(entry.token_index)
                if token_uid in nano_action_token_uids:
                    raise InvalidMintMeltHeaderError(
                        f'token {token_uid.hex()}: declared in both MeltHeader and a '
                        f'NanoHeader action; supply changes must use a single channel per token'
                    )

    def verify_mint_melt_authority_inputs(self, tx: Transaction) -> None:
        """Rule M2: every MintHeader/MeltHeader entry needs the matching authority input.

        For each (token_index, amount) in MintHeader, the tx MUST consume at
        least one mint authority input for tx.tokens[token_index - 1]. Symmetric
        for MeltHeader. Authority inputs/outputs remain transparent, so this
        check walks `tx.inputs` and inspects each spent transparent output.

        TokenCreationTransaction is exempt for token_index=1 (the new token):
        the TCT itself grants both authorities to the issuer, so the MintHeader
        entry for the new token does not require a pre-existing authority input.
        """
        from hathor.transaction.token_creation_tx import TokenCreationTransaction

        if not tx.has_mint_header() and not tx.has_melt_header():
            return

        assert tx.storage is not None

        # Collect authority sets per token from transparent inputs.
        mint_authorities: set[bytes] = set()
        melt_authorities: set[bytes] = set()
        for tx_input in tx.inputs:
            spent_tx = tx.storage.get_transaction(tx_input.tx_id)
            if tx_input.index >= len(spent_tx.outputs):
                # Shielded inputs cannot be authority outputs.
                continue
            spent_output = spent_tx.outputs[tx_input.index]
            if not spent_output.is_token_authority():
                continue
            token_uid = spent_tx.get_token_uid(spent_output.get_token_index())
            if spent_output.can_mint_token():
                mint_authorities.add(token_uid)
            if spent_output.can_melt_token():
                melt_authorities.add(token_uid)

        is_tct = isinstance(tx, TokenCreationTransaction)

        if tx.has_mint_header():
            for entry in tx.get_mint_header().entries:
                if is_tct and entry.token_index == 1:
                    # The new token's authority is granted by the TCT itself.
                    continue
                token_uid = tx.get_token_uid(entry.token_index)
                if token_uid not in mint_authorities:
                    raise ForbiddenMint(entry.amount, token_uid)

        if tx.has_melt_header():
            for entry in tx.get_melt_header().entries:
                if is_tct and entry.token_index == 1:
                    continue
                token_uid = tx.get_token_uid(entry.token_index)
                if token_uid not in melt_authorities:
                    raise ForbiddenMelt.from_token(entry.amount, token_uid)

    def verify_no_undeclared_mint_melt(self, tx: Transaction, token_dict: TokenInfoDict) -> None:
        """Rule M4: reject mint/melt that is not declared via MintHeader/MeltHeader.

        Shielded txs hide non-HTR amounts, so a transparent token_dict surplus/deficit
        on a non-NATIVE token is only legitimate when covered by a corresponding
        Mint/Melt header entry. Without the header there is no public scalar to feed
        the augmented balance equation and the prover could mint from nothing.
        """
        mint_token_uids: set[bytes] = set()
        melt_token_uids: set[bytes] = set()
        if tx.has_mint_header():
            for entry in tx.get_mint_header().entries:
                mint_token_uids.add(tx.get_token_uid(entry.token_index))
        if tx.has_melt_header():
            for entry in tx.get_melt_header().entries:
                melt_token_uids.add(tx.get_token_uid(entry.token_index))

        for token_uid, token_info in token_dict.items():
            if token_info.version == TokenVersion.NATIVE:
                continue
            if token_info.can_mint and token_info.has_been_minted() and token_uid not in mint_token_uids:
                raise ShieldedMintMeltForbiddenError(
                    f'token {token_uid.hex()}: undeclared mint in shielded tx '
                    f'(transparent surplus: {token_info.amount}); declare via MintHeader'
                )
            if token_info.can_melt and token_info.has_been_melted() and token_uid not in melt_token_uids:
                raise ShieldedMintMeltForbiddenError(
                    f'token {token_uid.hex()}: undeclared melt in shielded tx '
                    f'(transparent deficit: {token_info.amount}); declare via MeltHeader'
                )

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
