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

from typing_extensions import assert_never

from hathor.conf.settings import HathorSettings
from hathor.nanocontracts import NCStorageFactory, OnChainBlueprint
from hathor.nanocontracts.storage import NCBlockStorage
from hathor.profiler import get_cpu_profiler
from hathor.transaction import BaseTransaction, Block, MergeMinedBlock, Transaction, TxVersion
from hathor.transaction.poa import PoaBlock
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.token_info import TokenInfoDict
from hathor.transaction.validation_state import ValidationState
from hathor.verification.fee_header_verifier import FeeHeaderVerifier
from hathor.verification.required_checks import Stage, required_checks_for
from hathor.verification.verification_context import VerificationContext
from hathor.verification.verification_params import VerificationParams
from hathor.verification.vertex_verifiers import VertexVerifiers

cpu = get_cpu_profiler()


class VerificationService:
    __slots__ = ('_settings', 'verifiers', '_tx_storage', '_nc_storage_factory')

    def __init__(
        self,
        *,
        settings: HathorSettings,
        verifiers: VertexVerifiers,
        tx_storage: TransactionStorage | None = None,
        nc_storage_factory: NCStorageFactory | None = None,
    ) -> None:
        self._settings = settings
        self.verifiers = verifiers
        self._tx_storage = tx_storage
        self._nc_storage_factory = nc_storage_factory

    def validate_basic(self, vertex: BaseTransaction, params: VerificationParams) -> bool:
        """ Run basic validations (all that are possible without dependencies) and update the validation state.

        If no exception is raised, the ValidationState will end up as `BASIC` and return `True`.
        """
        # XXX: skip validation if previously validated
        if vertex.get_metadata().validation.is_at_least_basic():
            return True

        self.verify_basic(vertex, params)
        vertex.set_validation(ValidationState.BASIC)

        return True

    def validate_full(
        self,
        vertex: BaseTransaction,
        params: VerificationParams,
        *,
        sync_checkpoints: bool = False,
        init_static_metadata: bool = True,
    ) -> bool:
        """ Run full validations (these need access to all dependencies) and update the validation state.

        If no exception is raised, the ValidationState will end up as `FULL` or `CHECKPOINT_FULL` and return `True`.
        """
        assert self._tx_storage is not None
        from hathor.transaction.transaction_metadata import ValidationState

        meta = vertex.get_metadata()
        if init_static_metadata:
            vertex.init_static_metadata_from_storage(self._settings, self._tx_storage)

        # skip full validation when it is a checkpoint
        if meta.validation.is_checkpoint():
            vertex.set_validation(ValidationState.CHECKPOINT_FULL)
            return True

        # XXX: in some cases it might be possible that this transaction is verified by a checkpoint but we went
        #      directly into trying a full validation so we should check it here to make sure the validation states
        #      ends up being CHECKPOINT_FULL instead of FULL
        if not meta.validation.is_at_least_basic():
            # run basic validation if we haven't already
            self.verify_basic(vertex, params)

        self.verify(vertex, params)
        validation = ValidationState.CHECKPOINT_FULL if sync_checkpoints else ValidationState.FULL
        vertex.set_validation(validation)
        return True

    def _new_context(self, vertex: BaseTransaction) -> VerificationContext:
        """Start a fresh VerificationContext for a verification stage. Each
        stage records its own incremental flags; we avoid touching metadata
        here so verify() can fail cheaply (e.g. WeightError) before any
        metadata read that could itself raise (weight→work on NaN/inf)."""
        return VerificationContext(vertex_hash=vertex.hash or b'')

    def _persist_context(self, vertex: BaseTransaction, ctx: VerificationContext) -> None:
        """Accumulate this stage's flags into metadata. OR semantics — prior
        stages' flags are preserved."""
        meta = vertex.get_metadata()
        meta.verification_checks |= ctx.checks_run

    def verify_basic(
        self,
        vertex: BaseTransaction,
        params: VerificationParams,
    ) -> None:
        """Basic verifications (the ones without access to dependencies: parents+inputs). Raises on error.

        Used by `self.validate_basic`. Should not modify the validation state."""
        if vertex.hash in self._settings.SKIP_VERIFICATION:
            return

        ctx = self._new_context(vertex)

        self.verifiers.vertex.verify_version_basic(vertex, ctx=ctx)
        self.verifiers.vertex.verify_old_timestamp(vertex, params, ctx=ctx)

        # We assert with type() instead of isinstance() because each subclass has a specific branch.
        match vertex.version:
            case TxVersion.REGULAR_BLOCK:
                assert type(vertex) is Block
                self._verify_basic_block(vertex, params, ctx)
            case TxVersion.MERGE_MINED_BLOCK:
                assert type(vertex) is MergeMinedBlock
                self._verify_basic_merge_mined_block(vertex, params, ctx)
            case TxVersion.POA_BLOCK:
                assert type(vertex) is PoaBlock
                self._verify_basic_poa_block(vertex, ctx)
            case TxVersion.REGULAR_TRANSACTION:
                assert type(vertex) is Transaction
                self._verify_basic_tx(vertex, params, ctx)
            case TxVersion.TOKEN_CREATION_TRANSACTION:
                assert type(vertex) is TokenCreationTransaction
                self._verify_basic_token_creation_tx(vertex, params, ctx)
            case TxVersion.ON_CHAIN_BLUEPRINT:
                assert type(vertex) is OnChainBlueprint
                assert self._settings.ENABLE_NANO_CONTRACTS
                self._verify_basic_on_chain_blueprint(vertex, params, ctx)
            case _:  # pragma: no cover
                assert_never(vertex.version)

        if vertex.is_nano_contract():
            assert self._settings.ENABLE_NANO_CONTRACTS
            # nothing to do

        required = required_checks_for(vertex, params, self._settings, Stage.VERIFY_BASIC)
        ctx.check(required, stage=Stage.VERIFY_BASIC.value)
        self._persist_context(vertex, ctx)

    def _verify_basic_block(self, block: Block, params: VerificationParams, ctx: VerificationContext) -> None:
        """Partially run validations, the ones that need parents/inputs are skipped."""
        if not params.skip_block_weight_verification:
            self.verifiers.block.verify_weight(block, ctx=ctx)
        self.verifiers.block.verify_reward(block, ctx=ctx)
        self.verifiers.block.verify_checkpoints(block, ctx=ctx)

    def _verify_basic_merge_mined_block(
        self, block: MergeMinedBlock, params: VerificationParams, ctx: VerificationContext
    ) -> None:
        self._verify_basic_block(block, params, ctx)

    def _verify_basic_poa_block(self, block: PoaBlock, ctx: VerificationContext) -> None:
        self.verifiers.poa_block.verify_poa(block, ctx=ctx)
        self.verifiers.block.verify_reward(block, ctx=ctx)

    def _verify_basic_tx(self, tx: Transaction, params: VerificationParams, ctx: VerificationContext) -> None:
        """Partially run validations, the ones that need parents/inputs are skipped."""
        if tx.is_genesis:
            # TODO do genesis validation?
            return
        self.verifiers.tx.verify_parents_basic(tx, ctx=ctx)
        if self._settings.CONSENSUS_ALGORITHM.is_pow():
            self.verifiers.tx.verify_weight(tx, ctx=ctx)
        self._verify_without_storage(tx, params, ctx)

    def _verify_basic_token_creation_tx(
        self, tx: TokenCreationTransaction, params: VerificationParams, ctx: VerificationContext
    ) -> None:
        self._verify_basic_tx(tx, params, ctx)

    def _verify_basic_on_chain_blueprint(
        self, tx: OnChainBlueprint, params: VerificationParams, ctx: VerificationContext
    ) -> None:
        self._verify_basic_tx(tx, params, ctx)

    def verify(self, vertex: BaseTransaction, params: VerificationParams) -> None:
        """Run all verifications. Raises on error.

        Used by `self.validate_full`. Should not modify the validation state."""
        if vertex.hash in self._settings.SKIP_VERIFICATION:
            return

        ctx = self._new_context(vertex)

        self.verifiers.vertex.verify_headers(vertex, params, ctx=ctx)

        # We assert with type() instead of isinstance() because each subclass has a specific branch.
        match vertex.version:
            case TxVersion.REGULAR_BLOCK:
                assert type(vertex) is Block
                self._verify_block(vertex, params, ctx)
            case TxVersion.MERGE_MINED_BLOCK:
                assert type(vertex) is MergeMinedBlock
                self._verify_merge_mined_block(vertex, params, ctx)
            case TxVersion.POA_BLOCK:
                assert type(vertex) is PoaBlock
                self._verify_poa_block(vertex, params, ctx)
            case TxVersion.REGULAR_TRANSACTION:
                assert type(vertex) is Transaction
                self._verify_tx(vertex, params, ctx)
            case TxVersion.TOKEN_CREATION_TRANSACTION:
                assert type(vertex) is TokenCreationTransaction
                self._verify_token_creation_tx(vertex, params, ctx)
            case TxVersion.ON_CHAIN_BLUEPRINT:
                assert type(vertex) is OnChainBlueprint
                self._verify_tx(vertex, params, ctx)
            case _:  # pragma: no cover
                assert_never(vertex.version)

        if vertex.is_nano_contract():
            assert self._settings.ENABLE_NANO_CONTRACTS
            self.verifiers.nano_header.verify_method_call(vertex, params, ctx=ctx)
            self.verifiers.nano_header.verify_seqnum(vertex, params, ctx=ctx)

        required = required_checks_for(vertex, params, self._settings, Stage.VERIFY)
        ctx.check(required, stage=Stage.VERIFY.value)
        self._persist_context(vertex, ctx)

    @cpu.profiler(key=lambda _, block, params, ctx: 'block-verify!{}'.format(block.hash.hex()))
    def _verify_block(self, block: Block, params: VerificationParams, ctx: VerificationContext) -> None:
        """
            (1) confirms at least two pending transactions and references last block
            (2) solves the pow with the correct weight (done in HathorManager)
            (3) creates the correct amount of tokens in the output (done in HathorManager)
            (4) all parents must exist and have timestamp smaller than ours
            (5) data field must contain at most BLOCK_DATA_MAX_SIZE bytes
            (6) whether this block must signal feature support
        """
        # TODO Should we validate a limit of outputs?
        if block.is_genesis:
            # TODO do genesis validation
            return

        self._verify_without_storage(block, params, ctx)

        # (1) and (4)
        self.verifiers.vertex.verify_parents(block, ctx=ctx)
        self.verifiers.block.verify_height(block, ctx=ctx)
        self.verifiers.block.verify_mandatory_signaling(block, ctx=ctx)

    def _verify_merge_mined_block(
        self, block: MergeMinedBlock, params: VerificationParams, ctx: VerificationContext
    ) -> None:
        self.verifiers.merge_mined_block.verify_aux_pow(block, ctx=ctx)
        self._verify_block(block, params, ctx)

    def _verify_poa_block(self, block: PoaBlock, params: VerificationParams, ctx: VerificationContext) -> None:
        self._verify_block(block, params, ctx)

    @cpu.profiler(key=lambda _, tx, params, ctx, **kw: 'tx-verify!{}'.format(tx.hash.hex()))
    def _verify_tx(
        self,
        tx: Transaction,
        params: VerificationParams,
        ctx: VerificationContext,
        *,
        token_dict: TokenInfoDict | None = None
    ) -> None:
        """ Common verification for all transactions:
           (i) number of inputs is at most 256
          (ii) number of outputs is at most 256
         (iii) confirms at least two pending transactions
          (iv) solves the pow (we verify weight is correct in HathorManager)
           (v) validates signature of inputs
          (vi) validates public key and output (of the inputs) addresses
         (vii) validate that both parents are valid
        (viii) validate input's timestamps
          (ix) validate inputs and outputs sum
        """
        if tx.is_genesis:
            # TODO do genesis validation
            return
        self._verify_without_storage(tx, params, ctx)
        self.verifiers.tx.verify_sigops_input(tx, params.features.count_checkdatasig_op, ctx=ctx)
        self.verifiers.tx.verify_inputs(tx, params, ctx=ctx)
        self.verifiers.tx.verify_version(tx, params, ctx=ctx)

        block_storage = self._get_block_storage(params)
        self.verifiers.tx.verify_sum(
            self._settings,
            tx,
            token_dict or tx.get_complete_token_info(block_storage),
            # if this tx isn't a nano contract we assume we can find all the tokens to validate this tx
            allow_nonexistent_tokens=tx.is_nano_contract(),
            ctx=ctx,
        )

        self.verifiers.vertex.verify_parents(tx, ctx=ctx)
        self.verifiers.tx.verify_conflict(tx, params, ctx=ctx)
        if params.reject_locked_reward:
            self.verifiers.tx.verify_reward_locked(tx, ctx=ctx)

    def _verify_token_creation_tx(
        self, tx: TokenCreationTransaction, params: VerificationParams, ctx: VerificationContext
    ) -> None:
        """ Run all validations as regular transactions plus validation on token info.

        We also overload verify_sum to make some different checks
        """
        # we should validate the token info before verifying the tx
        self.verifiers.token_creation_tx.verify_token_info(tx, params, ctx=ctx)
        token_dict = tx.get_complete_token_info(self._get_block_storage(params))
        self._verify_tx(tx, params, ctx, token_dict=token_dict)
        self.verifiers.token_creation_tx.verify_minted_tokens(tx, token_dict, ctx=ctx)

    def verify_without_storage(self, vertex: BaseTransaction, params: VerificationParams) -> None:
        """Public entry point for verify_without_storage — creates a standalone
        context, runs the checks, persists flags. Used only by callers outside
        the normal verify_basic/verify flow (no completeness assertion)."""
        if vertex.hash in self._settings.SKIP_VERIFICATION:
            return
        ctx = self._new_context(vertex)
        self._verify_without_storage(vertex, params, ctx)
        self._persist_context(vertex, ctx)

    def _verify_without_storage(
        self, vertex: BaseTransaction, params: VerificationParams, ctx: VerificationContext
    ) -> None:
        if vertex.hash in self._settings.SKIP_VERIFICATION:
            return

        if vertex.has_fees():
            self._verify_without_storage_fee_header(vertex, ctx)

        # We assert with type() instead of isinstance() because each subclass has a specific branch.
        match vertex.version:
            case TxVersion.REGULAR_BLOCK:
                assert type(vertex) is Block
                self._verify_without_storage_block(vertex, params, ctx)
            case TxVersion.MERGE_MINED_BLOCK:
                assert type(vertex) is MergeMinedBlock
                self._verify_without_storage_merge_mined_block(vertex, params, ctx)
            case TxVersion.POA_BLOCK:
                assert type(vertex) is PoaBlock
                self._verify_without_storage_poa_block(vertex, params, ctx)
            case TxVersion.REGULAR_TRANSACTION:
                assert type(vertex) is Transaction
                self._verify_without_storage_tx(vertex, params, ctx)
            case TxVersion.TOKEN_CREATION_TRANSACTION:
                assert type(vertex) is TokenCreationTransaction
                self._verify_without_storage_token_creation_tx(vertex, params, ctx)
            case TxVersion.ON_CHAIN_BLUEPRINT:
                assert type(vertex) is OnChainBlueprint
                self._verify_without_storage_on_chain_blueprint(vertex, params, ctx)
            case _:  # pragma: no cover
                assert_never(vertex.version)

        if vertex.is_nano_contract():
            assert self._settings.ENABLE_NANO_CONTRACTS
            self._verify_without_storage_nano_header(vertex, params, ctx)

    def _verify_without_storage_base_block(
        self, block: Block, params: VerificationParams, ctx: VerificationContext
    ) -> None:
        self.verifiers.block.verify_no_inputs(block, ctx=ctx)
        self.verifiers.vertex.verify_outputs(block, ctx=ctx)
        self.verifiers.block.verify_output_token_indexes(block, ctx=ctx)
        self.verifiers.block.verify_data(block, ctx=ctx)
        self.verifiers.vertex.verify_sigops_output(block, params.features.count_checkdatasig_op, ctx=ctx)

    def _verify_without_storage_block(
        self, block: Block, params: VerificationParams, ctx: VerificationContext
    ) -> None:
        """ Run all verifications that do not need a storage.
        """
        self.verifiers.vertex.verify_pow(block, ctx=ctx)
        self._verify_without_storage_base_block(block, params, ctx)

    def _verify_without_storage_merge_mined_block(
        self, block: MergeMinedBlock, params: VerificationParams, ctx: VerificationContext
    ) -> None:
        self._verify_without_storage_block(block, params, ctx)

    def _verify_without_storage_poa_block(
        self, block: PoaBlock, params: VerificationParams, ctx: VerificationContext
    ) -> None:
        self._verify_without_storage_base_block(block, params, ctx)

    def _verify_without_storage_tx(
        self, tx: Transaction, params: VerificationParams, ctx: VerificationContext
    ) -> None:
        """ Run all verifications that do not need a storage.
        """
        if self._settings.CONSENSUS_ALGORITHM.is_pow():
            self.verifiers.vertex.verify_pow(tx, ctx=ctx)
        self.verifiers.tx.verify_number_of_inputs(tx, ctx=ctx)
        self.verifiers.vertex.verify_outputs(tx, ctx=ctx)
        self.verifiers.tx.verify_output_token_indexes(tx, ctx=ctx)
        self.verifiers.vertex.verify_sigops_output(tx, params.features.count_checkdatasig_op, ctx=ctx)
        self.verifiers.tx.verify_tokens(tx, params, ctx=ctx)

    def _verify_without_storage_token_creation_tx(
        self,
        tx: TokenCreationTransaction,
        params: VerificationParams,
        ctx: VerificationContext,
    ) -> None:
        self._verify_without_storage_tx(tx, params, ctx)

    def _verify_without_storage_nano_header(
        self, tx: BaseTransaction, params: VerificationParams, ctx: VerificationContext
    ) -> None:
        assert tx.is_nano_contract()
        self.verifiers.nano_header.verify_nc_signature(tx, params, ctx=ctx)
        self.verifiers.nano_header.verify_actions(tx, ctx=ctx)

    def _verify_without_storage_fee_header(self, tx: BaseTransaction, ctx: VerificationContext) -> None:
        assert tx.has_fees()
        assert isinstance(tx, Transaction)
        FeeHeaderVerifier.verify_fee_list(tx.get_fee_header(), tx, ctx=ctx)

    def _verify_without_storage_on_chain_blueprint(
        self,
        tx: OnChainBlueprint,
        params: VerificationParams,
        ctx: VerificationContext,
    ) -> None:
        self._verify_without_storage_tx(tx, params, ctx)
        self.verifiers.on_chain_blueprint.verify_pubkey_is_allowed(tx, ctx=ctx)
        self.verifiers.on_chain_blueprint.verify_nc_signature(tx, ctx=ctx)
        self.verifiers.on_chain_blueprint.verify_code(tx, ctx=ctx)

    def _get_block_storage(self, params: VerificationParams) -> NCBlockStorage:
        assert self._nc_storage_factory is not None
        if params.nc_block_root_id is None:
            return self._nc_storage_factory.get_empty_block_storage()
        return self._nc_storage_factory.get_block_storage(params.nc_block_root_id)
