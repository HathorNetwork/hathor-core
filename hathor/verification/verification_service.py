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
from hathor.nanocontracts import OnChainBlueprint
from hathor.profiler import get_cpu_profiler
from hathor.transaction import BaseTransaction, Block, MergeMinedBlock, Transaction, TxVersion
from hathor.transaction.poa import PoaBlock
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.transaction import TokenInfo
from hathor.transaction.validation_state import ValidationState
from hathor.types import TokenUid
from hathor.verification.vertex_verifiers import VertexVerifiers

cpu = get_cpu_profiler()


class VerificationService:
    __slots__ = ('_settings', 'verifiers', '_tx_storage')

    def __init__(
        self,
        *,
        settings: HathorSettings,
        verifiers: VertexVerifiers,
        tx_storage: TransactionStorage | None = None,
    ) -> None:
        self._settings = settings
        self.verifiers = verifiers
        self._tx_storage = tx_storage

    def validate_basic(self, vertex: BaseTransaction, *, skip_block_weight_verification: bool = False) -> bool:
        """ Run basic validations (all that are possible without dependencies) and update the validation state.

        If no exception is raised, the ValidationState will end up as `BASIC` and return `True`.
        """
        # XXX: skip validation if previously validated
        if vertex.get_metadata().validation.is_at_least_basic():
            return True

        self.verify_basic(vertex, skip_block_weight_verification=skip_block_weight_verification)
        vertex.set_validation(ValidationState.BASIC)

        return True

    def validate_full(
        self,
        vertex: BaseTransaction,
        *,
        skip_block_weight_verification: bool = False,
        sync_checkpoints: bool = False,
        reject_locked_reward: bool = True,
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
            self.verify_basic(vertex, skip_block_weight_verification=skip_block_weight_verification)

        self.verify(vertex, reject_locked_reward=reject_locked_reward)
        validation = ValidationState.CHECKPOINT_FULL if sync_checkpoints else ValidationState.FULL
        vertex.set_validation(validation)
        return True

    def verify_basic(self, vertex: BaseTransaction, *, skip_block_weight_verification: bool = False) -> None:
        """Basic verifications (the ones without access to dependencies: parents+inputs). Raises on error.

        Used by `self.validate_basic`. Should not modify the validation state."""
        self.verifiers.vertex.verify_version(vertex)
        self.verifiers.vertex.verify_headers(vertex)

        # We assert with type() instead of isinstance() because each subclass has a specific branch.
        match vertex.version:
            case TxVersion.REGULAR_BLOCK:
                assert type(vertex) is Block
                self._verify_basic_block(vertex, skip_weight_verification=skip_block_weight_verification)
            case TxVersion.MERGE_MINED_BLOCK:
                assert type(vertex) is MergeMinedBlock
                self._verify_basic_merge_mined_block(vertex, skip_weight_verification=skip_block_weight_verification)
            case TxVersion.POA_BLOCK:
                assert type(vertex) is PoaBlock
                self._verify_basic_poa_block(vertex)
            case TxVersion.REGULAR_TRANSACTION:
                assert type(vertex) is Transaction
                self._verify_basic_tx(vertex)
            case TxVersion.TOKEN_CREATION_TRANSACTION:
                assert type(vertex) is TokenCreationTransaction
                self._verify_basic_token_creation_tx(vertex)
            case TxVersion.ON_CHAIN_BLUEPRINT:
                assert type(vertex) is OnChainBlueprint
                assert self._settings.ENABLE_NANO_CONTRACTS and self._settings.ENABLE_ON_CHAIN_BLUEPRINTS
                self._verify_basic_on_chain_blueprint(vertex)
            case _:
                assert_never(vertex.version)

        if vertex.is_nano_contract():
            assert self._settings.ENABLE_NANO_CONTRACTS
            # nothing to do

    def _verify_basic_block(self, block: Block, *, skip_weight_verification: bool) -> None:
        """Partially run validations, the ones that need parents/inputs are skipped."""
        if not skip_weight_verification:
            self.verifiers.block.verify_weight(block)
        self.verifiers.block.verify_reward(block)

    def _verify_basic_merge_mined_block(self, block: MergeMinedBlock, *, skip_weight_verification: bool) -> None:
        self._verify_basic_block(block, skip_weight_verification=skip_weight_verification)

    def _verify_basic_poa_block(self, block: PoaBlock) -> None:
        self.verifiers.poa_block.verify_poa(block)
        self.verifiers.block.verify_reward(block)

    def _verify_basic_tx(self, tx: Transaction) -> None:
        """Partially run validations, the ones that need parents/inputs are skipped."""
        if tx.is_genesis:
            # TODO do genesis validation?
            return
        self.verifiers.tx.verify_parents_basic(tx)
        if self._settings.CONSENSUS_ALGORITHM.is_pow():
            self.verifiers.tx.verify_weight(tx)
        self.verify_without_storage(tx)

    def _verify_basic_token_creation_tx(self, tx: TokenCreationTransaction) -> None:
        self._verify_basic_tx(tx)

    def _verify_basic_on_chain_blueprint(self, tx: OnChainBlueprint) -> None:
        self._verify_basic_tx(tx)

    def verify(self, vertex: BaseTransaction, *, reject_locked_reward: bool = True) -> None:
        """Run all verifications. Raises on error.

        Used by `self.validate_full`. Should not modify the validation state."""
        # We assert with type() instead of isinstance() because each subclass has a specific branch.
        match vertex.version:
            case TxVersion.REGULAR_BLOCK:
                assert type(vertex) is Block
                self._verify_block(vertex)
            case TxVersion.MERGE_MINED_BLOCK:
                assert type(vertex) is MergeMinedBlock
                self._verify_merge_mined_block(vertex)
            case TxVersion.POA_BLOCK:
                assert type(vertex) is PoaBlock
                self._verify_poa_block(vertex)
            case TxVersion.REGULAR_TRANSACTION:
                assert type(vertex) is Transaction
                self._verify_tx(vertex, reject_locked_reward=reject_locked_reward)
            case TxVersion.TOKEN_CREATION_TRANSACTION:
                assert type(vertex) is TokenCreationTransaction
                self._verify_token_creation_tx(vertex, reject_locked_reward=reject_locked_reward)
            case TxVersion.ON_CHAIN_BLUEPRINT:
                assert type(vertex) is OnChainBlueprint
                # TODO: on-chain blueprint verifications
                self._verify_tx(vertex, reject_locked_reward=reject_locked_reward)
            case _:
                assert_never(vertex.version)

        if vertex.is_nano_contract():
            assert self._settings.ENABLE_NANO_CONTRACTS
            # nothing to do

    @cpu.profiler(key=lambda _, block: 'block-verify!{}'.format(block.hash.hex()))
    def _verify_block(self, block: Block) -> None:
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

        self.verify_without_storage(block)

        # (1) and (4)
        self.verifiers.vertex.verify_parents(block)

        self.verifiers.block.verify_height(block)

        self.verifiers.block.verify_mandatory_signaling(block)

    def _verify_merge_mined_block(self, block: MergeMinedBlock) -> None:
        self.verifiers.merge_mined_block.verify_aux_pow(block)
        self._verify_block(block)

    def _verify_poa_block(self, block: PoaBlock) -> None:
        self._verify_block(block)

    @cpu.profiler(key=lambda _, tx: 'tx-verify!{}'.format(tx.hash.hex()))
    def _verify_tx(
        self,
        tx: Transaction,
        *,
        reject_locked_reward: bool,
        token_dict: dict[TokenUid, TokenInfo] | None = None
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
        self.verify_without_storage(tx)
        self.verifiers.tx.verify_sigops_input(tx)
        self.verifiers.tx.verify_inputs(tx)  # need to run verify_inputs first to check if all inputs exist
        self.verifiers.tx.verify_sum(token_dict or tx.get_complete_token_info())
        self.verifiers.vertex.verify_parents(tx)
        if reject_locked_reward:
            self.verifiers.tx.verify_reward_locked(tx)

    def _verify_token_creation_tx(self, tx: TokenCreationTransaction, *, reject_locked_reward: bool) -> None:
        """ Run all validations as regular transactions plus validation on token info.

        We also overload verify_sum to make some different checks
        """
        token_dict = tx.get_complete_token_info()
        self._verify_tx(tx, reject_locked_reward=reject_locked_reward, token_dict=token_dict)
        self.verifiers.token_creation_tx.verify_minted_tokens(tx, token_dict)
        self.verifiers.token_creation_tx.verify_token_info(tx)

    def verify_without_storage(self, vertex: BaseTransaction) -> None:
        # We assert with type() instead of isinstance() because each subclass has a specific branch.
        match vertex.version:
            case TxVersion.REGULAR_BLOCK:
                assert type(vertex) is Block
                self._verify_without_storage_block(vertex)
            case TxVersion.MERGE_MINED_BLOCK:
                assert type(vertex) is MergeMinedBlock
                self._verify_without_storage_merge_mined_block(vertex)
            case TxVersion.POA_BLOCK:
                assert type(vertex) is PoaBlock
                self._verify_without_storage_poa_block(vertex)
            case TxVersion.REGULAR_TRANSACTION:
                assert type(vertex) is Transaction
                self._verify_without_storage_tx(vertex)
            case TxVersion.TOKEN_CREATION_TRANSACTION:
                assert type(vertex) is TokenCreationTransaction
                self._verify_without_storage_token_creation_tx(vertex)
            case TxVersion.ON_CHAIN_BLUEPRINT:
                assert type(vertex) is OnChainBlueprint
                self._verify_without_storage_on_chain_blueprint(vertex)
            case _:
                assert_never(vertex.version)

        if vertex.is_nano_contract():
            assert self._settings.ENABLE_NANO_CONTRACTS
            self._verify_without_storage_nano_header(vertex)

    def _verify_without_storage_base_block(self, block: Block) -> None:
        self.verifiers.block.verify_no_inputs(block)
        self.verifiers.vertex.verify_outputs(block)
        self.verifiers.block.verify_output_token_indexes(block)
        self.verifiers.block.verify_data(block)
        self.verifiers.vertex.verify_sigops_output(block)

    def _verify_without_storage_block(self, block: Block) -> None:
        """ Run all verifications that do not need a storage.
        """
        self.verifiers.vertex.verify_pow(block)
        self._verify_without_storage_base_block(block)

    def _verify_without_storage_merge_mined_block(self, block: MergeMinedBlock) -> None:
        self._verify_without_storage_block(block)

    def _verify_without_storage_poa_block(self, block: PoaBlock) -> None:
        self._verify_without_storage_base_block(block)

    def _verify_without_storage_tx(self, tx: Transaction) -> None:
        """ Run all verifications that do not need a storage.
        """
        if self._settings.CONSENSUS_ALGORITHM.is_pow():
            self.verifiers.vertex.verify_pow(tx)
        self.verifiers.tx.verify_number_of_inputs(tx)
        self.verifiers.vertex.verify_outputs(tx)
        self.verifiers.tx.verify_output_token_indexes(tx)
        self.verifiers.vertex.verify_sigops_output(tx)

    def _verify_without_storage_token_creation_tx(self, tx: TokenCreationTransaction) -> None:
        self._verify_without_storage_tx(tx)

    def _verify_without_storage_nano_header(self, tx: BaseTransaction) -> None:
        assert tx.is_nano_contract()
        self.verifiers.nano_header.verify_nc_signature(tx)
        self.verifiers.nano_header.verify_actions(tx)

    def _verify_without_storage_on_chain_blueprint(self, tx: OnChainBlueprint) -> None:
        self._verify_without_storage_tx(tx)
        self.verifiers.on_chain_blueprint.verify_pubkey_is_allowed(tx)
        self.verifiers.on_chain_blueprint.verify_nc_signature(tx)
        self.verifiers.on_chain_blueprint.verify_code(tx)
