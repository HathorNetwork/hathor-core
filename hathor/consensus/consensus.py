# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, assert_never

from structlog import get_logger

from hathor.consensus.block_consensus import BlockConsensusAlgorithmFactory
from hathor.consensus.context import ConsensusAlgorithmContext
from hathor.consensus.transaction_consensus import TransactionConsensusAlgorithmFactory
from hathor.execution_manager import non_critical_code
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.utils import Features
from hathor.nanocontracts.exception import NCInvalidSignature
from hathor.nanocontracts.execution import NCBlockExecutor, NCConsensusBlockExecutor
from hathor.profiler import get_cpu_profiler
from hathor.pubsub import HathorEvents
from hathor.transaction import BaseTransaction, Block, Transaction
from hathor.transaction.exceptions import InvalidInputData, RewardLocked, TooManySigOps
from hathor.util import not_none
from hathor.verification.verification_params import VerificationParams

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.feature_activation.feature_service import FeatureService
    from hathor.nanocontracts import NCStorageFactory
    from hathor.nanocontracts.nc_exec_logs import NCLogStorage
    from hathor.nanocontracts.runner.runner import RunnerFactory
    from hathor.nanocontracts.sorter.types import NCSorterCallable
    from hathor.transaction.storage import TransactionStorage

logger = get_logger()
cpu = get_cpu_profiler()

_base_transaction_log = logger.new()


@dataclass(slots=True, frozen=True, kw_only=True)
class ConsensusEvent:
    event: HathorEvents
    kwargs: dict[str, Any]


class ConsensusAlgorithm:
    """Execute the consensus algorithm marking blocks and transactions as either executed or voided.

    The consensus algorithm uses the metadata voided_by to set whether a block or transaction is executed.
    If voided_by is empty, then the block or transaction is executed. Otherwise, it is voided.

    The voided_by stores which hashes are causing the voidance. The hashes may be from both blocks and
    transactions.

    The voidance propagates through the DAG of transactions. For example, if tx1 is voided and tx2 verifies
    tx1, then tx2 must be voided as well. Another example is that, if a block is not in the bestchain,
    any transaction spending one of the block's outputs is also voided.

    In the DAG of transactions, the voided_by of tx1 is always a subset of the voided_by of all transactions
    that verifies tx1 or spend one of tx1's outputs. The hash of tx1 may only be on its own voided_by when
    tx1 has conflicts and is not the winner.

    When a block is not in the bestchain, its voided_by contains its hash. This hash is also propagated
    through the transactions that spend one of its outputs.

    Differently from transactions, the hash of the blocks are not propagated through the voided_by of
    other blocks. For example, if b0 <- b1 <- b2 <- b3 is a side chain, i.e., not the best blockchain,
    then b0's voided_by contains b0's hash, b1's voided_by contains b1's hash, and so on. The hash of
    b0 will not be propagated to the voided_by of b1, b2, and b3.
    """

    def __init__(
        self,
        nc_storage_factory: 'NCStorageFactory',
        soft_voided_tx_ids: set[bytes],
        *,
        settings: HathorSettings,
        tx_storage: TransactionStorage,
        runner_factory: RunnerFactory,
        nc_calls_sorter: NCSorterCallable,
        nc_log_storage: NCLogStorage,
        feature_service: FeatureService,
        nc_exec_fail_trace: bool = False,
    ) -> None:
        self._settings = settings
        self.log = logger.new()
        self.tx_storage = tx_storage
        self.nc_storage_factory = nc_storage_factory
        self.soft_voided_tx_ids = frozenset(soft_voided_tx_ids)

        # Create NCBlockExecutor (pure) for execution
        self._block_executor = NCBlockExecutor(
            settings=settings,
            runner_factory=runner_factory,
            nc_storage_factory=nc_storage_factory,
            nc_calls_sorter=nc_calls_sorter,
        )

        # Create NCConsensusBlockExecutor (with side effects) for consensus
        self._consensus_block_executor = NCConsensusBlockExecutor(
            settings=settings,
            block_executor=self._block_executor,
            nc_storage_factory=nc_storage_factory,
            nc_log_storage=nc_log_storage,
            nc_exec_fail_trace=nc_exec_fail_trace,
        )

        self.block_algorithm_factory = BlockConsensusAlgorithmFactory(
            settings, self._consensus_block_executor, feature_service,
        )
        self.transaction_algorithm_factory = TransactionConsensusAlgorithmFactory()
        self.nc_calls_sorter = nc_calls_sorter
        self.feature_service = feature_service

    def create_context(self) -> ConsensusAlgorithmContext:
        """Handy method to create a context that can be used to access block and transaction algorithms."""
        return ConsensusAlgorithmContext(self)

    @cpu.profiler(key=lambda self, base: 'consensus!{}'.format(base.hash.hex()))
    def unsafe_update(self, base: BaseTransaction) -> list[ConsensusEvent]:
        """
        Run a consensus update with its own context, indexes will be updated accordingly.

        It is considered unsafe because the caller is responsible for crashing the full node
        if this method throws any exception.
        """
        from hathor.transaction import Block, Transaction
        assert self.tx_storage.is_only_valid_allowed()
        meta = base.get_metadata()
        assert meta.validation.is_valid()

        # XXX: first make sure we can run the consensus update on this tx:
        meta = base.get_metadata()
        assert meta.voided_by is None or (self._settings.PARTIALLY_VALIDATED_ID not in meta.voided_by)
        assert meta.validation.is_fully_connected()

        # this context instance will live only while this update is running
        context = self.create_context()

        best_height, best_tip = self.tx_storage.indexes.height.get_height_tip()

        # This has to be called before the removal of vertices, otherwise this call may fail.
        old_best_block = self.tx_storage.get_block(best_tip)

        if isinstance(base, Transaction):
            context.transaction_algorithm.update_consensus(base)
        elif isinstance(base, Block):
            context.block_algorithm.update_consensus(base)
        else:
            raise NotImplementedError

        # signal a mempool tips index update for all affected transactions,
        # because that index is used on _compute_vertices_that_became_invalid below.
        for tx_affected in _sorted_affected_txs(context.txs_affected):
            self.tx_storage.indexes.mempool_tips.update(tx_affected)

        txs_to_remove: list[BaseTransaction] = []
        new_best_height, new_best_tip = self.tx_storage.indexes.height.get_height_tip()

        if context.reorg_info is not None:
            if new_best_height < best_height:
                self.log.warn(
                    'height decreased, re-checking mempool', prev_height=best_height, new_height=new_best_height,
                    prev_block_tip=best_tip.hex(), new_block_tip=new_best_tip.hex(),
                )

            # XXX: this method will mark as INVALID all transactions in the mempool that became invalid after the reorg
            txs_to_remove.extend(
                self._compute_vertices_that_became_invalid(new_best_block=context.reorg_info.new_best_block)
            )

        if txs_to_remove:
            self.log.warn('some transactions on the mempool became invalid and will be removed',
                          count=len(txs_to_remove))
            # XXX: because transactions in `txs_to_remove` are marked as invalid, we need this context to be
            # able to remove them
            with self.tx_storage.allow_invalid_context():
                self._remove_transactions(txs_to_remove, context)

        pubsub_events = []

        # emit the reorg started event if needed
        if context.reorg_info is not None:
            assert isinstance(old_best_block, Block)
            new_best_block = self.tx_storage.get_transaction(new_best_tip)
            reorg_size = old_best_block.get_height() - context.reorg_info.common_block.get_height()
            # TODO: After we remove block ties, should the assert below be true?
            # assert old_best_block.get_metadata().voided_by
            assert old_best_block != new_best_block
            assert reorg_size > 0
            self.log.info(
                'reorg detected',
                reorg_size=reorg_size,
                previous_best_block=old_best_block.hash_hex,
                new_best_block=new_best_block.hash_hex,
                common_block=context.reorg_info.common_block.hash_hex,
            )
            pubsub_events.append(ConsensusEvent(
                event=HathorEvents.REORG_STARTED,
                kwargs=dict(
                    old_best_height=best_height,
                    old_best_block=old_best_block,
                    new_best_height=new_best_height,
                    new_best_block=new_best_block,
                    common_block=context.reorg_info.common_block,
                    reorg_size=reorg_size,
                )
            ))

        # finally signal an index update for all affected transactions
        for tx_affected in _sorted_affected_txs(context.txs_affected):
            self.tx_storage.indexes.update_critical_indexes(tx_affected)
            with non_critical_code(self.log):
                self.tx_storage.indexes.update_non_critical_indexes(tx_affected)
            pubsub_events.append(ConsensusEvent(event=HathorEvents.CONSENSUS_TX_UPDATE, kwargs=dict(tx=tx_affected)))

        # signal all transactions of which the execution succeeded
        for tx_nc_success in context.nc_exec_success:
            pubsub_events.append(ConsensusEvent(event=HathorEvents.NC_EXEC_SUCCESS, kwargs=dict(tx=tx_nc_success)))

        # handle custom NC events
        if isinstance(base, Block):
            assert context.nc_events is not None
            for tx, events in context.nc_events:
                assert tx.is_nano_contract()
                for event in events:
                    pubsub_events.append(
                        ConsensusEvent(event=HathorEvents.NC_EVENT, kwargs=dict(tx=tx, nc_event=event))
                    )
        else:
            assert context.nc_events is None

        # And emit events for txs that were removed
        for tx_removed in txs_to_remove:
            pubsub_events.append(ConsensusEvent(event=HathorEvents.CONSENSUS_TX_REMOVED, kwargs=dict(tx=tx_removed)))

        # and also emit the reorg finished event if needed
        if context.reorg_info is not None:
            pubsub_events.append(ConsensusEvent(event=HathorEvents.REORG_FINISHED, kwargs={}))

        return pubsub_events

    def filter_out_voided_by_entries_from_parents(self, tx: BaseTransaction, voided_by: set[bytes]) -> set[bytes]:
        """Filter out voided_by entries that should be inherited from parents."""
        voided_by = set(voided_by)
        voided_by = self._filter_out_nc_fail_entries(tx, voided_by)
        voided_by = self._filter_out_soft_voided_entries(tx, voided_by)
        return voided_by

    def _filter_out_soft_voided_entries(self, tx: BaseTransaction, voided_by: set[bytes]) -> set[bytes]:
        """Remove voided_by entries of soft voided transactions."""
        from hathor.nanocontracts import NC_EXECUTION_FAIL_ID
        if not (self.soft_voided_tx_ids & voided_by):
            return voided_by
        ret = set()
        for h in voided_by:
            if h == self._settings.SOFT_VOIDED_ID:
                continue
            if h == self._settings.CONSENSUS_FAIL_ID:
                continue
            if h == NC_EXECUTION_FAIL_ID:
                continue
            if h == tx.hash:
                continue
            if h in self.soft_voided_tx_ids:
                continue
            tx3 = self.tx_storage.get_transaction(h)
            tx3_meta = tx3.get_metadata()
            tx3_voided_by: set[bytes] = tx3_meta.voided_by or set()
            if not (self.soft_voided_tx_ids & tx3_voided_by):
                ret.add(h)
        return ret

    def _filter_out_nc_fail_entries(self, tx: BaseTransaction, voided_by: set[bytes]) -> set[bytes]:
        """Remove NC_EXECUTION_FAIL_ID flag from voided_by inherited by parents."""
        from hathor.nanocontracts import NC_EXECUTION_FAIL_ID
        ret = set(voided_by)
        if NC_EXECUTION_FAIL_ID in ret:
            # If NC_EXECUTION_FAIL_ID is in voided_by, then tx.hash must be in voided_by too.
            # So we remove both of them.
            ret.remove(NC_EXECUTION_FAIL_ID)
            ret.remove(tx.hash)
        # Then we remove all hashes from transactions that also have the NC_EXECUTION_FAIL_ID flag.
        for h in voided_by:
            if h == self._settings.SOFT_VOIDED_ID:
                continue
            if h == NC_EXECUTION_FAIL_ID:
                continue
            if h == tx.hash:
                continue
            tx2 = self.tx_storage.get_transaction(h)
            tx2_meta = tx2.get_metadata()
            tx2_voided_by: set[bytes] = tx2_meta.voided_by or set()
            if NC_EXECUTION_FAIL_ID in tx2_voided_by:
                ret.discard(h)
        assert NC_EXECUTION_FAIL_ID not in ret
        return ret

    def _remove_transactions(self, txs: list[BaseTransaction], context: ConsensusAlgorithmContext) -> None:
        """Will remove all the transactions on the list from the database.

        Special notes:

        - will refuse and raise an error when removing all transactions would leave dangling transactions, that is,
          transactions without existing parent. That is, it expects the `txs` list to include all children of deleted
          txs, from both the confirmation and funds DAGs
        - inputs's spent_outputs should not have any of the transactions being removed as spending transactions,
          this method will update and save those transaction's metadata
        - parent's children metadata will be updated to reflect the removals
        - all indexes will be updated
        """
        parents_to_update: dict[bytes, list[bytes]] = defaultdict(list)
        txset = {tx.hash for tx in txs}
        for tx in txs:
            tx_meta = tx.get_metadata()
            assert not tx_meta.validation.is_checkpoint()
            assert bool(tx_meta.voided_by), 'removed txs must be voided'
            for parent in set(tx.parents) - txset:
                parents_to_update[parent].append(tx.hash)
            for child in tx.get_children():
                if child not in txset:
                    raise AssertionError(
                        'It is an error to try to remove transactions that would leave a gap in the DAG'
                    )
            for spending_txs in tx_meta.spent_outputs.values():
                if set(spending_txs) - txset:
                    raise AssertionError(
                        'It is an error to try to remove transactions that would leave a gap in the DAG'
                    )
            for tx_input in tx.inputs:
                spent_tx = tx.get_spent_tx(tx_input)
                spent_tx_meta = spent_tx.get_metadata()
                if tx.hash in spent_tx_meta.spent_outputs[tx_input.index]:
                    spent_tx_meta.spent_outputs[tx_input.index].remove(tx.hash)
                    context.save(spent_tx)
        for parent_hash, children_to_remove in parents_to_update.items():
            parent_tx = self.tx_storage.get_transaction(parent_hash)
            for child in children_to_remove:
                self.tx_storage.vertex_children.remove_child(parent_tx, child)
            context.save(parent_tx)
        for tx in txs:
            self.log.debug('remove transaction', tx=tx.hash_hex)
            self.tx_storage.remove_transaction(tx)

    def _compute_vertices_that_became_invalid(self, *, new_best_block: Block) -> list[BaseTransaction]:
        """This method will look for transactions in the mempool that have become invalid after a reorg."""
        from hathor.transaction.storage.traversal import BFSTimestampWalk
        from hathor.transaction.validation_state import ValidationState

        mempool_tips = list(self.tx_storage.indexes.mempool_tips.iter(self.tx_storage))
        if not mempool_tips:
            # Mempool is empty, nothing to remove.
            return []

        mempool_rules: tuple[Callable[[Transaction], bool], ...] = (
            lambda tx: self._reward_lock_mempool_rule(tx, new_best_block.get_height()),
            lambda tx: self._feature_activation_rules(tx, new_best_block),
            self._unknown_contract_mempool_rule,
        )

        find_invalid_bfs = BFSTimestampWalk(
            self.tx_storage, is_dag_funds=True, is_dag_verifications=True, is_left_to_right=False
        )

        invalid_txs: set[BaseTransaction] = set()

        # Run a right-to-left BFS starting from the mempool tips.
        for tx in find_invalid_bfs.run(mempool_tips, skip_root=False):
            if not isinstance(tx, Transaction):
                find_invalid_bfs.skip_neighbors()
                continue

            if tx.get_metadata().first_block is not None:
                find_invalid_bfs.skip_neighbors()
                continue

            # At this point, it's a mempool tx, so we have to re-verify it.
            if not all(rule(tx) for rule in mempool_rules):
                invalid_txs.add(tx)
            find_invalid_bfs.add_neighbors()

        # From the invalid txs, mark all vertices to the right as invalid. This includes both txs and blocks.
        to_remove: list[BaseTransaction] = []
        find_to_remove_bfs = BFSTimestampWalk(
            self.tx_storage, is_dag_funds=True, is_dag_verifications=True, is_left_to_right=True
        )
        for vertex in find_to_remove_bfs.run(invalid_txs, skip_root=False):
            vertex.set_validation(ValidationState.INVALID)
            to_remove.append(vertex)
            find_to_remove_bfs.add_neighbors()

        to_remove.reverse()
        return to_remove

    def _reward_lock_mempool_rule(self, tx: Transaction, new_best_height: int) -> bool:
        """
        Check whether a tx became invalid after a reorg because the new best height is not enough to unlock a reward.
        Return True if it's valid, False otherwise.
        """
        from hathor.verification.transaction_verifier import TransactionVerifier
        try:
            TransactionVerifier.verify_reward_locked_for_height(
                self._settings, tx, new_best_height, assert_min_height_verification=False
            )
        except RewardLocked:
            return False
        return True

    def _unknown_contract_mempool_rule(self, tx: Transaction) -> bool:
        """
        Check whether a tx became invalid after a reorg because the NC used in nc_id was unexecuted.
        Return True if it's valid, False otherwise.
        """
        if not tx.is_nano_contract():
            return True

        from hathor.nanocontracts.exception import NanoContractDoesNotExist
        nano_header = tx.get_nano_header()
        try:
            # TODO: We use this call to check whether the contract ID still exists after the reorg, as it may
            #  have been a contract created by another contract that became "unexecuted" after the reorg. We
            #  could use a more explicit check here instead of relying on this method.
            nano_header.get_blueprint_id()
        except NanoContractDoesNotExist:
            return False
        return True

    def _feature_activation_rules(self, tx: Transaction, new_best_block: Block) -> bool:
        """Check whether a tx became invalid because of some feature state of the new best block."""
        features = self.feature_service.get_feature_states(vertex=new_best_block)

        for feature, feature_state in features.items():
            is_active = feature_state.is_active()
            match feature:
                case Feature.NANO_CONTRACTS:
                    if not self._nano_activation_rule(tx, is_active):
                        return False
                case Feature.FEE_TOKENS:
                    if not self._fee_tokens_activation_rule(tx, is_active):
                        return False
                case Feature.COUNT_CHECKDATASIG_OP:
                    if not self._checkdatasig_count_rule(tx):
                        return False
                case Feature.OPCODES_V2:
                    if not self._opcodes_v2_activation_rule(tx, new_best_block):
                        return False
                case Feature.SHIELDED_TRANSACTIONS:
                    if not self._shielded_activation_rule(tx, is_active):
                        return False
                case (
                    Feature.INCREASE_MAX_MERKLE_PATH_LENGTH
                    | Feature.NOP_FEATURE_1
                    | Feature.NOP_FEATURE_2
                    | Feature.NOP_FEATURE_3
                ):
                    # These features do not affect transactions.
                    pass
                case _:
                    assert_never(feature)

        return True

    def _nano_activation_rule(self, tx: Transaction, is_active: bool) -> bool:
        """Check whether a tx became invalid because the reorg changed the nano feature activation state."""
        from hathor.nanocontracts import OnChainBlueprint

        if is_active:
            # When nano is active, this rule has no effect.
            return True

        # The nano feature activation is actually used to enable 2 use cases:
        if tx.is_nano_contract():
            return False

        if isinstance(tx, OnChainBlueprint):
            return False

        return True

    def _fee_tokens_activation_rule(self, tx: Transaction, is_active: bool) -> bool:
        """
        Check whether a tx became invalid because the reorg changed the fee-based tokens feature activation state.
        """
        from hathor.transaction.token_creation_tx import TokenCreationTransaction
        from hathor.transaction.token_info import TokenVersion

        if is_active:
            # When fee-based tokens feature is active, this rule has no effect.
            return True

        # The fee-based tokens feature activation is actually used to enable 2 use cases:
        if isinstance(tx, TokenCreationTransaction) and tx.token_version == TokenVersion.FEE:
            return False

        if tx.has_fees():
            return False

        return True

    def _shielded_activation_rule(self, tx: Transaction, is_active: bool) -> bool:
        """Check whether a tx became invalid because the reorg changed the shielded feature activation state."""
        if is_active:
            return True

        if tx.has_shielded_outputs():
            return False

        return True

    def _checkdatasig_count_rule(self, tx: Transaction) -> bool:
        """Check whether a tx became invalid because of the count checkdatasig feature."""
        from hathor.verification.vertex_verifier import VertexVerifier

        # We check all txs regardless of the feature state, because this rule
        # already prohibited mempool txs before the block feature activation.
        # Any exception in the sigops verification will be considered
        # a fail and the tx will be removed from the mempool.
        try:
            VertexVerifier._verify_sigops_output(settings=self._settings, vertex=tx, enable_checkdatasig_count=True)
        except Exception as e:
            if not isinstance(e, TooManySigOps):
                self.log.exception('unexpected exception in mempool-reverification')
            return False
        return True

    def _opcodes_v2_activation_rule(self, tx: Transaction, new_best_block: Block) -> bool:
        """Check whether a tx became invalid because of the opcodes V2 feature."""
        from hathor.verification.nano_header_verifier import NanoHeaderVerifier
        from hathor.verification.transaction_verifier import TransactionVerifier

        # We check all txs regardless of the feature state, because this rule
        # already prohibited mempool txs before the block feature activation.

        features = Features.from_vertex(
            settings=self._settings,
            feature_service=self.feature_service,
            vertex=new_best_block,
        )
        params = VerificationParams.default_for_mempool(best_block=new_best_block, features=features)

        # Any exception in the inputs verification will be considered
        # a fail and the tx will be removed from the mempool.
        try:
            TransactionVerifier._verify_inputs(self._settings, tx, params, skip_script=False)
        except Exception as e:
            if not isinstance(e, InvalidInputData):
                self.log.exception('unexpected exception in mempool-reverification')
            return False

        # Any exception in the nc_signature verification will be considered
        # a fail and the tx will be removed from the mempool.
        if tx.is_nano_contract():
            try:
                NanoHeaderVerifier._verify_nc_signature(self._settings, tx, params)
            except Exception as e:
                if not isinstance(e, NCInvalidSignature):
                    self.log.exception('unexpected exception in mempool-reverification')
                return False

        return True


def _sorted_affected_txs(affected_txs: set[BaseTransaction]) -> list[BaseTransaction]:
    """
    Sort affected txs by voided first, then descending timestamp (reverse topological order).
    This is useful for generating Reliable Integration events.
    """
    def sorter(tx: BaseTransaction) -> tuple[bool, int]:
        meta = tx.get_metadata()
        is_voided = bool(meta.voided_by)

        return is_voided, not_none(tx.timestamp)

    return sorted(affected_txs, key=sorter, reverse=True)
