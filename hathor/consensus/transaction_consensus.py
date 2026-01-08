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

from typing import TYPE_CHECKING, Any, Iterable, cast

from structlog import get_logger

from hathor.conf.get_settings import get_global_settings
from hathor.transaction import BaseTransaction, Block, Transaction, TxInput
from hathor.types import VertexId
from hathor.util import classproperty
from hathor.utils.weight import weight_to_work

if TYPE_CHECKING:
    from hathor.consensus.context import ConsensusAlgorithmContext

logger = get_logger()

_base_transaction_log = logger.new()


class TransactionConsensusAlgorithm:
    """Implement the consensus algorithm for transactions."""

    def __init__(self, context: 'ConsensusAlgorithmContext') -> None:
        self._settings = get_global_settings()
        self.context = context

    @classproperty
    def log(cls) -> Any:
        """ This is a workaround because of a bug on structlog (or abc).

        See: https://github.com/hynek/structlog/issues/229
        """
        return _base_transaction_log

    def update_consensus(self, tx: Transaction) -> None:
        self.mark_inputs_as_used(tx)
        self.update_voided_info(tx)
        self.set_conflict_twins(tx)
        self.execute_nano_contracts(tx)

    def execute_nano_contracts(self, tx: Transaction) -> None:
        """This method is called when the transaction is added to the mempool.

        The method is currently only executed when the transaction is confirmed by a block.
        Hence, we do nothing here.
        """
        pass

    def mark_inputs_as_used(self, tx: Transaction) -> None:
        """ Mark all its inputs as used
        """
        for txin in tx.inputs:
            self.mark_input_as_used(tx, txin)

    def mark_input_as_used(self, tx: Transaction, txin: TxInput) -> None:
        """ Mark a given input as used
        """
        assert tx.storage is not None

        spent_tx = tx.storage.get_transaction(txin.tx_id)
        spent_meta = spent_tx.get_metadata()
        spent_by = spent_meta.spent_outputs[txin.index]
        assert tx.hash not in spent_by

        # Update our meta.conflict_with.
        meta = tx.get_metadata()
        if spent_by:
            # We initially void ourselves. This conflict will be resolved later.
            if not meta.voided_by:
                meta.voided_by = {tx.hash}
            else:
                meta.voided_by.add(tx.hash)
            if meta.conflict_with:
                meta.conflict_with.extend(set(spent_by) - set(meta.conflict_with))
            else:
                meta.conflict_with = spent_by.copy()
        self.context.save(tx)

        for h in spent_by:
            # Update meta.conflict_with of our conflict transactions.
            conflict_tx = tx.storage.get_transaction(h)
            tx_meta = conflict_tx.get_metadata()
            if tx_meta.conflict_with:
                if tx.hash not in tx_meta.conflict_with:
                    # We could use a set instead of a list but it consumes ~2.15 times more of memory.
                    tx_meta.conflict_with.append(tx.hash)
            else:
                tx_meta.conflict_with = [tx.hash]
            self.context.save(conflict_tx)

        # Add ourselves to meta.spent_by of our input.
        spent_by.append(tx.hash)
        self.context.save(spent_tx)

    def set_conflict_twins(self, tx: Transaction) -> None:
        """ Get all transactions that conflict with self
            and check if they are also a twin of self
        """
        assert tx.storage is not None

        meta = tx.get_metadata()
        if not meta.conflict_with:
            return

        conflict_txs = [tx.storage.get_transaction(h) for h in meta.conflict_with]
        self.check_twins(tx, conflict_txs)

    def check_twins(self, tx: Transaction, transactions: Iterable[BaseTransaction]) -> None:
        """ Check if the tx has any twins in transactions list
            A twin tx is a tx that has the same inputs and outputs
            We add all the hashes of the twin txs in the metadata

        :param transactions: list of transactions to be checked if they are twins with self
        """
        assert tx.storage is not None

        # Getting tx metadata to save the new twins
        meta = tx.get_metadata()

        # Sorting inputs and outputs for easier validation
        sorted_inputs = sorted(tx.inputs, key=lambda x: (x.tx_id, x.index, x.data))
        sorted_outputs = sorted(tx.outputs, key=lambda x: (x.script, x.value))

        for candidate in transactions:

            # If quantity of inputs is different, it's not a twin.
            if len(candidate.inputs) != len(tx.inputs):
                continue

            # If quantity of outputs is different, it's not a twin.
            if len(candidate.outputs) != len(tx.outputs):
                continue

            # If the hash is the same, it's not a twin.
            if candidate.hash == tx.hash:
                continue

            # Verify if all the inputs are the same
            equal = True
            for index, tx_input in enumerate(sorted(candidate.inputs, key=lambda x: (x.tx_id, x.index, x.data))):
                if (tx_input.tx_id != sorted_inputs[index].tx_id or tx_input.data != sorted_inputs[index].data
                        or tx_input.index != sorted_inputs[index].index):
                    equal = False
                    break

            # Verify if all the outputs are the same
            if equal:
                for index, tx_output in enumerate(sorted(candidate.outputs, key=lambda x: (x.script, x.value))):
                    if (tx_output.value != sorted_outputs[index].value
                            or tx_output.script != sorted_outputs[index].script):
                        equal = False
                        break

            # If everything is equal we add in both metadatas
            if equal:
                meta.twins.append(candidate.hash)
                tx_meta = candidate.get_metadata()
                tx_meta.twins.append(tx.hash)
                self.context.save(candidate)

        self.context.save(tx)

    def update_voided_info(self, tx: Transaction) -> None:
        """ This method should be called only once when the transactions is added to the DAG.
        """
        from hathor.nanocontracts import NC_EXECUTION_FAIL_ID
        assert tx.storage is not None

        voided_by: set[bytes] = set()

        # Union of voided_by of parents
        for parent in tx.get_parents():
            parent_meta = parent.get_metadata()
            if parent_meta.voided_by:
                voided_by.update(
                    self.context.consensus.filter_out_voided_by_entries_from_parents(parent, parent_meta.voided_by)
                )
        assert self._settings.SOFT_VOIDED_ID not in voided_by
        assert NC_EXECUTION_FAIL_ID not in voided_by
        assert not (self.context.consensus.soft_voided_tx_ids & voided_by)

        # Union of voided_by of inputs
        for txin in tx.inputs:
            spent_tx = tx.storage.get_transaction(txin.tx_id)
            spent_meta = spent_tx.get_metadata()
            if spent_meta.voided_by:
                voided_by.update(spent_meta.voided_by)
                voided_by.discard(self._settings.SOFT_VOIDED_ID)
                voided_by.discard(NC_EXECUTION_FAIL_ID)
        assert self._settings.SOFT_VOIDED_ID not in voided_by
        assert NC_EXECUTION_FAIL_ID not in voided_by

        # Update accumulated weight of the transactions voiding us.
        assert tx.hash not in voided_by
        for h in voided_by:
            if h == self._settings.SOFT_VOIDED_ID:
                continue
            tx2 = tx.storage.get_transaction(h)
            tx2_meta = tx2.get_metadata()
            tx2_meta.accumulated_weight += weight_to_work(tx.weight)
            self.context.save(tx2)

        # Then, we add ourselves.
        meta = tx.get_metadata()
        assert not meta.voided_by or meta.voided_by == {tx.hash}
        assert meta.accumulated_weight == weight_to_work(tx.weight)
        if tx.hash in self.context.consensus.soft_voided_tx_ids:
            voided_by.add(self._settings.SOFT_VOIDED_ID)
            voided_by.add(tx.hash)
        if meta.conflict_with:
            voided_by.add(tx.hash)

        # We must save before marking conflicts as voided because
        # the conflicting tx might affect this tx's voided_by metadata.
        if voided_by:
            meta.voided_by = voided_by.copy()
            self.context.save(tx)
            tx.storage.del_from_indexes(tx)

        # Check conflicts of the transactions voiding us.
        for h in voided_by:
            if h == self._settings.SOFT_VOIDED_ID:
                continue
            if h == tx.hash:
                continue
            tx2 = tx.storage.get_transaction(h)
            if not tx2.is_block:
                assert isinstance(tx2, Transaction)
                self.check_conflicts(tx2)

        # Mark voided conflicts as voided.
        for h in meta.conflict_with or []:
            conflict_tx = cast(Transaction, tx.storage.get_transaction(h))
            conflict_tx_meta = conflict_tx.get_metadata()
            if conflict_tx_meta.voided_by:
                if conflict_tx_meta.first_block is not None:
                    # do nothing
                    self.assert_voided_with_first_block(conflict_tx)
                    self.log.info('skipping voided conflict with first block', conflict_tx=conflict_tx.hash_hex)
                else:
                    self.mark_as_voided(conflict_tx)

        # Finally, check our conflicts.
        meta = tx.get_metadata()
        if meta.voided_by == {tx.hash}:
            self.check_conflicts(tx)

        # Assert the final state is valid.
        self.assert_valid_consensus(tx)

    def assert_voided_with_first_block(self, tx: BaseTransaction) -> None:
        """Assert the voided transaction with first block is valid."""
        from hathor.nanocontracts import NC_EXECUTION_FAIL_ID
        assert tx.storage is not None

        meta = tx.get_metadata()
        assert meta.voided_by is not None
        if bool(self.context.consensus.soft_voided_tx_ids & meta.voided_by):
            # Soft voided txs can be confirmed by blocks.
            return
        if NC_EXECUTION_FAIL_ID in meta.voided_by:
            # Nano transactions that failed execution can be confirmed by blocks.
            assert tx.is_nano_contract()
            return
        for h in meta.voided_by:
            # Transactions voided by Nano transactions that failed execution can be confirmed by blocks.
            tx2 = cast(Transaction, tx.storage.get_transaction(h))
            tx2_meta = tx2.get_metadata()
            assert tx2_meta.voided_by
            if NC_EXECUTION_FAIL_ID in tx2_meta.voided_by:
                assert tx2.is_nano_contract()
                return
        raise AssertionError

    def assert_valid_consensus(self, tx: BaseTransaction) -> None:
        """Assert the conflict resolution is valid."""
        meta = tx.get_metadata()
        is_tx_executed = bool(not meta.voided_by)
        for h in meta.conflict_with or []:
            assert tx.storage is not None
            conflict_tx = cast(Transaction, tx.storage.get_transaction(h))
            conflict_tx_meta = conflict_tx.get_metadata()
            is_conflict_tx_executed = bool(not conflict_tx_meta.voided_by)
            assert not (is_tx_executed and is_conflict_tx_executed)

    def check_conflicts(self, tx: Transaction) -> None:
        """ Check which transaction is the winner of a conflict, the remaining are voided.

        The verification is made for each input, and `self` is only marked as winner if it
        wins in all its inputs.
        """
        assert tx.storage is not None
        self.log.debug('tx.check_conflicts', tx=tx.hash_hex)

        meta = tx.get_metadata()
        if meta.voided_by != {tx.hash}:
            return

        # Filter the possible candidates to compare to tx.
        candidates: list[Transaction] = []
        conflict_list: list[Transaction] = []
        for h in meta.conflict_with or []:
            conflict_tx = cast(Transaction, tx.storage.get_transaction(h))
            conflict_list.append(conflict_tx)
            conflict_tx_meta = conflict_tx.get_metadata()
            if not conflict_tx_meta.voided_by or conflict_tx_meta.voided_by == {conflict_tx.hash}:
                candidates.append(conflict_tx)

        # Check whether we have the highest accumulated weight.
        # First with the voided transactions.
        is_highest = True
        for candidate in candidates:
            tx_meta = candidate.get_metadata()
            if tx_meta.voided_by:
                if tx_meta.accumulated_weight > meta.accumulated_weight:
                    is_highest = False
                    break
        if not is_highest:
            return

        # Then, with the executed transactions.
        tie_list = []
        for candidate in candidates:
            tx_meta = candidate.get_metadata()
            if not tx_meta.voided_by:
                candidate.update_accumulated_weight(stop_value=meta.accumulated_weight)
                tx_meta = candidate.get_metadata()
                d = tx_meta.accumulated_weight - meta.accumulated_weight
                if d == 0:
                    tie_list.append(candidate)
                elif d > 0:
                    is_highest = False
                    break
        if not is_highest:
            return

        # If we got here, either it was a tie or we won.
        # So, let's void the conflict txs.
        for conflict_tx in sorted(conflict_list, key=lambda x: x.timestamp, reverse=True):
            self.mark_as_voided(conflict_tx)

        if not tie_list:
            # If it is not a tie, we won. \o/
            self.mark_as_winner(tx)

    def mark_as_winner(self, tx: Transaction) -> None:
        """ Mark a transaction as winner when it has a conflict and its aggregated weight
        is the greatest one.
        """
        self.log.debug('tx.mark_as_winner', tx=tx.hash_hex)
        meta = tx.get_metadata()
        assert bool(meta.conflict_with)  # FIXME: this looks like a runtime guarantee, MUST NOT be an assert
        assert meta.voided_by == {tx.hash}
        assert tx.hash not in self.context.consensus.soft_voided_tx_ids
        self.remove_voided_by(tx, tx.hash)
        self.assert_valid_consensus(tx)

    def remove_voided_by(self, tx: Transaction, voided_hash: bytes) -> bool:
        """ Remove a hash from `meta.voided_by` and its descendants (both from verification DAG
        and funds tree).
        """
        from hathor.transaction.storage.traversal import BFSTimestampWalk

        assert tx.storage is not None

        meta = tx.get_metadata()
        if not meta.voided_by:
            return False
        if voided_hash not in meta.voided_by:
            return False

        self.log.debug('remove_voided_by', tx=tx.hash_hex, voided_hash=voided_hash.hex())

        bfs = BFSTimestampWalk(tx.storage, is_dag_funds=True, is_dag_verifications=True, is_left_to_right=True)
        check_list: list[BaseTransaction] = []
        for tx2 in bfs.run(tx, skip_root=False):
            assert tx2.storage is not None

            meta2 = tx2.get_metadata()
            if not (meta2.voided_by and voided_hash in meta2.voided_by):
                bfs.skip_neighbors()
                continue
            if meta2.voided_by:
                meta2.voided_by.discard(voided_hash)
            if meta2.voided_by == {tx2.hash}:
                check_list.append(tx2)
            if not meta2.voided_by:
                meta2.voided_by = None
                tx.storage.add_to_indexes(tx2)
            self.context.save(tx2)
            self.assert_valid_consensus(tx2)
            bfs.add_neighbors()

        from hathor.transaction import Transaction
        for tx2 in check_list:
            if not tx2.is_block:
                assert isinstance(tx2, Transaction)
                self.check_conflicts(tx2)
        return True

    def mark_as_voided(self, tx: Transaction) -> None:
        """ Mark a transaction as voided when it has a conflict and its aggregated weight
        is NOT the greatest one.
        """
        self.log.debug('tx.mark_as_voided', tx=tx.hash_hex)
        meta = tx.get_metadata()
        assert bool(meta.conflict_with)
        if meta.voided_by and tx.hash in meta.voided_by:
            return
        self.add_voided_by(tx, tx.hash)
        self.assert_valid_consensus(tx)

    def has_only_nc_execution_fail_id(self, tx: Transaction) -> bool:
        """Return true if the only reason that tx is voided is because of nano execution failures."""
        from hathor.nanocontracts import NC_EXECUTION_FAIL_ID
        meta = tx.get_metadata()

        if meta.voided_by is None:
            return False
        assert meta.voided_by

        if tx.hash in meta.voided_by:
            if NC_EXECUTION_FAIL_ID not in meta.voided_by:
                # If tx has a conflict, it is voiding itself but did not failed nano execution,
                # then we can safely return False.
                return False

        for h in meta.voided_by:
            if h == tx.hash:
                continue
            if h == NC_EXECUTION_FAIL_ID:
                continue
            if h == self._settings.SOFT_VOIDED_ID:
                return False
            assert tx.storage is not None
            tx2 = tx.storage.get_transaction(h)
            tx2_meta = tx2.get_metadata()
            tx2_voided_by: set[VertexId] = tx2_meta.voided_by or set()
            if NC_EXECUTION_FAIL_ID not in tx2_voided_by:
                return False
            assert tx2_voided_by == {tx2.hash, NC_EXECUTION_FAIL_ID}

        return True

    def add_voided_by(self, tx: Transaction, voided_hash: bytes, *, is_dag_verifications: bool = True) -> bool:
        """ Add a hash from `meta.voided_by` and its descendants (both from verification DAG
        and funds tree).
        """
        assert tx.storage is not None

        meta = tx.get_metadata()
        if meta.voided_by and voided_hash in meta.voided_by:
            return False

        self.log.debug('add_voided_by', tx=tx.hash_hex, voided_hash=voided_hash.hex())

        if meta.voided_by and bool(self.context.consensus.soft_voided_tx_ids & meta.voided_by):
            # If tx is soft voided, we can only walk through the DAG of funds.
            is_dag_verifications = False

        if self.has_only_nc_execution_fail_id(tx):
            # If a transaction is voided solely because other nano transactions have failed execution,
            # we should restrict our traversal to the DAG of funds only. This is important because if
            # a transaction has a conflict and loses during conflict resolution, it will add itself
            # to meta.voided_by.
            is_dag_verifications = False

        from hathor.transaction.storage.traversal import BFSTimestampWalk
        bfs = BFSTimestampWalk(tx.storage, is_dag_funds=True, is_dag_verifications=is_dag_verifications,
                               is_left_to_right=True)
        check_list: list[Transaction] = []
        for tx2 in bfs.run(tx, skip_root=False):
            assert tx2.storage is not None
            meta2 = tx2.get_metadata()

            if tx2.is_block:
                assert isinstance(tx2, Block)
                self.context.block_algorithm.mark_as_voided(tx2)

            assert not meta2.voided_by or voided_hash not in meta2.voided_by
            if tx2.hash != tx.hash and meta2.conflict_with and not meta2.voided_by:
                check_list.extend(cast(Transaction, tx2.storage.get_transaction(h)) for h in meta2.conflict_with)
            if meta2.voided_by:
                meta2.voided_by.add(voided_hash)
            else:
                meta2.voided_by = {voided_hash}
            if meta2.conflict_with:
                assert isinstance(tx2, Transaction)
                self.mark_as_voided(tx2)
                # All voided transactions with conflicts must have their accumulated weight calculated.
                tx2.update_accumulated_weight(save_file=False)
            self.context.save(tx2)
            tx2.storage.del_from_indexes(tx2, relax_assert=True)
            self.assert_valid_consensus(tx2)
            bfs.add_neighbors()

        for tx2 in check_list:
            self.check_conflicts(tx2)
        return True


class TransactionConsensusAlgorithmFactory:
    def __call__(self, context: 'ConsensusAlgorithmContext') -> TransactionConsensusAlgorithm:
        return TransactionConsensusAlgorithm(context)
