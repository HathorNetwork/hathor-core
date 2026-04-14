#  Copyright 2025 Hathor Labs
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

"""NCBlockExecutor - Pure execution of nano contract transactions in a block."""

from __future__ import annotations

import hashlib
import traceback
from collections import defaultdict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterator

from hathor.feature_activation.utils import Features
from hathor.nanocontracts.exception import NCFail, NCInsufficientFunds
from hathor.nanocontracts.nano_runtime_version import NanoRuntimeVersion
from hathor.transaction import Block, Transaction
from hathor.transaction.exceptions import TokenNotFound
from hathor.transaction.nc_execution_state import NCExecutionState
from hathorlib.nanocontracts.runner.runner import MAX_SEQNUM_JUMP_SIZE
from hathorlib.nanocontracts.types import Address, BlueprintId, ContractId, NCRawArgs, VertexId

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.feature_activation.feature_service import FeatureService
    from hathor.nanocontracts.runner import Runner
    from hathor.nanocontracts.runner.runner import RunnerFactory
    from hathor.nanocontracts.sorter.types import NCSorterCallable
    from hathor.nanocontracts.storage import NCBlockStorage, NCStorageFactory
    from hathor.nanocontracts.types import TokenUid


# Transaction execution result types (also used as block execution effects)
@dataclass(slots=True, frozen=True)
class NCTxExecutionSuccess:
    """Result type for successful NC execution."""
    tx: Transaction
    block_storage: 'NCBlockStorage'
    runner: 'Runner | None' = None


@dataclass(slots=True, frozen=True)
class NCTxExecutionFailure:
    """Result type for failed NC execution."""
    tx: Transaction
    block_storage: 'NCBlockStorage | None'
    runner: 'Runner | None'
    exception: NCFail
    traceback: str
    persist_block_storage: bool = False


@dataclass(slots=True, frozen=True)
class NCTxExecutionSkipped:
    """Result type for skipped NC execution (voided transactions)."""
    tx: Transaction
    block_storage: 'NCBlockStorage | None' = None
    persist_block_storage: bool = False


NCTxExecutionResult = NCTxExecutionSuccess | NCTxExecutionFailure | NCTxExecutionSkipped


# Block execution lifecycle effect types for generator-based execution
@dataclass(slots=True, frozen=True)
class NCBeginBlock:
    """Effect yielded at the start of block execution."""
    block: Block
    parent_root_id: bytes
    block_storage: 'NCBlockStorage'
    nc_sorted_calls: list[Transaction]


@dataclass(slots=True, frozen=True)
class NCBeginTransaction:
    """Effect yielded at the start of transaction execution."""
    tx: Transaction
    rng_seed: bytes


@dataclass(slots=True, frozen=True)
class NCEndTransaction:
    """Effect yielded at the end of transaction processing."""
    tx: Transaction


@dataclass(slots=True, frozen=True)
class NCEndBlock:
    """Effect yielded at the end of block execution."""
    block: Block
    block_storage: 'NCBlockStorage'
    final_root_id: bytes


NCBlockEffect = (
    NCBeginBlock | NCBeginTransaction | NCTxExecutionResult |
    NCEndTransaction | NCEndBlock
)


class NCBlockExecutor:
    """
    Pure execution of nano contract and transfer-header transactions in a block.

    This class contains the core NC execution logic without any side effects.
    It yields execution events that can be processed by a caller to apply
    state changes.
    """

    def __init__(
        self,
        *,
        settings: 'HathorSettings',
        runner_factory: 'RunnerFactory',
        nc_storage_factory: 'NCStorageFactory',
        nc_calls_sorter: 'NCSorterCallable',
        feature_service: FeatureService,
    ) -> None:
        """
        Initialize the block executor.

        Args:
            settings: Hathor settings.
            runner_factory: Factory to create Runner instances.
            nc_storage_factory: Factory to create NC storage instances.
            nc_calls_sorter: Function to sort NC transactions for deterministic execution order.
        """
        self._settings = settings
        self._runner_factory = runner_factory
        self._nc_storage_factory = nc_storage_factory
        self._nc_calls_sorter = nc_calls_sorter
        self._feature_service = feature_service

    def execute_block(self, block: Block) -> Iterator[NCBlockEffect]:
        """Execute block as generator, yielding effects without applying them.

        This is the pure execution method that yields lifecycle events as it processes
        each transaction. The caller decides whether to apply the side effects.

        Args:
            block: The block to execute.

        Yields:
            NCBlockEffect instances representing each step of execution.
        """
        from hathor.nanocontracts import NC_EXECUTION_FAIL_ID

        assert self._settings.ENABLE_NANO_CONTRACTS
        assert not block.is_genesis, "Genesis blocks should be handled separately"

        meta = block.get_metadata()
        assert not meta.voided_by
        assert meta.nc_block_root_id is None

        parent = block.get_block_parent()
        parent_meta = parent.get_metadata()
        parent_root_id = parent_meta.nc_block_root_id
        assert parent_root_id is not None

        stateful_txs: list[Transaction] = []
        nc_calls: list[Transaction] = []
        for tx in block.iter_transactions_in_this_block():
            if not tx.is_nano_contract() and not tx.has_transfer_header():
                continue
            stateful_txs.append(tx)
            if not tx.is_nano_contract():
                continue
            tx_meta = tx.get_metadata()
            assert tx_meta.nc_execution in {None, NCExecutionState.PENDING}
            if tx_meta.voided_by:
                assert NC_EXECUTION_FAIL_ID not in tx_meta.voided_by
            nc_calls.append(tx)

        stateful_sorted_txs = self._nc_calls_sorter(block, stateful_txs) if stateful_txs else []
        nc_sorted_calls = [tx for tx in stateful_sorted_txs if tx.is_nano_contract()]
        block_storage = self._nc_storage_factory.get_block_storage(parent_root_id)
        features = Features.from_vertex(settings=self._settings, feature_service=self._feature_service, vertex=block)

        yield NCBeginBlock(
            block=block,
            parent_root_id=parent_root_id,
            block_storage=block_storage,
            nc_sorted_calls=nc_sorted_calls,
        )

        seed_hasher = hashlib.sha256(block.hash)

        current_root_id = parent_root_id

        for tx in stateful_sorted_txs:
            tx_block_storage = self._nc_storage_factory.get_block_storage(current_root_id)
            # Compute RNG seed for this transaction
            seed_hasher.update(tx.hash)
            seed_hasher.update(current_root_id)
            rng_seed = seed_hasher.digest()

            yield NCBeginTransaction(tx=tx, rng_seed=rng_seed)

            # Execute transaction and yield the result directly
            result = self.execute_transaction(
                runtime_version=features.nano_runtime_version,
                tx=tx,
                block_storage=tx_block_storage,
                rng_seed=rng_seed,
            )
            yield result

            match result:
                case NCTxExecutionSuccess(block_storage=result_block_storage):
                    current_root_id = result_block_storage.get_root_id()
                case NCTxExecutionFailure(block_storage=result_block_storage, persist_block_storage=True):
                    assert result_block_storage is not None
                    current_root_id = result_block_storage.get_root_id()
                case NCTxExecutionSkipped(block_storage=result_block_storage, persist_block_storage=True):
                    assert result_block_storage is not None
                    current_root_id = result_block_storage.get_root_id()
                case _:
                    pass

            yield NCEndTransaction(tx=tx)

        # Compute final root ID without committing
        final_root_id = current_root_id
        block_storage = self._nc_storage_factory.get_block_storage(final_root_id)
        if not stateful_sorted_txs:
            assert final_root_id == parent_root_id
        yield NCEndBlock(
            block=block,
            block_storage=block_storage,
            final_root_id=final_root_id,
        )

    def execute_transaction(
        self,
        *,
        runtime_version: NanoRuntimeVersion,
        tx: Transaction,
        block_storage: 'NCBlockStorage',
        rng_seed: bytes,
    ) -> NCTxExecutionResult:
        """Execute a single NC transaction.

        This method is pure and side-effect free. It does not persist anything,
        does not call callbacks, and returns all information needed by the caller
        to handle success/failure cases."""
        tx_meta = tx.get_metadata()
        if tx_meta.voided_by:
            if tx.is_nano_contract() and not tx.has_transfer_header():
                nc_header = tx.get_nano_header()
                nc_address = Address(nc_header.nc_address)
                seqnum = block_storage.get_address_seqnum(nc_address)
                if nc_header.nc_seqnum > seqnum:
                    block_storage.set_address_seqnum(nc_address, nc_header.nc_seqnum)
                return NCTxExecutionSkipped(tx=tx, block_storage=block_storage, persist_block_storage=True)
            return NCTxExecutionSkipped(tx=tx)

        if not tx.is_nano_contract():
            try:
                self._verify_transfer_header_balances(block_storage, tx)
                self._verify_transfer_header_seqnums(block_storage, tx)
                self._apply_transfer_header_diffs(block_storage, self._get_transfer_header_diffs(tx))
                self._apply_transfer_header_seqnums(block_storage, tx)
            except NCFail as e:
                return NCTxExecutionFailure(
                    tx=tx,
                    block_storage=None,
                    runner=None,
                    exception=e,
                    traceback=traceback.format_exc(),
                )
            return NCTxExecutionSuccess(tx=tx, block_storage=block_storage)

        transfer_header_diffs = self._get_transfer_header_diffs(tx)
        before_current_call_block_storage = self._nc_storage_factory.get_block_storage(block_storage.get_root_id())
        runner = self._runner_factory.create(
            runtime_version=runtime_version,
            block_storage=block_storage,
            before_current_call_block_storage=before_current_call_block_storage,
            seed=rng_seed,
        )

        try:
            if tx.has_transfer_header():
                self._verify_transfer_header_balances(block_storage, tx)
                self._apply_transfer_header_diffs(block_storage, transfer_header_diffs)

            nano_header = tx.get_nano_header()

            if nano_header.is_creating_a_new_contract():
                contract_id = ContractId(VertexId(tx.hash))
            else:
                contract_id = ContractId(VertexId(nano_header.nc_id))

            assert nano_header.nc_seqnum >= 0
            current_seqnum = runner.block_storage.get_address_seqnum(Address(nano_header.nc_address))
            diff = nano_header.nc_seqnum - current_seqnum
            if diff <= 0 or diff > MAX_SEQNUM_JUMP_SIZE:
                runner._last_call_info = runner._build_call_info(contract_id)
                raise NCFail(f'invalid seqnum (diff={diff})')
            runner.block_storage.set_address_seqnum(Address(nano_header.nc_address), nano_header.nc_seqnum)

            vertex_metadata = tx.get_metadata()
            assert vertex_metadata.first_block is not None, (
                "execute must only be called after first_block is updated"
            )

            context = nano_header.get_context()
            assert context.block.hash == vertex_metadata.first_block

            nc_args = NCRawArgs(nano_header.nc_args_bytes)
            if nano_header.is_creating_a_new_contract():
                blueprint_id = BlueprintId(VertexId(nano_header.nc_id))
                runner.create_contract_with_nc_args(contract_id, blueprint_id, context, nc_args)
            else:
                runner.call_public_method_with_nc_args(
                    contract_id, nano_header.nc_method, context, nc_args
                )

            self._verify_sum_after_execution(tx, block_storage)
        except NCFail as e:
            self._ensure_runner_has_last_call_info(tx, runner)
            return NCTxExecutionFailure(
                tx=tx,
                block_storage=block_storage if not tx.has_transfer_header() else None,
                runner=runner,
                exception=e,
                traceback=traceback.format_exc(),
                persist_block_storage=not tx.has_transfer_header(),
            )

        return NCTxExecutionSuccess(tx=tx, block_storage=block_storage, runner=runner)

    def _get_transfer_header_diffs(self, tx: Transaction) -> dict[tuple['Address', 'TokenUid'], int]:
        from hathor.nanocontracts.types import Address, TokenUid

        diffs: defaultdict[tuple[Address, TokenUid], int] = defaultdict(int)
        if not tx.has_transfer_header():
            return dict(diffs)

        transfer_header = tx.get_transfer_header()
        for txin in transfer_header.inputs:
            token_uid = TokenUid(tx.get_token_uid(txin.token_index))
            input_address = transfer_header.addresses[txin.address_index]
            diffs[(Address(input_address.address), token_uid)] -= txin.amount

        for txout in transfer_header.outputs:
            token_uid = TokenUid(tx.get_token_uid(txout.token_index))
            diffs[(Address(txout.address), token_uid)] += txout.amount

        return dict(diffs)

    def _verify_transfer_header_balances(
        self,
        block_storage: 'NCBlockStorage',
        tx: Transaction,
    ) -> None:
        transfer_header_diffs = self._get_transfer_header_diffs(tx)
        for (address, token_uid), diff in transfer_header_diffs.items():
            if diff >= 0:
                continue

            balance = block_storage.get_address_balance(address, token_uid)
            if balance + diff < 0:
                raise NCInsufficientFunds(
                    f'insufficient transfer-header balance for address={address.hex()} '
                    f'token={token_uid.hex()}: available={balance} required={-diff}'
                )

    def _verify_transfer_header_seqnums(self, block_storage: 'NCBlockStorage', tx: Transaction) -> None:
        if not tx.has_transfer_header():
            return

        transfer_header = tx.get_transfer_header()
        for input_address in transfer_header.addresses:
            current_seqnum = block_storage.get_address_seqnum(Address(input_address.address))
            diff = input_address.seqnum - current_seqnum
            if diff <= 0 or diff > MAX_SEQNUM_JUMP_SIZE:
                raise NCFail(f'invalid transfer-header seqnum (diff={diff})')

    def _apply_transfer_header_diffs(
        self,
        block_storage: 'NCBlockStorage',
        transfer_header_diffs: dict[tuple['Address', 'TokenUid'], int],
    ) -> None:
        from hathor.nanocontracts.types import Amount

        for (address, token_uid), diff in transfer_header_diffs.items():
            if diff == 0:
                continue
            block_storage.add_address_balance(address, Amount(diff), token_uid)

    def _apply_transfer_header_seqnums(self, block_storage: 'NCBlockStorage', tx: Transaction) -> None:
        if not tx.has_transfer_header():
            return

        transfer_header = tx.get_transfer_header()
        for input_address in transfer_header.addresses:
            block_storage.set_address_seqnum(Address(input_address.address), input_address.seqnum)

    def _ensure_runner_has_last_call_info(self, tx: Transaction, runner: 'Runner') -> None:
        from hathor.nanocontracts.types import ContractId, VertexId

        if runner._last_call_info is not None:
            return

        nano_header = tx.get_nano_header()
        if nano_header.is_creating_a_new_contract():
            contract_id = ContractId(VertexId(tx.hash))
        else:
            contract_id = ContractId(VertexId(nano_header.nc_id))
        runner._last_call_info = runner._build_call_info(contract_id)

    def _verify_sum_after_execution(self, tx: Transaction, block_storage: 'NCBlockStorage') -> None:
        """Verify token sums after execution for dynamically created tokens."""
        from hathor.verification.transaction_verifier import TransactionVerifier
        try:
            token_dict = tx.get_complete_token_info(block_storage)
            TransactionVerifier.verify_sum(self._settings, tx, token_dict)
        except TokenNotFound as e:
            # At this point, any nonexistent token would have made a prior validation fail. For example, if there
            # was a withdrawal of a nonexistent token, it would have failed in the balance validation before.
            raise AssertionError from e
        except Exception as e:
            raise NCFail from e
