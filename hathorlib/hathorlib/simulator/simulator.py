# Copyright 2026 Hathor Labs
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

"""Blueprint Simulator — high-level API for testing NanoContract blueprints."""

from __future__ import annotations

import hashlib
import importlib.util
import traceback
from pathlib import Path
from typing import Any, Callable

from hathorlib.nanocontracts import Blueprint, Context, NanoRuntimeVersion, NCFail, Runner, RunnerFactory
from hathorlib.nanocontracts.nc_exec_logs import NCExecEntry, NCEvent
from hathorlib.nanocontracts.storage import NCBlockStorage
from hathorlib.nanocontracts.storage.contract_storage import Balance
from hathorlib.nanocontracts.types import (
    BLUEPRINT_EXPORT_NAME,
    Address,
    BlueprintId,
    ContractId,
    NCAction,
    NCDepositAction,
    NCWithdrawalAction,
    NCAcquireAuthorityAction,
    NCGrantAuthorityAction,
    TokenUid,
    VertexId,
)
from hathorlib.nanocontracts.vertex_data import BlockData
from hathorlib.simulator.context_factory import ContextFactory
from hathorlib.simulator.event_store import EventStore
from hathorlib.simulator.id_generator import IdGenerator
from hathorlib.simulator.in_memory_services import InMemoryBlueprintService, InMemoryTxStorage, SimulatorClock
from hathorlib.simulator.in_memory_storage import InMemoryNCStorageFactory
from hathorlib.simulator.result import BlockResult, TxResult
from hathorlib.simulator.snapshot import SimulatorSnapshot
from hathorlib.token_info import TokenDescription, TokenVersion


class Simulator:
    """High-level API for testing NanoContract blueprints in-memory.

    Mirrors the NCBlockExecutor pattern:
    - A "current block" accumulates call results.
    - Each call_public/create_contract creates a fresh Runner.
    - On success, runner.commit() persists to block storage.
    - On failure, changes are discarded.
    - new_block() commits the block storage and starts a new one.

    With auto_new_block=True (default), new_block() is called after every
    successful call, making each call its own block. Set to False for
    multi-tx-per-block testing.

    Example:
        from hathorlib.simulator import Simulator, SimulatorBuilder

        sim = SimulatorBuilder().build()
        bid = sim.register_blueprint(MyBlueprint)
        alice = sim.create_address('alice')
        result = sim.create_contract(bid, caller=alice)
        sim.call_public(result.contract_id, 'do_something', caller=alice)
        value = sim.call_view(result.contract_id, 'get_value')
    """

    def __init__(
        self,
        *,
        runner_factory: RunnerFactory,
        runtime_version: NanoRuntimeVersion,
        storage_factory: InMemoryNCStorageFactory,
        blueprint_service: InMemoryBlueprintService,
        tx_storage: InMemoryTxStorage,
        clock: SimulatorClock,
        id_generator: IdGenerator,
        context_factory: ContextFactory,
        auto_new_block: bool = True,
    ) -> None:
        self._runner_factory = runner_factory
        self._runtime_version = runtime_version
        self._storage_factory = storage_factory
        self._blueprint_service = blueprint_service
        self._tx_storage = tx_storage
        self._clock = clock
        self._id_gen = id_generator
        self._ctx_factory = context_factory
        self._auto_new_block = auto_new_block
        self._event_store = EventStore()

        # Registered blueprint classes: class -> BlueprintId
        self._blueprint_ids: dict[type[Blueprint], BlueprintId] = {}

        # Current block state
        self._current_block_hash: VertexId | None = None
        self._current_block_data_cache: BlockData | None = None
        self._current_block_storage: NCBlockStorage | None = None
        self._current_block_results: list[TxResult] = []

        # RNG seed state (mirrors block_executor's seed_hasher)
        self._seed_hasher = hashlib.sha256(b'simulator')

        # Start the first block
        self._begin_block()

    # Block Lifecycle

    def _begin_block(self) -> None:
        """Begin a new block: create block storage from the current trie root.

        Block data (hash, timestamp) is created lazily via _ensure_block_data()
        so that advance_time() called between blocks is reflected in the timestamp.
        """
        if self._current_block_storage is None:
            # First block: empty storage
            self._current_block_storage = self._storage_factory.get_empty_block_storage()
        else:
            # Subsequent blocks: build on the committed root
            root_id = self._current_block_storage.get_root_id()
            self._current_block_storage = self._storage_factory.get_block_storage(root_id)

        self._current_block_results = []
        self._current_block_hash = None
        self._current_block_data_cache = None

    def _ensure_block_data(self) -> None:
        """Create block data on first use within a block, capturing the current clock time."""
        if self._current_block_data_cache is None:
            block_data = self._ctx_factory.next_block()
            self._current_block_hash = block_data.hash
            self._current_block_data_cache = block_data

    def new_block(self) -> BlockResult:
        """End the current block and start a new one.

        Commits the block storage (like ConsensusBlockExecutor does on NCEndBlock)
        and returns a summary of all transactions in the completed block.
        """
        assert self._current_block_storage is not None
        # Ensure block data exists (may be empty block with no calls)
        self._ensure_block_data()
        assert self._current_block_hash is not None

        # Commit block storage (mirrors consensus_block_executor NCEndBlock handling)
        self._current_block_storage.commit()

        result = BlockResult(
            block_hash=self._current_block_hash,
            block_height=self._ctx_factory.block_height,
            tx_results=list(self._current_block_results),
        )

        # Begin next block
        self._begin_block()
        return result

    # Blueprint Management

    def register_blueprint(self, blueprint_class: type[Blueprint]) -> BlueprintId:
        """Register a blueprint class. Returns its deterministic ID.

        Idempotent: registering the same class again returns the same ID.
        """
        if blueprint_class in self._blueprint_ids:
            return self._blueprint_ids[blueprint_class]

        blueprint_id = self._id_gen.create_blueprint_id(blueprint_class)
        self._blueprint_service.register_blueprint(blueprint_id, blueprint_class)
        self._blueprint_ids[blueprint_class] = blueprint_id
        return blueprint_id

    def load_blueprint(self, file_path: str | Path) -> BlueprintId:
        """Load and register a blueprint from a Python file.

        The file must export a ``__blueprint__`` variable that is a subclass of Blueprint.

        Returns the deterministic BlueprintId for the loaded class.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the file does not export ``__blueprint__`` or it is not a Blueprint subclass.
        """
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f'Blueprint file not found: {path}')

        module_name = f'_simulator_blueprint_{path.stem}'
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise ValueError(f'Cannot load module from: {path}')

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        blueprint_class = getattr(module, BLUEPRINT_EXPORT_NAME, None)
        if blueprint_class is None:
            raise ValueError(f'File {path} does not export a {BLUEPRINT_EXPORT_NAME} variable')
        if not (isinstance(blueprint_class, type) and issubclass(blueprint_class, Blueprint)):
            raise ValueError(f'{BLUEPRINT_EXPORT_NAME} in {path} is not a Blueprint subclass')

        return self.register_blueprint(blueprint_class)

    # Address and Token management

    def create_address(self, name: str) -> Address:
        """Create a deterministic test address from a human-readable name."""
        return self._id_gen.create_address(name)

    def create_token(self, name: str, symbol: str, version: TokenVersion = TokenVersion.DEPOSIT) -> TokenUid:
        """Create and register a custom token for testing."""
        token_uid = self._id_gen.create_token_uid(name)
        self._tx_storage.register_token(TokenDescription(
            token_id=token_uid,
            token_name=name,
            token_symbol=symbol,
            token_version=version,
        ))
        return token_uid

    # Contract Lifecycle

    def create_contract(
        self,
        blueprint_id: BlueprintId,
        *,
        caller: Address,
        args: tuple = (),
        kwargs: dict[str, Any] | None = None,
        actions: list[NCAction] | None = None,
    ) -> TxResult:
        """Create a new contract instance and call its initialize() method.

        Args:
            blueprint_id: The BlueprintId returned by register_blueprint() or load_blueprint().

        Returns a TxResult with the contract_id, tx_hash, block_hash, events, and logs.
        On failure, raises the NCFail exception (changes are not committed).
        """
        contract_id = self._id_gen.create_contract_id()

        def _do_create(runner: Runner, ctx: Context) -> Any:
            return runner.create_contract(
                contract_id, blueprint_id, ctx, *(args or ()), **(kwargs or {}),
            )

        return self._execute_call(
            contract_id=contract_id,
            caller=caller,
            actions=actions,
            fn=_do_create,
        )

    # Method Calls

    def call_public(
        self,
        contract_id: ContractId,
        method_name: str,
        *,
        caller: Address,
        args: tuple = (),
        kwargs: dict[str, Any] | None = None,
        actions: list[NCAction] | None = None,
    ) -> TxResult:
        """Call a public method on a contract.

        Returns a TxResult with tx_hash, block_hash, events, and logs.
        On failure, raises the NCFail exception (changes are not committed).
        """
        def _do_call(runner: Runner, ctx: Context) -> Any:
            return runner.call_public_method(
                contract_id, method_name, ctx, *(args or ()), **(kwargs or {}),
            )

        return self._execute_call(
            contract_id=contract_id,
            caller=caller,
            actions=actions,
            fn=_do_call,
        )

    def call_view(
        self,
        contract_id: ContractId,
        method_name: str,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """Call a view method on a contract. No state changes, no block advancement."""
        assert self._current_block_storage is not None
        self._ensure_block_data()
        runner = self._create_runner()
        return runner.call_view_method(contract_id, method_name, *args, **kwargs)

    # Core Execution

    def _create_runner(self) -> Runner:
        """Create a Runner for the current block, mirroring block_executor.execute_transaction."""
        assert self._current_block_storage is not None
        self._seed_hasher.update(self._current_block_storage.get_root_id())
        rng_seed = self._seed_hasher.digest()

        return self._runner_factory.create(
            runtime_version=self._runtime_version,
            block_storage=self._current_block_storage,
            seed=rng_seed,
        )

    def _execute_call(
        self,
        *,
        contract_id: ContractId,
        caller: Address | ContractId,
        actions: list[NCAction] | None,
        fn: Callable[[Runner, Context], Any],
    ) -> TxResult:
        """Execute a contract call following the block_executor pattern.

        1. Create a Runner (per-call, like block_executor creates per-tx)
        2. Create a Context with synthetic VertexData/BlockData
        3. Execute the call
        4. On success: runner.commit() (like consensus_block_executor on NCTxExecutionSuccess)
        5. On failure: discard runner (no commit, changes lost)
        6. Capture events and logs
        7. If auto_new_block: call new_block()
        """
        self._ensure_block_data()
        assert self._current_block_hash is not None
        runner = self._create_runner()

        # Create context using current block data
        block_data = self._ctx_factory.current_block_data()
        ctx = self._ctx_factory.create_context(
            caller=caller,
            block_data=block_data,
            actions=actions,
        )
        tx_hash = VertexId(ctx.vertex.hash)

        try:
            fn(runner, ctx)
        except NCFail:
            # On failure: don't commit, capture logs for debugging, re-raise
            call_info = runner.get_last_call_info()
            exec_entry = NCExecEntry.from_call_info(call_info, traceback.format_exc())
            self._event_store.record_tx(
                tx_hash=tx_hash,
                block_hash=self._current_block_hash,
                events=[],
                exec_entry=exec_entry,
            )
            # Invalidate block data cache so next call picks up current clock time
            self._current_block_data_cache = None
            raise

        # On success: commit runner changes (mirrors consensus_block_executor)
        runner.commit()

        # Capture events and logs
        call_info = runner.get_last_call_info()
        events = list(call_info.nc_logger.__events__)
        exec_entry = NCExecEntry.from_call_info(call_info, None)

        self._event_store.record_tx(
            tx_hash=tx_hash,
            block_hash=self._current_block_hash,
            events=events,
            exec_entry=exec_entry,
        )

        result = TxResult(
            tx_hash=tx_hash,
            block_hash=self._current_block_hash,
            contract_id=contract_id,
            events=events,
            exec_entry=exec_entry,
        )
        self._current_block_results.append(result)

        if self._auto_new_block:
            self.new_block()

        return result

    # State Inspection

    def get_balance(
        self,
        contract_id: ContractId,
        token_uid: TokenUid | None = None,
    ) -> Balance:
        """Get the balance of a contract for a given token.

        Returns a Balance object with .available and .locked attributes.
        """
        from hathorlib.conf.settings import HATHOR_TOKEN_UID
        assert self._current_block_storage is not None
        token = bytes(token_uid) if token_uid is not None else HATHOR_TOKEN_UID
        nc_storage = self._current_block_storage.get_contract_storage(contract_id)
        return nc_storage.get_balance(token)

    def has_contract(self, contract_id: ContractId) -> bool:
        """Check if a contract has been initialized."""
        assert self._current_block_storage is not None
        return self._current_block_storage.has_contract(contract_id)

    # Events & Logs

    def get_events(
        self,
        *,
        tx_hash: VertexId | None = None,
        block_hash: VertexId | None = None,
    ) -> list[NCEvent]:
        """Get events, optionally filtered by tx_hash or block_hash."""
        return self._event_store.get_events(tx_hash=tx_hash, block_hash=block_hash)

    def get_logs(
        self,
        *,
        tx_hash: VertexId | None = None,
        block_hash: VertexId | None = None,
    ) -> list[NCExecEntry]:
        """Get execution logs, optionally filtered by tx_hash or block_hash."""
        return self._event_store.get_logs(tx_hash=tx_hash, block_hash=block_hash)

    # Action Helpers

    @staticmethod
    def deposit(token_uid: TokenUid, amount: int) -> NCDepositAction:
        """Create a deposit action for use in method calls."""
        return NCDepositAction(token_uid=token_uid, amount=amount)

    @staticmethod
    def withdrawal(token_uid: TokenUid, amount: int) -> NCWithdrawalAction:
        """Create a withdrawal action for use in method calls."""
        return NCWithdrawalAction(token_uid=token_uid, amount=amount)

    @staticmethod
    def grant_authority(token_uid: TokenUid, *, mint: bool = False, melt: bool = False) -> NCGrantAuthorityAction:
        if not (mint or melt):
            raise ValueError("We cannot have an authority that is neither mint nor melt")
        return NCGrantAuthorityAction(token_uid=token_uid, mint=mint, melt=melt)

    @staticmethod
    def acquire_authority(token_uid: TokenUid, *, mint: bool = False, melt: bool = False) -> NCAcquireAuthorityAction:
        if not (mint or melt):
            raise ValueError("We cannot have an authority that is neither mint nor melt")
        return NCAcquireAuthorityAction(token_uid=token_uid, mint=mint, melt=melt)

    # Time Control

    def advance_time(self, seconds: float) -> None:
        """Advance the simulated clock by the given number of seconds."""
        self._clock.advance(seconds)

    def set_time(self, timestamp: float) -> None:
        """Set the simulated clock to a specific timestamp."""
        self._clock.set_time(timestamp)

    # Snapshot/Restore

    def snapshot(self) -> SimulatorSnapshot:
        """Take a snapshot of the current simulation state.

        Captures all in-memory state via deep copy, allowing restoration later.
        """
        assert self._current_block_storage is not None
        # Commit current block storage to ensure consistent state
        self._current_block_storage.commit()

        return SimulatorSnapshot.capture(
            storage_factory=self._storage_factory,
            block_storage_root_id=self._current_block_storage.get_root_id(),
            tx_storage=self._tx_storage,
            clock=self._clock,
            context_factory=self._ctx_factory,
            id_generator=self._id_gen,
            event_store=self._event_store,
            current_block_hash=self._current_block_hash,
        )

    def restore(self, snapshot: SimulatorSnapshot) -> None:
        """Restore simulation state from a snapshot.

        Replaces all in-memory state with the snapshot's state.
        """
        snapshot.restore(
            storage_factory=self._storage_factory,
            tx_storage=self._tx_storage,
            clock=self._clock,
            context_factory=self._ctx_factory,
            id_generator=self._id_gen,
            event_store=self._event_store,
        )
        # Rebuild block storage from the restored trie state
        self._current_block_hash = snapshot.current_block_hash
        self._current_block_results = []
        # Restore block storage from the snapshotted root ID
        self._current_block_storage = self._storage_factory.get_block_storage(snapshot.block_storage_root_id)

    # Properties

    @property
    def auto_new_block(self) -> bool:
        return self._auto_new_block

    @auto_new_block.setter
    def auto_new_block(self, value: bool) -> None:
        self._auto_new_block = value

    @property
    def block_height(self) -> int:
        return self._ctx_factory.block_height

    @property
    def clock_time(self) -> float:
        """Return the current simulated clock time."""
        return self._clock.seconds()
