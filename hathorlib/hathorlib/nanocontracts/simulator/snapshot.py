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

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from hathorlib.nanocontracts.types import VertexId

if TYPE_CHECKING:
    from hathorlib.simulator.context_factory import ContextFactory
    from hathorlib.simulator.event_store import EventStore
    from hathorlib.simulator.id_generator import IdGenerator
    from hathorlib.simulator.in_memory_services import InMemoryTxStorage, SimulatorClock
    from hathorlib.simulator.in_memory_storage import InMemoryNCStorageFactory


@dataclass(frozen=True)
class SimulatorSnapshot:
    """Frozen simulation state that can be restored later.

    Captured via deep copy of all mutable in-memory state.

    Included in the snapshot:
        - Contract storage (trie): all contract state, balances, and blueprint associations.
        - Trie root pointer: used to rebuild NCBlockStorage on restore.
        - Token registry: HTR and any custom tokens created via create_token().
        - Clock time: the current simulated timestamp.
        - Block height: the current block height counter.
        - ID counter: ensures deterministic ID generation continues correctly.
        - Events and logs: all recorded events and execution logs, indexed by tx/block hash.
        - Current block hash: the hash of the in-progress block.

    NOT included (and why):
        - Blueprint registry: blueprint classes are code references, not mutable state.
          They persist across restore since blueprints are never unregistered.
        - Settings, RunnerFactory, runtime version: immutable configuration set at build time.
        - auto_new_block flag: configuration preference, not simulation state.
        - RNG seed hasher: not reset on restore, so the randomness sequence after restore
          will differ from the original path. Fine for testing but not bit-identical replay.
        - Pending block results: cleared on restore; any uncommitted tx results in the
          current block are lost.
        - Block data cache: not restored; lazily recreated on the next call.
    """
    trie_store_data: dict[bytes, Any]
    block_storage_root_id: bytes
    tokens: dict[bytes, Any]
    clock_time: float
    block_height: int
    id_counter: int
    event_store_state: dict[str, Any]
    current_block_hash: VertexId | None

    @staticmethod
    def capture(
        *,
        storage_factory: InMemoryNCStorageFactory,
        block_storage_root_id: bytes,
        tx_storage: InMemoryTxStorage,
        clock: SimulatorClock,
        context_factory: ContextFactory,
        id_generator: IdGenerator,
        event_store: EventStore,
        current_block_hash: VertexId | None,
    ) -> SimulatorSnapshot:
        """Capture the current simulation state as a frozen snapshot."""
        return SimulatorSnapshot(
            trie_store_data=copy.deepcopy(storage_factory._store._store),
            block_storage_root_id=block_storage_root_id,
            tokens=copy.deepcopy(tx_storage._tokens),
            clock_time=clock.seconds(),
            block_height=context_factory.block_height,
            id_counter=id_generator.counter,
            event_store_state=copy.deepcopy(event_store.__dict__),
            current_block_hash=current_block_hash,
        )

    def restore(
        self,
        *,
        storage_factory: InMemoryNCStorageFactory,
        tx_storage: InMemoryTxStorage,
        clock: SimulatorClock,
        context_factory: ContextFactory,
        id_generator: IdGenerator,
        event_store: EventStore,
    ) -> None:
        """Restore simulation state from this snapshot."""
        storage_factory._store._store = copy.deepcopy(self.trie_store_data)
        tx_storage._tokens = copy.deepcopy(self.tokens)
        clock.set_time(self.clock_time)
        context_factory.block_height = self.block_height
        id_generator.counter = self.id_counter
        restored = copy.deepcopy(self.event_store_state)
        for key, value in restored.items():
            setattr(event_store, key, value)
