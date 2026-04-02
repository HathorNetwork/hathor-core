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

from typing import TYPE_CHECKING

from hathorlib import TxVersion
from hathorlib.nanocontracts.context import Context
from hathorlib.nanocontracts.types import Address, ContractId, NCAction
from hathorlib.nanocontracts.vertex_data import BlockData, VertexData

if TYPE_CHECKING:
    from hathorlib.simulator.id_generator import IdGenerator
    from hathorlib.simulator.in_memory_services import SimulatorClock

# NC transaction version constant
_NC_TX_VERSION = TxVersion(5)


class ContextFactory:
    """Creates Context objects for simulation without real transactions."""

    def __init__(self, clock: SimulatorClock, id_generator: IdGenerator) -> None:
        self._clock = clock
        self._id_gen = id_generator
        self._block_height: int = 0
        self._current_block: BlockData | None = None

    def next_block(self) -> BlockData:
        """Advance to the next block and return its data."""
        self._block_height += 1
        self._current_block = BlockData(
            hash=self._id_gen.create_vertex_id(f'block_{self._block_height}'),
            timestamp=int(self._clock.seconds()),
            height=self._block_height,
        )
        return self._current_block

    def current_block_data(self) -> BlockData:
        """Return the current block data without advancing."""
        assert self._current_block is not None, 'No block has been created yet. Call next_block() first.'
        return self._current_block

    def make_vertex_data(self) -> VertexData:
        """Create minimal VertexData for simulation."""
        return VertexData(
            version=_NC_TX_VERSION,
            hash=self._id_gen.create_vertex_id('tx'),
            nonce=0,
            signal_bits=0,
            weight=1.0,
            inputs=(),
            outputs=(),
            tokens=(),
            parents=(),
            headers=(),
        )

    def create_context(
        self,
        *,
        caller: Address | ContractId,
        block_data: BlockData,
        actions: list[NCAction] | None = None,
    ) -> Context:
        """Create a Context for a method call."""
        grouped = Context.__group_actions__(actions or [])
        return Context(
            caller_id=caller,
            vertex_data=self.make_vertex_data(),
            block_data=block_data,
            actions=grouped,
        )

    @property
    def block_height(self) -> int:
        return self._block_height

    @block_height.setter
    def block_height(self, value: int) -> None:
        self._block_height = value
