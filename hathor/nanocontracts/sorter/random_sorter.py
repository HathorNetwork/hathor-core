# Copyright 2023 Hathor Labs
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

import hashlib
from collections import defaultdict
from dataclasses import dataclass

from sortedcontainers import SortedSet
from typing_extensions import Self

from hathor.nanocontracts.rng import NanoRNG
from hathor.transaction import Block, Transaction
from hathor.types import Address, VertexId


def random_nc_calls_sorter(block: Block, nc_calls: list[Transaction]) -> list[Transaction]:
    sorter = NCBlockSorter.create_from_block(block, nc_calls)
    seed = hashlib.sha256(block.hash).digest()

    order = sorter.generate_random_topological_order(seed)
    tx_by_id = dict((tx.hash, tx) for tx in nc_calls)
    assert set(order) == set(tx_by_id.keys())

    ret: list[Transaction] = []
    for _id in order:
        ret.append(tx_by_id[_id])
    return ret


@dataclass(slots=True, kw_only=True)
class SorterNode:
    id: VertexId
    outgoing_edges: set[VertexId]
    incoming_edges: set[VertexId]

    def copy(self) -> 'SorterNode':
        return SorterNode(
            id=self.id,
            outgoing_edges=set(self.outgoing_edges),
            incoming_edges=set(self.incoming_edges),
        )


class NCBlockSorter:
    """This class is responsible for sorting a list of Nano cryptocurrency
    transactions to be executed by the consensus algorithm. The transactions
    are sorted in topological order, ensuring proper dependency management.

    Algorithm:

    1. Construct a Directed Acyclic Graph (DAG) of dependencies in O(n).
    2. Add "dummy" nodes between groups of txs with the same seqnum, acting as proxies for DAG dependencies.
    3. Apply Kahn's algorithm to produce a topological sort in O(n). Skip nodes that are not part of nc_calls,
       that is, with IDs that are either not txs, not NCs, or are dummy nodes.
    """
    __slots__ = ('db', '_dirty', '_block', '_nc_hashes')

    def __init__(self, nc_hashes: set[VertexId]) -> None:
        self.db: dict[VertexId, SorterNode] = {}
        self._dirty: bool = False
        self._block: Block | None = None
        self._nc_hashes = nc_hashes

    @classmethod
    def create_from_block(cls, block: Block, nc_calls: list[Transaction]) -> Self:
        """Create a Sorter instance from the nano transactions confirmed by a block."""
        nc_hashes = set(tx.hash for tx in nc_calls)
        sorter = cls(nc_hashes)
        sorter._block = block

        # Add only edges from the funds DAG to the graph.
        for tx in block.iter_transactions_in_this_block():
            sorter.add_vertex(tx.hash)

            if tx.is_nano_contract():
                nano_header = tx.get_nano_header()
                sorter.add_edge(tx.hash, nano_header.nc_id)

            for txin in tx.inputs:
                sorter.add_edge(tx.hash, txin.tx_id)

        # Add edges from nano seqnum.

        # A dict of txs grouped by address and then seqnum.
        grouped_txs: defaultdict[Address, defaultdict[int, list[Transaction]]] = defaultdict(lambda: defaultdict(list))
        dummy_nodes = 0

        for tx in nc_calls:
            assert tx.is_nano_contract()
            nano_header = tx.get_nano_header()
            grouped_txs[nano_header.nc_address][nano_header.nc_seqnum].append(tx)

        for _address, txs_by_seqnum in grouped_txs.items():
            sorted_by_seqnum = sorted(txs_by_seqnum.items())
            for i in range(1, len(sorted_by_seqnum)):
                prev_seqnum, prev_txs = sorted_by_seqnum[i - 1]
                curr_seqnum, curr_txs = sorted_by_seqnum[i]
                dummy_node_id = f'dummy:{dummy_nodes}'.encode()
                sorter.add_vertex(dummy_node_id)
                dummy_nodes += 1

                # Add edges from the dummy node to all prev_txs
                for prev_tx in prev_txs:
                    sorter.add_edge(dummy_node_id, prev_tx.hash)

                # Add edges from curr_txs to the dummy node only when the
                # tx's timestamp is greater than all prev_txs timestamps
                max_prev_txs_timestamp = max(prev_txs, key=lambda tx: tx.timestamp).timestamp
                for curr_tx in curr_txs:
                    if curr_tx.timestamp > max_prev_txs_timestamp:
                        sorter.add_edge(curr_tx.hash, dummy_node_id)

        return sorter

    def copy(self) -> NCBlockSorter:
        """Copy the sorter. It is useful if one wants to call get_random_topological_order() multiple times."""
        if self._dirty:
            raise RuntimeError('copying a dirty sorter')
        new_sorter = NCBlockSorter(self._nc_hashes)
        for vertex_id, vertex in self.db.items():
            new_sorter.db[vertex_id] = vertex.copy()
        return new_sorter

    def add_vertex(self, _id: VertexId) -> None:
        """Add a vertex to the DAG."""
        _ = self.get_node(_id)

    def add_edge(self, from_: VertexId, to: VertexId) -> None:
        """Add the edge (_from, _to) to this DAG."""
        assert from_ != to
        self.get_node(from_).outgoing_edges.add(to)
        self.get_node(to).incoming_edges.add(from_)

    def get_node(self, id_: VertexId) -> SorterNode:
        """Get a node by id or create one if it does not exist."""
        vertex = self.db.get(id_)
        if vertex is not None:
            return vertex

        vertex = SorterNode(id=id_, outgoing_edges=set(), incoming_edges=set())
        self.db[id_] = vertex
        return vertex

    def get_vertices_with_no_outgoing_edges(self) -> SortedSet[VertexId]:
        """Get all vertices with no outgoing edges."""
        return SortedSet(v.id for v in self.db.values() if not v.outgoing_edges)

    def generate_random_topological_order(self, seed: bytes) -> list[VertexId]:
        """Generate a random topological order according to the DAG.

        This method can only be called once because it changes the DAG during its execution.
        """
        if self._dirty:
            raise RuntimeError('this method can only be called once')
        self._dirty = True

        rng = NanoRNG(seed)

        candidates = self.get_vertices_with_no_outgoing_edges()
        ret = []
        for i in range(len(self.db)):
            assert len(candidates) > 0, 'empty candidates, probably caused by circular dependencies in the graph'
            idx = len(candidates) - rng.randbelow(len(candidates)) - 1
            vertex_id = candidates.pop(idx)

            # Skip all nodes that do not belong to nc_calls, which are either non-nano txs or dummy nodes.
            if vertex_id in self._nc_hashes:
                ret.append(vertex_id)

            vertex = self.get_node(vertex_id)
            assert not vertex.outgoing_edges
            for in_vertex_id in vertex.incoming_edges:
                in_vertex = self.get_node(in_vertex_id)
                in_vertex.outgoing_edges.remove(vertex_id)

                if not in_vertex.outgoing_edges:
                    candidates.add(in_vertex_id)

        return ret
