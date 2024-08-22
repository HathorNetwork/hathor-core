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

from math import floor
from typing import NamedTuple, Self

from hathor.nanocontracts import NanoContract
from hathor.transaction import Block
from hathor.types import VertexId
from hathor.util import Random


class SorterNode(NamedTuple):
    id: VertexId
    outgoing_edges: set[VertexId]
    incoming_edges: set[VertexId]

    def copy(self) -> Self:
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
    2. Filter out non-Nano transactions from the DAG, preserving dependency relations, in O(n).
    3. Apply Kahn's algorithm to produce a topological sort in O(n).
    """
    def __init__(self):
        self.db: dict[VertexId, SorterNode] = {}
        self._dirty: bool = False

    @classmethod
    def create_from_block(cls, block: Block, nc_calls: list[NanoContract]) -> Self:
        sorter = cls()

        # Add all edges to the graph.
        for tx in block.iter_transactions_in_this_block():
            for pi in tx.parents:
                sorter.add_edge(tx.hash, pi)
            for txin in tx.inputs:
                sorter.add_edge(tx.hash, txin.tx_id)

        # Remove all transactions that do not belong to nc_calls.
        allowed_keys = set(tx.hash for tx in nc_calls)
        all_keys = list(sorter.db.keys())
        for key in all_keys:
            if key not in allowed_keys:
                sorter.remove_vertex(key)

        return sorter

    def copy(self) -> Self:
        if self._dirty:
            raise RuntimeError('copying a dirty sorter')
        new_sorter = NCBlockSorter()
        for vertex_id, vertex in self.db.items():
            new_sorter.db[vertex_id] = vertex.copy()
        return new_sorter

    def add_edge(self, _from: VertexId, _to: VertexId) -> None:
        self.get_node(_from).outgoing_edges.add(_to)
        self.get_node(_to).incoming_edges.add(_from)

    def get_node(self, _id: VertexId) -> SorterNode:
        vertex = self.db.get(_id)
        if vertex is not None:
            return vertex

        vertex = SorterNode(_id, set(), set())
        self.db[_id] = vertex
        return vertex

    def remove_vertex(self, _id: VertexId, *, discard: bool = False) -> None:
        if discard and _id not in self.db:
            return
        vertex = self.db.pop(_id)

        for in_vertex_id in vertex.incoming_edges:
            in_vertex = self.get_node(in_vertex_id)
            in_vertex.outgoing_edges.update(vertex.outgoing_edges)
            in_vertex.outgoing_edges.remove(_id)

        for out_vertex_id in vertex.outgoing_edges:
            out_vertex = self.get_node(out_vertex_id)
            out_vertex.incoming_edges.update(vertex.incoming_edges)
            out_vertex.incoming_edges.remove(_id)

    def get_vertices_with_no_outgoing_edges(self) -> list[VertexId]:
        return [v.id for v in self.db.values() if not v.outgoing_edges]

    def get_random_topological_order(self, seed: bytes, nc_calls: list[NanoContract]) -> list[NanoContract]:
        order = self.generate_random_topological_order(seed)
        tx_by_id = dict((tx.hash, tx) for tx in nc_calls)
        assert set(order) == set(tx_by_id.keys())

        ret = []
        for _id in order:
            ret.append(tx_by_id[_id])
        return ret

    def generate_random_topological_order(self, seed: bytes) -> list[VertexId]:
        if self._dirty:
            raise RuntimeError('this method can only be called once')
        self._dirty = True

        # Most of the random module’s algorithms and seeding functions are subject to change across Python versions,
        # but two aspects are guaranteed not to change:
        #
        # - If a new seeding method is added, then a backward compatible seeder will be offered.
        #
        # - The generator’s random() method will continue to produce the same sequence when the compatible seeder is
        #   given the same seed.
        #
        # https://docs.python.org/3/library/random.html#random.Random
        rng = Random(seed)

        candidates = self.get_vertices_with_no_outgoing_edges()
        ret = []
        for i in range(len(self.db)):
            idx = floor(rng.random() * len(candidates))
            # FIXME pop() runs in O(n)
            vertex_id = candidates.pop(idx)
            ret.append(vertex_id)

            vertex = self.get_node(vertex_id)
            assert not vertex.outgoing_edges
            for in_vertex_id in vertex.incoming_edges:
                in_vertex = self.get_node(in_vertex_id)
                in_vertex.outgoing_edges.remove(vertex_id)

                if not in_vertex.outgoing_edges:
                    candidates.append(in_vertex_id)

        return ret
