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

from typing import NamedTuple, Self

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from hathor.difficulty import Hash
from hathor.nanocontracts import NanoContract
from hathor.transaction import Block
from hathor.types import VertexId


class SorterRNG:
    """Implement a deterministic random number generator that will be used by the sorter.

    This implementation uses the ChaCha20 encryption as RNG.
    """
    def __init__(self, seed: bytes) -> None:
        self.seed = Hash(seed)

        key = self.seed
        nonce = self.seed[:16]

        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None)
        self._encryptor = cipher.encryptor()

    def _randbits(self, bits: int) -> int:
        """Return a random integer in the range [0, 2**bits)."""
        # Generate 64-bit random string of bytes.
        assert bits >= 1
        size = bits // 8
        if bits % 8 != 0:
            size += 1
        ciphertext = self._encryptor.update(b'\0' * size)
        x = int.from_bytes(ciphertext, byteorder='little', signed=False)
        return x % (2**bits)

    def randbelow(self, n: int) -> int:
        """Return a random integer in the range [0, n)."""
        assert n >= 1
        k = n.bit_length()
        r = self._randbits(k)  # 0 <= r < 2**k
        while r >= n:
            r = self._randbits(k)
        return r


class SorterNode(NamedTuple):
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
    2. Filter out non-Nano transactions from the DAG, preserving dependency relations, in O(n).
    3. Apply Kahn's algorithm to produce a topological sort in O(n).
    """
    def __init__(self) -> None:
        self.db: dict[VertexId, SorterNode] = {}
        self._dirty: bool = False

    @classmethod
    def create_from_block(cls, block: Block, nc_calls: list[NanoContract]) -> Self:
        """Create a Sorter instance from the nano transactions confirmed by a block."""
        sorter = cls()

        # Add only edges from the funds DAG to the graph.
        for tx in block.iter_transactions_in_this_block():
            sorter.add_vertex(tx.hash)
            for txin in tx.inputs:
                sorter.add_edge(tx.hash, txin.tx_id)

        # Remove all transactions that do not belong to nc_calls.
        allowed_keys = set(tx.hash for tx in nc_calls)
        all_keys = list(sorter.db.keys())
        for key in all_keys:
            if key not in allowed_keys:
                sorter.remove_vertex(key)

        return sorter

    def copy(self) -> 'NCBlockSorter':
        """Copy the sorter. It is useful if one wants to call get_random_topological_order() multiple times."""
        if self._dirty:
            raise RuntimeError('copying a dirty sorter')
        new_sorter = NCBlockSorter()
        for vertex_id, vertex in self.db.items():
            new_sorter.db[vertex_id] = vertex.copy()
        return new_sorter

    def add_vertex(self, _id: VertexId) -> None:
        """Add a vertex to the DAG."""
        self.get_node(_id)

    def add_edge(self, _from: VertexId, _to: VertexId) -> None:
        """Add the edge (_from, _to) to this DAG."""
        self.get_node(_from).outgoing_edges.add(_to)
        self.get_node(_to).incoming_edges.add(_from)

    def get_node(self, _id: VertexId) -> SorterNode:
        """Get a node by id or create one if it does not exist."""
        vertex = self.db.get(_id)
        if vertex is not None:
            return vertex

        vertex = SorterNode(_id, set(), set())
        self.db[_id] = vertex
        return vertex

    def remove_vertex(self, _id: VertexId, *, discard: bool = False) -> None:
        """Remove vertex keeping the dependencies structure."""
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
        """Get all vertices with no outgoing edges."""
        return [v.id for v in self.db.values() if not v.outgoing_edges]

    def get_random_topological_order(self, seed: bytes, nc_calls: list[NanoContract]) -> list[NanoContract]:
        """Return a shuffled list of nano transactions that is a valid topological order."""
        order = self.generate_random_topological_order(seed)
        tx_by_id = dict((tx.hash, tx) for tx in nc_calls)
        assert set(order) == set(tx_by_id.keys())

        ret = []
        for _id in order:
            ret.append(tx_by_id[_id])
        return ret

    def generate_random_topological_order(self, seed: bytes) -> list[VertexId]:
        """Generate a random topological order according to the DAG.

        This method can only be called once because it changes the DAG during its execution.
        """
        if self._dirty:
            raise RuntimeError('this method can only be called once')
        self._dirty = True

        rng = SorterRNG(seed)

        candidates = self.get_vertices_with_no_outgoing_edges()
        ret = []
        for i in range(len(self.db)):
            idx = rng.randbelow(len(candidates))
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
