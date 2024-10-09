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

import heapq
from abc import ABC, abstractmethod
from collections import deque
from itertools import chain
from typing import TYPE_CHECKING, Iterable, Iterator, Optional, Union

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction  # noqa: F401
    from hathor.transaction.storage import VertexStorageProtocol
    from hathor.types import VertexId


class HeapItem:
    """ Used by the heap of the BFS to get the transactions sorted by timestamp.
    """
    def __init__(self, tx: 'BaseTransaction', *, reverse: bool = False):
        self.tx = tx
        if not reverse:
            self.key = tx.timestamp
        else:
            self.key = -tx.timestamp

    def __lt__(self, other: 'HeapItem') -> bool:
        return self.key < other.key

    def __le__(self, other: 'HeapItem') -> bool:
        return self.key <= other.key


class GenericWalk(ABC):
    """ A helper class to walk on the DAG.
    """
    seen: set['VertexId']

    def __init__(
        self,
        storage: VertexStorageProtocol,
        *,
        is_dag_funds: bool = False,
        is_dag_verifications: bool = False,
        is_left_to_right: bool = True,
    ) -> None:
        """
        If `is_left_to_right` is `True`, we walk in the direction of the unverified transactions.
        Otherwise, we walk in the direction of the genesis.

        :param is_dag_funds: Add neighbors from the DAG of funds
        :param is_dag_verifications: Add neighbors from the DAG of verifications
        :param is_left_to_right: Decide which side of the DAG we will walk to
        """
        self.storage = storage
        self.seen = set()

        self.is_dag_funds = is_dag_funds
        self.is_dag_verifications = is_dag_verifications
        self.is_left_to_right = is_left_to_right

        self._reverse_heap: bool = not self.is_left_to_right
        self._ignore_neighbors: Optional['BaseTransaction'] = None

    @abstractmethod
    def _push_visit(self, tx: 'BaseTransaction') -> None:
        """ Add tx to be visited later.
        """
        raise NotImplementedError

    @abstractmethod
    def _pop_visit(self) -> 'BaseTransaction':
        """ Return the next tx to be visited.
        """
        raise NotImplementedError

    @abstractmethod
    def _is_empty(self) -> bool:
        """ Return true if there aren't any txs left to be visited.
        """
        raise NotImplementedError

    def _get_iterator(self, tx: 'BaseTransaction', *, is_left_to_right: bool) -> Iterator['VertexId']:
        meta = None
        it: Iterator['VertexId'] = chain()

        if self.is_dag_verifications:
            if is_left_to_right:
                meta = meta or tx.get_metadata()
                it = chain(it, meta.children)
            else:
                it = chain(it, tx.parents)

        if self.is_dag_funds:
            if is_left_to_right:
                meta = meta or tx.get_metadata()
                it = chain(it, *meta.spent_outputs.values())
            else:
                it = chain(it, [txin.tx_id for txin in tx.inputs])

        return it

    def add_neighbors(self, tx: 'BaseTransaction') -> None:
        """ Add neighbors of `tx` to be visited later according to the configuration.
        """
        it = self._get_iterator(tx, is_left_to_right=self.is_left_to_right)
        for _hash in it:
            if _hash not in self.seen:
                self.seen.add(_hash)
                neighbor = self.storage.get_vertex(_hash)
                self._push_visit(neighbor)

    def skip_neighbors(self, tx: 'BaseTransaction') -> None:
        """ Mark `tx` to have its neighbors skipped, i.e., they will not be added to be
        visited later. `tx` must be equal to the current yielded transaction.
        """
        self._ignore_neighbors = tx

    def run(self, root: Union['BaseTransaction', Iterable['BaseTransaction']], *,
            skip_root: bool = False) -> Iterator['BaseTransaction']:
        """ Run the walk.

        XXX: when using multiple roots the behavior of skip_root=True is undefined. We don't have a need for any
        particular behavior when one of the roots is a parent/child of another (still visit it, or skip it).

        :param skip_root: Indicate whether we should include the `root` or not in the walk
        """

        roots = root if isinstance(root, Iterable) else [root]

        for root in roots:
            self.seen.add(root.hash)
            if not skip_root:
                self._push_visit(root)
            else:
                self.add_neighbors(root)

        while not self._is_empty():
            tx = self._pop_visit()
            yield tx
            if not self._ignore_neighbors:
                self.add_neighbors(tx)
            else:
                assert self._ignore_neighbors == tx
                self._ignore_neighbors = None


class BFSTimestampWalk(GenericWalk):
    """ A help to walk in the DAG using a BFS that prioritizes by timestamp.
    """
    _to_visit: list[HeapItem]

    def __init__(
        self,
        storage: VertexStorageProtocol,
        *,
        is_dag_funds: bool = False,
        is_dag_verifications: bool = False,
        is_left_to_right: bool = True,
    ) -> None:
        super().__init__(
            storage,
            is_dag_funds=is_dag_funds,
            is_dag_verifications=is_dag_verifications,
            is_left_to_right=is_left_to_right
        )
        self._to_visit = []

    def _is_empty(self) -> bool:
        return not self._to_visit

    def _push_visit(self, tx: 'BaseTransaction') -> None:
        heapq.heappush(self._to_visit, HeapItem(tx, reverse=self._reverse_heap))

    def _pop_visit(self) -> 'BaseTransaction':
        item = heapq.heappop(self._to_visit)
        tx = item.tx
        # We can safely remove it because we are walking in topological order
        # and it won't appear again in the future because this would be a cycle.
        self.seen.remove(tx.hash)
        return tx


class BFSOrderWalk(GenericWalk):
    """ A help to walk in the DAG using a BFS.
    """
    _to_visit: deque['BaseTransaction']

    def __init__(
        self,
        storage: VertexStorageProtocol,
        *,
        is_dag_funds: bool = False,
        is_dag_verifications: bool = False,
        is_left_to_right: bool = True,
    ) -> None:
        super().__init__(
            storage,
            is_dag_funds=is_dag_funds,
            is_dag_verifications=is_dag_verifications,
            is_left_to_right=is_left_to_right
        )
        self._to_visit = deque()

    def _is_empty(self) -> bool:
        return not self._to_visit

    def _push_visit(self, tx: 'BaseTransaction') -> None:
        self._to_visit.append(tx)

    def _pop_visit(self) -> 'BaseTransaction':
        return self._to_visit.popleft()


class DFSWalk(GenericWalk):
    """ A help to walk in the DAG using a DFS.
    """
    _to_visit: list['BaseTransaction']

    def __init__(
        self,
        storage: VertexStorageProtocol,
        *,
        is_dag_funds: bool = False,
        is_dag_verifications: bool = False,
        is_left_to_right: bool = True,
    ) -> None:
        super().__init__(
            storage,
            is_dag_funds=is_dag_funds,
            is_dag_verifications=is_dag_verifications,
            is_left_to_right=is_left_to_right
        )
        self._to_visit = []

    def _is_empty(self) -> bool:
        return not self._to_visit

    def _push_visit(self, tx: 'BaseTransaction') -> None:
        self._to_visit.append(tx)

    def _pop_visit(self) -> 'BaseTransaction':
        return self._to_visit.pop()
