
import heapq
from abc import ABC, abstractmethod
from itertools import chain
from typing import TYPE_CHECKING, Any, Iterator, List, Optional, Set

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction  # noqa: F401
    from hathor.transaction.storage import TransactionStorage  # noqa: F401


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
    seen: Set[bytes]
    to_visit: List[Any]

    def __init__(self, storage: 'TransactionStorage', *, is_dag_funds: bool = False,
                 is_dag_verifications: bool = False, is_left_to_right: bool = True):
        """
        If `is_left_to_right` is `True`, we walk in the direction of the unverified transactions.
        Otherwise, we walk in the direction of the genesis.

        :param is_dag_funds: Add neighbors from the DAG of funds
        :param is_dag_verifications: Add neighbors from the DAG of verifications
        :param is_left_to_right: Decide which side of the DAG we will walk to
        """
        self.storage = storage
        self.seen = set()
        self.to_visit = []

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

    def add_neighbors(self, tx: 'BaseTransaction') -> None:
        """ Add neighbors of `tx` to be visited later according to the configuration.
        """
        meta = None
        it: Iterator[bytes] = chain()

        if self.is_dag_verifications:
            if self.is_left_to_right:
                meta = meta or tx.get_metadata()
                it = chain(it, meta.children)
            else:
                it = chain(it, tx.parents)

        if self.is_dag_funds:
            if self.is_left_to_right:
                meta = meta or tx.get_metadata()
                it = chain(it, *meta.spent_outputs.values())
            else:
                it = chain(it, [txin.tx_id for txin in tx.inputs])

        for _hash in it:
            if _hash not in self.seen:
                self.seen.add(_hash)
                neighbor = self.storage.get_transaction(_hash)
                self._push_visit(neighbor)

    def skip_neighbors(self, tx: 'BaseTransaction') -> None:
        """ Mark `tx` to have its neighbors skipped, i.e., they will not be added to be
        visited later. `tx` must be equal to the current yielded transaction.
        """
        self._ignore_neighbors = tx

    def run(self, root: 'BaseTransaction', *, skip_root: bool = False) -> Iterator['BaseTransaction']:
        """ Run the walk.

        :param skip_root: Indicate whether we should include the `root` or not in the walk
        """
        assert root.hash is not None
        self.seen.add(root.hash)
        if not skip_root:
            self._push_visit(root)
        else:
            self.add_neighbors(root)

        while self.to_visit:
            tx = self._pop_visit()
            assert tx.hash is not None
            yield tx
            if not self._ignore_neighbors:
                self.add_neighbors(tx)
            else:
                assert self._ignore_neighbors == tx
                self._ignore_neighbors = None


class BFSWalk(GenericWalk):
    """ A help to walk in the DAG using a BFS.
    """
    to_visit: List[HeapItem]

    def _push_visit(self, tx: 'BaseTransaction') -> None:
        heapq.heappush(self.to_visit, HeapItem(tx, reverse=self._reverse_heap))

    def _pop_visit(self) -> 'BaseTransaction':
        item = heapq.heappop(self.to_visit)
        tx = item.tx
        # We can safely remove it because we are walking in topological order
        # and it won't appear again in the future because this would be a cycle.
        assert tx.hash is not None
        self.seen.remove(tx.hash)
        return tx


class DFSWalk(GenericWalk):
    """ A help to walk in the DAG using a DFS.
    """
    to_visit: List['BaseTransaction']

    def _push_visit(self, tx: 'BaseTransaction') -> None:
        self.to_visit.append(tx)

    def _pop_visit(self) -> 'BaseTransaction':
        return self.to_visit.pop()
