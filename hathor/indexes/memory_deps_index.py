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

from typing import TYPE_CHECKING, Iterator, Optional

from structlog import get_logger

from hathor.indexes.deps_index import DepsIndex, get_requested_from_height
from hathor.transaction import BaseTransaction
from hathor.util import not_none

if TYPE_CHECKING:  # pragma: no cover
    from hathor.transaction.storage import TransactionStorage

logger = get_logger()


class MemoryDepsIndex(DepsIndex):
    # Reverse dependency mapping
    _rev_dep_index: dict[bytes, set[bytes]]

    # Ready to be validated cache
    _txs_with_deps_ready: set[bytes]

    # Next to be downloaded
    _needed_txs_index: dict[bytes, tuple[int, bytes]]

    def __init__(self):
        self.log = logger.new()
        self.force_clear()

    def get_db_name(self) -> Optional[str]:
        return None

    def force_clear(self) -> None:
        self._rev_dep_index = {}
        self._txs_with_deps_ready = set()
        self._needed_txs_index = {}

    def add_tx(self, tx: BaseTransaction, partial: bool = True) -> None:
        assert tx.hash is not None
        assert tx.storage is not None
        validation = tx.get_metadata().validation
        if validation.is_fully_connected():
            self._del_from_deps_index(tx)
        elif not partial:
            raise ValueError('partial=False will only accept fully connected transactions')
        else:
            self._add_deps(tx)
            self._add_needed(tx)

    def del_tx(self, tx: BaseTransaction) -> None:
        self._del_from_deps_index(tx)

    def _add_deps(self, tx: BaseTransaction) -> None:
        """This method is idempotent, because self.update needs it to be indempotent."""
        assert tx.hash is not None
        for dep in tx.get_all_dependencies():
            if dep not in self._rev_dep_index:
                self._rev_dep_index[dep] = set()
            self._rev_dep_index[dep].add(tx.hash)

    def _del_from_deps_index(self, tx: BaseTransaction) -> None:
        """This method is idempotent, because self.update needs it to be indempotent."""
        assert tx.hash is not None
        for dep in tx.get_all_dependencies():
            if dep not in self._rev_dep_index:
                continue
            rev_deps = self._rev_dep_index[dep]
            if tx.hash in rev_deps:
                rev_deps.remove(tx.hash)
            if not rev_deps:
                del self._rev_dep_index[dep]

    def remove_ready_for_validation(self, tx: bytes) -> None:
        """ Removes from ready for validation set.
        """
        self._txs_with_deps_ready.discard(tx)

    def next_ready_for_validation(self, tx_storage: 'TransactionStorage', *, dry_run: bool = False) -> Iterator[bytes]:
        if dry_run:
            cur_ready = self._txs_with_deps_ready.copy()
        else:
            cur_ready, self._txs_with_deps_ready = self._txs_with_deps_ready, set()
        while cur_ready:
            yield from sorted(cur_ready, key=lambda tx_hash: tx_storage.get_transaction(tx_hash).timestamp)
            if dry_run:
                cur_ready = self._txs_with_deps_ready - cur_ready
            else:
                cur_ready, self._txs_with_deps_ready = self._txs_with_deps_ready, set()

    def iter(self) -> Iterator[bytes]:
        yield from self._rev_dep_index.keys()

    def _iter_needed_txs(self) -> Iterator[bytes]:
        yield from self._needed_txs_index.keys()

    def _get_rev_deps(self, tx: bytes) -> frozenset[bytes]:
        """Get all txs that depend on the given tx (i.e. its reverse depdendencies)."""
        return frozenset(self._rev_dep_index.get(tx, set()))

    def known_children(self, tx: BaseTransaction) -> list[bytes]:
        assert tx.hash is not None
        assert tx.storage is not None
        it_rev_deps = map(tx.storage.get_transaction, self._get_rev_deps(tx.hash))
        return [not_none(rev.hash) for rev in it_rev_deps if tx.hash in rev.parents]

    # needed-txs-index methods:

    def has_needed_tx(self) -> bool:
        return bool(self._needed_txs_index)

    def is_tx_needed(self, tx: bytes) -> bool:
        return tx in self._needed_txs_index

    def remove_from_needed_index(self, tx: bytes) -> None:
        self._needed_txs_index.pop(tx, None)

    def get_next_needed_tx(self) -> bytes:
        # This strategy maximizes the chance to download multiple txs on the same stream
        # find the tx with highest "height"
        # XXX: we could cache this onto `needed_txs` so we don't have to fetch txs every time
        # TODO: improve this by using some sorted data structure to make this better than O(n)
        height, start_hash, tx = max((h, s, t) for t, (h, s) in self._needed_txs_index.items())
        self.log.debug('next needed tx start', needed=len(self._needed_txs_index), start=start_hash.hex(),
                       height=height, needed_tx=tx.hex())
        return start_hash

    def _add_needed(self, tx: BaseTransaction) -> None:
        """This method is idempotent, because self.update needs it to be indempotent."""
        assert tx.storage is not None
        tx_storage = tx.storage

        height = get_requested_from_height(tx)
        self.log.debug('add needed deps', tx=tx.hash_hex, height=height, type=type(tx).__name__)
        # get_all_dependencies is needed to ensure that we get the inputs that aren't reachable through parents alone,
        # this can happen for inputs that have not been confirmed as of the block the confirms the block or transaction
        # that we're adding the dependencies of
        for tx_hash in tx.get_all_dependencies():
            # It may happen that we have one of the dependencies already, so just add the ones we don't
            # have. We should add at least one dependency, otherwise this tx should be full validated
            if not tx_storage.transaction_exists(tx_hash):
                self.log.debug('tx parent is needed', tx=tx_hash.hex())
                self._needed_txs_index[tx_hash] = (height, not_none(tx.hash))
