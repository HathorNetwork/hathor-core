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

from dataclasses import dataclass
from enum import Enum
from functools import partial
from typing import TYPE_CHECKING, FrozenSet, Iterator, List, Optional, Tuple

from structlog import get_logger

from hathor.indexes.deps_index import DepsIndex, get_requested_from_height
from hathor.indexes.rocksdb_utils import RocksDBIndexUtils, incr_key
from hathor.transaction import BaseTransaction
from hathor.util import not_none

if TYPE_CHECKING:
    import rocksdb

    from hathor.transaction.storage import TransactionStorage

logger = get_logger()

_CF_NAME_DEPS_INDEX = b'deps-index'
_DB_NAME: str = 'deps'


class _Tag(Enum):
    READY = 0x01
    REVERSE = 0x02
    NEEDED = 0x03


@dataclass
class _KeyAny:
    tag: _Tag
    tx_hash: Optional[bytes]
    tx_dep_hash: Optional[bytes]


class RocksDBDepsIndex(DepsIndex, RocksDBIndexUtils):
    """ Index of dependencies between transactions

    Terms:

    - ready:   [tx], many tx, all of which are ready to be validated because their dependencies are fully-valid
    - reverse: tx_dep -> [tx], tx_dep is needed by many tx, in order for them to be validated
    - needed:  [tx_dep], many tx_dep, all of which need to be downloaded (we store which tx asked for a tx_dep)

    This index uses the following key-value formats:

        key_ready   = [tag=01][tx.hash]               value=''
                      |--1b--||--32b--|

        key_reverse = [tag=02][tx_dep.hash][tx.hash]  value=''
                      |--1b--||--32b------||--32b--|

        key_needed  = [tag=03][tx_dep.hash]           value=[height][tx.hash]
                      |--1b--||--32b------|                 |--4b--||--32b--|

    It works nicely because rocksdb uses a tree sorted by key under the hood.
    """

    def __init__(self, db: 'rocksdb.DB', *, cf_name: Optional[bytes] = None, _force: bool = False) -> None:
        if not _force:
            # See: https://github.com/HathorNetwork/hathor-core/issues/412
            raise TypeError('This class should not be used')
        self.log = logger.new()
        RocksDBIndexUtils.__init__(self, db, cf_name or _CF_NAME_DEPS_INDEX)

    def get_db_name(self) -> Optional[str]:
        # XXX: we don't need it to be parametrizable, so this is fine
        return _DB_NAME

    def force_clear(self) -> None:
        self.clear()

    def _to_key_ready(self, tx_hash: Optional[bytes] = None) -> bytes:
        """Make a key for accessing READY txs 'set'"""
        key = bytearray()
        key.append(_Tag.READY.value)
        if tx_hash is None:
            assert len(key) == 1
            return bytes(key)
        key.extend(tx_hash)
        assert len(key) == 1 + 32
        return bytes(key)

    def _to_key_reverse(self, tx_dep_hash: Optional[bytes] = None, tx_hash: Optional[bytes] = None) -> bytes:
        """Make a key for accessing REVERSE dependencies 'dict'"""
        key = bytearray()
        key.append(_Tag.REVERSE.value)
        if tx_dep_hash is None:
            assert tx_hash is None
            assert len(key) == 1
            return bytes(key)
        key.extend(tx_dep_hash)
        if tx_hash is None:
            assert len(key) == 1 + 32
            return bytes(key)
        key.extend(tx_hash)
        assert len(key) == 1 + 32 + 32
        return bytes(key)

    def _to_key_needed(self, tx_dep_hash: Optional[bytes] = None) -> bytes:
        """Make a key for accessing NEEDED txs 'dict'"""
        key = bytearray()
        key.append(_Tag.NEEDED.value)
        if tx_dep_hash is None:
            assert len(key) == 1
            return bytes(key)
        key.extend(tx_dep_hash)
        assert len(key) == 1 + 32
        return bytes(key)

    def _from_key_any(self, key: bytes) -> _KeyAny:
        """Parse any key on the column-family, the returned object has a tag that determines the key type."""
        assert len(key) >= 1
        tag = _Tag(key[0])
        if tag is _Tag.READY:
            assert len(key) == 1 + 32
            tx_hash = key[1:]
            assert len(tx_hash) == 32
            return _KeyAny(tag, tx_hash, None)
        elif tag is _Tag.REVERSE:
            assert len(key) == 1 + 32 + 32
            tx_dep_hash = key[1:33]
            tx_hash = key[33:]
            assert len(tx_hash) == len(tx_dep_hash) == 32
            return _KeyAny(tag, tx_hash, tx_dep_hash)
        elif tag is _Tag.NEEDED:
            assert len(key) == 1 + 32
            tx_dep_hash = key[1:]
            assert len(tx_dep_hash) == 32
            return _KeyAny(tag, None, tx_dep_hash)
        else:
            # XXX: if/elif is exhaustive for all possible tags and invalid tag value will fail sooner
            raise NotImplementedError('unreachable')

    def _to_value_needed(self, height: int, tx_hash: bytes) -> bytes:
        import struct
        value = bytearray()
        value.extend(struct.pack('!I', height))
        value.extend(tx_hash)
        assert len(value) == 4 + 32
        return bytes(value)

    def _from_value_needed(self, value: bytes) -> Tuple[int, bytes]:
        import struct
        assert len(value) == 4 + 32
        height, = struct.unpack('!I', value[:4])
        tx_hash = value[4:]
        return height, tx_hash

    def _iter_rev_deps_of(self, tx_dep_hash: bytes) -> Iterator[bytes]:
        it = self._db.iterkeys(self._cf)
        seek_key = self._to_key_reverse(tx_dep_hash)
        self.log.debug('seek to start', seek_key=seek_key.hex())
        it.seek(seek_key)
        for _, key in it:
            key_any = self._from_key_any(key)
            if key_any.tag is not _Tag.REVERSE:
                break
            if key_any.tx_dep_hash != tx_dep_hash:
                break
            tx_hash = key_any.tx_hash
            assert tx_hash is not None
            self.log.debug('seek found', tx=tx_hash.hex())
            yield tx_hash
        self.log.debug('seek end')

    def _del_from_deps(self, tx: BaseTransaction, batch: 'rocksdb.WriteBatch') -> None:
        assert tx.hash is not None
        for tx_dep_hash in tx.get_all_dependencies():
            batch.delete((self._cf, self._to_key_reverse(tx_dep_hash, tx.hash)))

    def _add_ready(self, tx_hash: bytes, batch: 'rocksdb.WriteBatch') -> None:
        key = self._to_key_ready(tx_hash)
        batch.put((self._cf, key), b'')

    def add_tx(self, tx: BaseTransaction, partial: bool = True) -> None:
        import rocksdb
        assert tx.hash is not None
        assert tx.storage is not None
        batch = rocksdb.WriteBatch()
        validation = tx.get_metadata().validation
        if validation.is_fully_connected():
            # discover if new txs are ready because of this tx
            self._update_new_deps_ready(tx, batch)
            # finally remove from rev deps
            self._del_from_deps(tx, batch)
        elif not partial:
            raise ValueError('partial=False will only accept fully connected transactions')
        else:
            self._add_deps(tx, batch)
            self._add_needed(tx, batch)
        self._db.write(batch)

    def del_tx(self, tx: BaseTransaction) -> None:
        import rocksdb
        batch = rocksdb.WriteBatch()
        self._del_from_deps(tx, batch)
        self._db.write(batch)

    def _update_new_deps_ready(self, tx: BaseTransaction, batch: 'rocksdb.WriteBatch') -> None:
        """Go over the reverse dependencies of tx and check if any of them are now ready to be validated.

        This is also idempotent.
        """
        assert tx.hash is not None
        assert tx.storage is not None
        for candidate_hash in self._iter_rev_deps_of(tx.hash):
            candidate_tx = tx.storage.get_transaction(candidate_hash, allow_partially_valid=True)
            if candidate_tx.is_ready_for_validation():
                self._add_ready(candidate_hash, batch)

    def _add_deps(self, tx: BaseTransaction, batch: 'rocksdb.WriteBatch') -> None:
        assert tx.hash is not None
        for dep in tx.get_all_dependencies():
            batch.put((self._cf, self._to_key_reverse(dep, tx.hash)), b'')

    def _add_needed(self, tx: BaseTransaction, batch: 'rocksdb.WriteBatch') -> None:
        assert tx.hash is not None
        assert tx.storage is not None
        tx_storage = tx.storage

        height = get_requested_from_height(tx)
        self.log.debug('add needed deps', tx=tx.hash_hex, height=height, type=type(tx).__name__)
        # get_all_dependencies is needed to ensure that we get the inputs that aren't reachable through parents alone,
        # this can happen for inputs that have not been confirmed as of the block the confirms the block or transaction
        # that we're adding the dependencies of
        for tx_dep_hash in tx.get_all_dependencies():
            # It may happen that we have one of the dependencies already, so just add the ones we don't have. We should
            # add at least one dependency, otherwise this tx should be full validated
            if not tx_storage.transaction_exists(tx_dep_hash):
                self.log.debug('tx parent is needed', tx=tx.hash.hex(), tx_dep=tx_dep_hash.hex())
                batch.put((self._cf, self._to_key_needed(tx_dep_hash)), self._to_value_needed(height, tx.hash))

        # also, remove the given transaction from needed, because we already have it
        batch.delete((self._cf, self._to_key_needed(tx.hash)))

    def remove_ready_for_validation(self, tx: bytes) -> None:
        self._db.delete((self._cf, self._to_key_ready(tx)))

    def next_ready_for_validation(self, tx_storage: 'TransactionStorage', *, dry_run: bool = False) -> Iterator[bytes]:
        import rocksdb
        batch = rocksdb.WriteBatch()
        ready = self._drain_all_sorted_ready(tx_storage, batch)
        if not dry_run:
            self._db.write(batch)
        while ready:
            yield from ready
            batch = rocksdb.WriteBatch()
            ready = self._drain_all_sorted_ready(tx_storage, batch)
            if not dry_run:
                self._db.write(batch)

    def _drain_all_sorted_ready(self, tx_storage: 'TransactionStorage', batch: 'rocksdb.WriteBatch') -> List[bytes]:
        ready = list(self._drain_all_ready(tx_storage, batch))
        ready.sort(key=lambda tx_hash: tx_storage.get_transaction(tx_hash, allow_partially_valid=True).timestamp)
        return ready

    def _drain_all_ready(self, tx_storage: 'TransactionStorage', batch: 'rocksdb.WriteBatch') -> Iterator[bytes]:
        it = self._db.iterkeys(self._cf)
        seek_key = self._to_key_ready()
        self.log.debug('seek to start', seek_key=seek_key.hex())
        it.seek(seek_key)
        for _, key in it:
            key_any = self._from_key_any(key)
            if key_any.tag is not _Tag.READY:
                break
            tx_hash = key_any.tx_hash
            assert tx_hash is not None
            self.log.debug('seek found', tx=tx_hash.hex())
            batch.delete((self._cf, key))
            yield tx_hash
        self.log.debug('seek end')

    def iter(self) -> Iterator[bytes]:
        yield from self._iter_has_rev_deps()

    def _iter_needed_txs(self) -> Iterator[bytes]:
        yield from (tx for tx, _, __ in self._iter_needed())

    def _iter_has_rev_deps(self) -> Iterator[bytes]:
        it = self._db.iterkeys(self._cf)
        seek_key = self._to_key_reverse()
        self.log.debug('seek to start', seek_key=seek_key.hex())
        it.seek(seek_key)
        for _, key in it:
            key_any = self._from_key_any(key)
            if key_any.tag is not _Tag.REVERSE:
                break
            tx_dep_hash = key_any.tx_dep_hash
            assert tx_dep_hash is not None
            self.log.debug('seek found', tx_dep=tx_dep_hash.hex())
            yield tx_dep_hash
            # XXX: do this seek to skip directly to the next tx_dep_hash, otherwise we would have to iterate until the
            #      found key has a different tx_dep_hash
            # XXX: also this assumes rocksdb skip will be faster than calling next repeatedly, an investigation should
            #      be made to confirm this
            seek_key = incr_key(self._to_key_reverse(tx_dep_hash))
            it.seek(seek_key)
        self.log.debug('seek end')

    def known_children(self, tx: BaseTransaction) -> List[bytes]:
        assert tx.hash is not None
        assert tx.storage is not None
        get_partially_validated = partial(tx.storage.get_transaction, allow_partially_valid=True)
        it_rev_deps = map(get_partially_validated, self._get_rev_deps(tx.hash))
        return [not_none(rev.hash) for rev in it_rev_deps if tx.hash in rev.parents]

    def _get_rev_deps(self, tx: bytes) -> FrozenSet[bytes]:
        """Get all txs that depend on the given tx (i.e. its reverse depdendencies)."""
        return frozenset(self._iter_rev_deps_of(tx))

    def has_needed_tx(self) -> bool:
        return any(self._iter_needed())

    def _iter_needed(self) -> Iterator[Tuple[bytes, int, bytes]]:
        """Iterate over needed txs items, which is a tuple of (tx_dep_hash, height, tx_requested_hash)"""
        it = self._db.iteritems(self._cf)
        seek_key = self._to_key_needed()
        self.log.debug('seek to start', seek_key=seek_key.hex())
        it.seek(seek_key)
        for (_, key), value in it:
            key_any = self._from_key_any(key)
            if key_any.tag is not _Tag.NEEDED:
                break
            tx_dep_hash = key_any.tx_dep_hash
            assert tx_dep_hash is not None
            height, tx_hash = self._from_value_needed(value)
            self.log.debug('seek found', tx_dep=tx_dep_hash.hex())
            yield tx_dep_hash, height, tx_hash
        self.log.debug('seek end')

    def is_tx_needed(self, tx: bytes) -> bool:
        key_needed = self._to_key_needed(tx)
        val = self._db.get((self._cf, key_needed))
        return val is not None

    def remove_from_needed_index(self, tx: bytes) -> None:
        key_needed = self._to_key_needed(tx)
        self._db.delete((self._cf, key_needed))

    def get_next_needed_tx(self) -> bytes:
        # This strategy maximizes the chance to download multiple txs on the same stream
        # Find the tx with highest "height"
        # XXX: we could cache this onto `needed_txs` so we don't have to fetch txs every time
        # TODO: improve this by using some sorted data structure to make this better than O(n)
        height, start_hash, tx = max((h, s, t) for t, h, s in self._iter_needed())
        self.log.debug('next needed tx start', start=start_hash.hex(), height=height, needed_tx=tx.hex())
        return start_hash
