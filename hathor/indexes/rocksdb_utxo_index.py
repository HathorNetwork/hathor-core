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

import struct
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING, Any, Iterator, Optional

from structlog import get_logger

from hathor.conf.settings import HathorSettings
from hathor.crypto.util import decode_address, get_address_b58_from_bytes
from hathor.indexes.rocksdb_utils import InternalUid, RocksDBIndexUtils, from_internal_token_uid, to_internal_token_uid
from hathor.indexes.utxo_index import UtxoIndex, UtxoIndexItem

if TYPE_CHECKING:  # pragma: no cover
    import rocksdb

logger = get_logger()

_DB_NAME: str = 'utxos'
_CF_NAME_UTXO_INDEX = b'utxo-index'


class _Tag(Enum):
    INVALID = 0x00
    NOLOCK = 0x01
    TIMELOCK = 0x02
    HEIGHTLOCK = 0x03


@dataclass(frozen=True)
class _KeyBase:
    tag: _Tag = _Tag.INVALID

    def __post_init__(self) -> None:
        assert self.tag is not _Tag.INVALID

    def __bytes__(self) -> bytes:
        array = bytearray()
        self._bytes(array)
        return bytes(array)

    def _bytes(self, array: bytearray) -> None:
        array.append(self.tag.value)
        assert len(array) == 1


@dataclass(frozen=True)
class _SeekKeyBase(_KeyBase):
    token_uid_internal: InternalUid = InternalUid(b'')
    address: bytes = b''

    def __post_init__(self) -> None:
        super().__post_init__()
        assert len(self.token_uid_internal) == 32
        assert len(self.address) == 25

    def _bytes(self, array: bytearray) -> None:
        super()._bytes(array)
        array.extend(self.token_uid_internal)
        array.extend(self.address)
        assert len(array) == 1 + 32 + 25

    def as_prefix(self) -> '_SeekKeyBase':
        """This helper method will always create a _SeekKeyBase which is a useful prefix when using its subclasses.

        In practice this is useful for filtering out keys that aren't relevant to a given query. The _SeekKeyBase class
        maps to the following prefix:

            [tag][token_uid][address]
            |1b-||--32b----||--25b--|

        Which is what is used to filter out entries in all cases of the UTXO index.
        """
        return _SeekKeyBase(tag=self.tag, token_uid_internal=self.token_uid_internal, address=self.address)


@dataclass(frozen=True)
class _SeekKeyNoLock(_SeekKeyBase):
    tag: _Tag = _Tag.NOLOCK
    amount: int = -1

    def __post_init__(self) -> None:
        super().__post_init__()
        assert self.tag is _Tag.NOLOCK
        assert self.amount > 0

    def _bytes(self, array: bytearray) -> None:
        super()._bytes(array)
        array.extend(struct.pack('>Q', self.amount))
        assert len(array) == 1 + 32 + 25 + 8


@dataclass(frozen=True)
class _KeyNoLock(_SeekKeyNoLock):
    tx_id: bytes = b''
    index: int = -1

    def __post_init__(self) -> None:
        super().__post_init__()
        assert len(self.tx_id) == 32
        assert self.index >= 0

    def _bytes(self, array: bytearray) -> None:
        super()._bytes(array)
        array.extend(self.tx_id)
        array.append(self.index)
        assert len(array) == 1 + 32 + 25 + 8 + 32 + 1

    def to_index_item(self) -> UtxoIndexItem:
        return UtxoIndexItem(
            token_uid=from_internal_token_uid(self.token_uid_internal),
            tx_id=self.tx_id,
            index=self.index,
            address=get_address_b58_from_bytes(self.address),
            amount=self.amount,
            timelock=None,
            heightlock=None,
        )


@dataclass(frozen=True)
class _SeekKeyTimeLock(_SeekKeyBase):
    tag: _Tag = _Tag.TIMELOCK
    timelock: int = -1
    amount: int = -1

    def __post_init__(self) -> None:
        super().__post_init__()
        assert self.timelock >= 0
        assert self.amount > 0

    def _bytes(self, array: bytearray) -> None:
        super()._bytes(array)
        array.extend(struct.pack('>I', self.timelock))
        array.extend(struct.pack('>Q', self.amount))
        assert len(array) == 1 + 32 + 25 + 4 + 8


@dataclass(frozen=True)
class _KeyTimeLock(_SeekKeyTimeLock):
    tx_id: bytes = b''
    index: int = -1

    def __post_init__(self) -> None:
        super().__post_init__()
        assert len(self.tx_id) == 32
        assert self.index >= 0

    def _bytes(self, array: bytearray) -> None:
        super()._bytes(array)
        array.extend(self.tx_id)
        array.append(self.index)
        assert len(array) == 1 + 32 + 25 + 4 + 8 + 32 + 1

    def to_index_item(self) -> UtxoIndexItem:
        return UtxoIndexItem(
            token_uid=from_internal_token_uid(self.token_uid_internal),
            tx_id=self.tx_id,
            index=self.index,
            address=get_address_b58_from_bytes(self.address),
            amount=self.amount,
            timelock=self.timelock,
            heightlock=None,
        )


@dataclass(frozen=True)
class _SeekKeyHeightLock(_SeekKeyBase):
    tag: _Tag = _Tag.HEIGHTLOCK
    heightlock: int = -1
    amount: int = -1

    def __post_init__(self) -> None:
        super().__post_init__()
        assert self.tag is _Tag.HEIGHTLOCK
        assert self.heightlock >= 0
        assert self.amount > 0

    def _bytes(self, array: bytearray) -> None:
        super()._bytes(array)
        array.extend(struct.pack('>I', self.heightlock))
        array.extend(struct.pack('>Q', self.amount))
        assert len(array) == 1 + 32 + 25 + 4 + 8


@dataclass(frozen=True)
class _KeyHeightLock(_SeekKeyHeightLock):
    tx_id: bytes = b''
    index: int = -1

    def __post_init__(self) -> None:
        super().__post_init__()
        assert len(self.tx_id) == 32
        assert self.index >= 0

    def _bytes(self, array: bytearray) -> None:
        super()._bytes(array)
        array.extend(self.tx_id)
        array.append(self.index)
        assert len(array) == 1 + 32 + 25 + 4 + 8 + 32 + 1

    def to_index_item(self) -> UtxoIndexItem:
        return UtxoIndexItem(
            token_uid=from_internal_token_uid(self.token_uid_internal),
            tx_id=self.tx_id,
            index=self.index,
            address=get_address_b58_from_bytes(self.address),
            amount=self.amount,
            timelock=None,
            heightlock=self.heightlock,
        )


def _parse_key(key: bytes) -> _KeyBase:
    assert len(key) >= 1
    tag = _Tag(key[0])
    if tag is _Tag.INVALID:
        raise ValueError('invalid tag found')
    elif tag is _Tag.NOLOCK:
        assert len(key) == 1 + 32 + 25 + 8 + 32 + 1
        return _KeyNoLock(
            tag=tag,
            token_uid_internal=InternalUid(key[1:33]),
            address=key[33:58],
            amount=struct.unpack('>Q', key[58:66])[0],
            tx_id=key[66:98],
            index=key[98],
        )
    elif tag is _Tag.TIMELOCK:
        assert len(key) == 1 + 32 + 25 + 4 + 8 + 32 + 1
        return _KeyTimeLock(
            tag=tag,
            token_uid_internal=InternalUid(key[1:33]),
            address=key[33:58],
            timelock=struct.unpack('>I', key[58:62])[0],
            amount=struct.unpack('>Q', key[62:70])[0],
            tx_id=key[70:102],
            index=key[102],
        )
    elif tag is _Tag.HEIGHTLOCK:
        assert len(key) == 1 + 32 + 25 + 4 + 8 + 32 + 1
        return _KeyHeightLock(
            tag=tag,
            token_uid_internal=InternalUid(key[1:33]),
            address=key[33:58],
            heightlock=struct.unpack('>I', key[58:62])[0],
            amount=struct.unpack('>Q', key[62:70])[0],
            tx_id=key[70:102],
            index=key[102],
        )
    else:
        # XXX: if/elif is exhaustive for all possible tags and invalid tag value will fail sooner
        raise NotImplementedError('unreachable')


def _key_from_index_item(item: UtxoIndexItem) -> _KeyBase:
    if item.timelock is not None:
        return _KeyTimeLock(
            token_uid_internal=to_internal_token_uid(item.token_uid),
            address=decode_address(item.address),
            timelock=item.timelock,
            amount=item.amount,
            tx_id=item.tx_id,
            index=item.index,
        )
    elif item.heightlock is not None:
        return _KeyHeightLock(
            token_uid_internal=to_internal_token_uid(item.token_uid),
            address=decode_address(item.address),
            heightlock=item.heightlock,
            amount=item.amount,
            tx_id=item.tx_id,
            index=item.index,
        )
    else:
        return _KeyNoLock(
            token_uid_internal=to_internal_token_uid(item.token_uid),
            address=decode_address(item.address),
            amount=item.amount,
            tx_id=item.tx_id,
            index=item.index,
        )


class RocksDBUtxoIndex(UtxoIndex, RocksDBIndexUtils):
    """ Index of UTXO information by token_uid+address.

    This index uses the following key formats:

        key_nolock     = [tag][token_uid][address][amount][tx_id][index] tag=NOLOCK
                         |1b-||--32b----||--25b--||--8b--||-32b-||-1b--|

        key_timelock   = [tag][token_uid][address][timelock][amount][tx_id][index] tag=TIMELOCK
                         |1b-||--32b----||--25b--||--4b----||--8b--||-32b-||-1b--|

        key_heightlock = [tag][token_uid][address][heightlock][amount][tx_id][index] tag=HEIGHTLOCK
                         |1b-||--32b----||--25b--||--4b------||--8b--||-32b-||-1b--|

    It works nicely because rocksdb uses a tree sorted by key under the hood.
    """

    def __init__(self, db: 'rocksdb.DB', *, settings: HathorSettings, cf_name: Optional[bytes] = None) -> None:
        super().__init__(settings=settings)
        self.log = logger.new()
        RocksDBIndexUtils.__init__(self, db, cf_name or _CF_NAME_UTXO_INDEX)

    def get_db_name(self) -> Optional[str]:
        return _DB_NAME

    def force_clear(self) -> None:
        self.clear()

    def _add_utxo(self, item: UtxoIndexItem) -> None:
        key = bytes(_key_from_index_item(item))
        self._db.put((self._cf, key), b'')

    def _remove_utxo(self, item: UtxoIndexItem) -> None:
        key = bytes(_key_from_index_item(item))
        self._db.delete((self._cf, key))

    def _iter_utxos_nolock(self, *, token_uid: bytes, address: str, target_amount: int) -> Iterator[UtxoIndexItem]:
        seek = _SeekKeyNoLock(token_uid_internal=to_internal_token_uid(token_uid), address=decode_address(address),
                              amount=target_amount)
        for key in self._iter_keys(seek):
            assert isinstance(key, _KeyNoLock)
            assert key.token_uid_internal == seek.token_uid_internal
            assert key.address == seek.address
            yield key.to_index_item()

    def _iter_utxos_timelock(self, *, token_uid: bytes, address: str, target_amount: int,
                             target_timestamp: Optional[int] = None) -> Iterator[UtxoIndexItem]:
        seek = _SeekKeyTimeLock(token_uid_internal=to_internal_token_uid(token_uid), address=decode_address(address),
                                amount=target_amount, timelock=(target_timestamp or 0xffffffff))
        for key in self._iter_keys(seek):
            assert isinstance(key, _KeyTimeLock)
            assert key.token_uid_internal == seek.token_uid_internal
            assert key.address == seek.address
            i = key.to_index_item()
            # it might happen that the first one is out of the timelock range
            if i.timelock is not None and i.timelock > seek.timelock:
                continue
            yield i

    def _iter_utxos_heightlock(self, *, token_uid: bytes, address: str, target_amount: int,
                               target_height: Optional[int] = None) -> Iterator[UtxoIndexItem]:
        seek = _SeekKeyHeightLock(token_uid_internal=to_internal_token_uid(token_uid), address=decode_address(address),
                                  amount=target_amount, heightlock=(target_height or 0xffffffff))
        for key in self._iter_keys(seek):
            assert isinstance(key, _KeyHeightLock)
            assert key.token_uid_internal == seek.token_uid_internal
            assert key.address == seek.address
            i = key.to_index_item()
            # it might happen that the first one is out of the heightlock range
            if i.heightlock is not None and i.heightlock > seek.heightlock:
                continue
            yield i

    def _iter_keys(self, seek: _SeekKeyBase) -> Iterator[_KeyBase]:
        """ This helper method iterates in reverse order from the seek key as long as keys match the seek prefix.

        For example, if the complete database is (letter is prefix, number is the rest):

        - `A1`
        - `A2`
        - `B1`
        - `B2`
        - `B3`
        - `C1`
        - `C2`

        A seek of `B4` should yield `B3,B2,B1`. Internally when we seek to `B4` the first element is `C1` which we
        filter out and continue once, until the iterator reaches `A2` and we break.
        """
        prefix = bytes(seek.as_prefix())
        first = True
        for k in self._db_rev_iter_from_seek(bytes(seek)):
            if not k.startswith(prefix):
                # XXX: the seek might overshoot so we should still continue one time to see if we missed any keys
                if first:
                    first = False
                    continue
                else:
                    break
            key = _parse_key(k)
            yield key

    def _db_rev_iter_from_seek(self, seek: bytes) -> Iterator[bytes]:
        """ This helper method will seek to the given seek key and iterate in reverse order.

        It mainly deals with the case where the seek would end up after the last element which would stop the iterator
        even if it's on reverse order (which you would normally expect to iterate from the last element).

        For example, if the complete database is:

        - `A1`
        - `A2`
        - `B1`
        - `B2`
        - `B3`

        Creating a reversed iterator and doing a seek to `B4` would result in an "empty" iterator because it went past
        the last element.

        If in practice you want it to start from `B3` instead of being empty, this method provides this behavior by
        doing a `seek_to_last` when the first `next` raises a `StopIteration`. It also omits yielding the column_family
        for simplicity.

        Otherwise, given the following example:

        - `A1`
        - `A2`
        - `B1`
        - `B2`
        - `B3`
        - `C1`
        - `C2`

        When seeking to `B4`, the following would be yielded in this order: `C1,B3,B2,B1,A2,A1`, this method does not
        look at any prefix so it continues until it reaches the start of the database.
        """
        it: Any = reversed(self._db.iterkeys(self._cf))
        it.seek(bytes(seek))
        try:
            _cf, k = next(it)
            yield k
        except StopIteration:
            it.seek_to_last()
        for _cf, k in it:
            yield k
