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
from typing import TYPE_CHECKING, Iterator, NamedTuple, Optional, TypedDict, cast

from structlog import get_logger

from hathor.conf.settings import HathorSettings
from hathor.indexes.rocksdb_utils import (
    InternalUid,
    RocksDBIndexUtils,
    from_internal_token_uid,
    incr_key,
    to_internal_token_uid,
)
from hathor.indexes.tokens_index import TokenIndexInfo, TokensIndex, TokenUtxoInfo
from hathor.transaction import BaseTransaction, Transaction
from hathor.transaction.base_transaction import TxVersion
from hathor.util import collect_n, json_dumpb, json_loadb

if TYPE_CHECKING:  # pragma: no cover
    import rocksdb

logger = get_logger()

_CF_NAME_TOKENS_INDEX = b'tokens-index'
_DB_NAME: str = 'tokens'


class _Tag(Enum):
    INFO = 0x01
    MINT = 0x02
    MELT = 0x03
    TXS = 0x04


@dataclass
class _KeyAny:
    token_uid_internal: InternalUid
    tag: _Tag
    timestamp: Optional[int] = None
    tx_hash: Optional[bytes] = None
    index: Optional[int] = None


class _InfoDict(TypedDict):
    name: str
    symbol: str
    total: int


class _TxIndex(NamedTuple):
    tx_hash: bytes
    timestamp: int


class RocksDBTokensIndex(TokensIndex, RocksDBIndexUtils):
    """ Index of token information by token_uid.

    This index uses the following key formats:

        key_info      = [tag][token_uid] (tag=0x01)
                        |1b-||--32b----|

        key_authority = [tag][token_uid][tx.hash][output.index] (tag=0x02 for mint, 0x03 for melt)
                        |1b-||--32b----||--32b--||--1 byte----|

        key_txs       = [tag][token_uid][tx.timestamp][tx.hash] (tag=0x04)
                        |1b-||--32b----||--4 bytes---||--32b--|

    It works nicely because rocksdb uses a tree sorted by key under the hood.
    """

    def __init__(self, db: 'rocksdb.DB', *, settings: HathorSettings, cf_name: Optional[bytes] = None) -> None:
        self.log = logger.new()
        TokensIndex.__init__(self, settings=settings)
        RocksDBIndexUtils.__init__(self, db, cf_name or _CF_NAME_TOKENS_INDEX)

    def get_db_name(self) -> Optional[str]:
        # XXX: we don't need it to be parametrizable, so this is fine
        return _DB_NAME

    def force_clear(self) -> None:
        self.clear()

    def _to_key_info(self, token_uid: bytes) -> bytes:
        """Make a key for accessing a token's info"""
        token_uid_internal = to_internal_token_uid(token_uid)
        key = bytearray()
        key.append(_Tag.INFO.value)
        key.extend(token_uid_internal)
        assert len(key) == 32 + 1
        return bytes(key)

    def _to_key_txs(self, token_uid: bytes, tx: Optional[_TxIndex]) -> bytes:
        """Make a key for a token's transactions, if `tx` is given, the key represents the membership itself."""
        import struct
        token_uid_internal = to_internal_token_uid(token_uid)
        key = bytearray()
        key.append(_Tag.TXS.value)
        key.extend(token_uid_internal)
        if tx is None:
            assert len(key) == 32 + 1
            return bytes(key)
        assert len(tx.tx_hash) == 32
        key.extend(struct.pack('>I', tx.timestamp))
        key.extend(tx.tx_hash)
        assert len(key) == 32 + 1 + 4 + 32
        return bytes(key)

    def _to_key_authority(self, token_uid: bytes, utxo: Optional[TokenUtxoInfo] = None, *, is_mint: bool) -> bytes:
        """Make a key for a token's mint/melt txs, if `utxo` is given, the key represents the membership itself."""
        token_uid_internal = to_internal_token_uid(token_uid)
        key = bytearray()
        key.append(_Tag.MINT.value if is_mint else _Tag.MELT.value)
        key.extend(token_uid_internal)
        if utxo is None:
            assert len(key) == 32 + 1
            return bytes(key)
        assert len(utxo.tx_hash) == 32
        key.extend(utxo.tx_hash)
        key.append(utxo.output_index)
        assert len(key) == 32 + 1 + 32 + 1
        return bytes(key)

    def _from_key_any(self, key: bytes) -> _KeyAny:
        """Parse any key on the column-family, the returned object has a tag that determines the key type."""
        import struct
        assert len(key) >= 1
        tag = _Tag(key[0])
        token_uid = InternalUid(key[1:33])
        assert len(token_uid) == 32
        if tag is _Tag.INFO:
            assert len(key) == 32 + 1
            return _KeyAny(token_uid, tag)
        elif tag is _Tag.TXS:
            assert len(key) == 32 + 1 + 4 + 32
            timestamp: int
            (timestamp,) = struct.unpack('>I', key[33:37])
            tx_hash = key[37:]
            assert len(tx_hash) == 32
            return _KeyAny(token_uid, tag, timestamp=timestamp, tx_hash=tx_hash)
        elif tag in {_Tag.MINT, _Tag.MELT}:
            assert len(key) == 32 + 1 + 32 + 1
            tx_hash = key[33:65]
            index = key[65]
            return _KeyAny(token_uid, tag, tx_hash=tx_hash, index=index)
        else:
            # XXX: if/elif is exhaustive for all possible tags and invalid tag value will fail sooner
            raise NotImplementedError('unreachable')

    def _to_value_info(self, info: _InfoDict) -> bytes:
        return json_dumpb(info)

    def _from_value_info(self, value: bytes) -> _InfoDict:
        return cast(_InfoDict, json_loadb(value))

    def _create_token_info(self, token_uid: bytes, name: str, symbol: str, total: int = 0) -> None:
        key = self._to_key_info(token_uid)
        old_value = self._db.get((self._cf, key))
        assert old_value is None
        value = self._to_value_info({
            'name': name,
            'symbol': symbol,
            'total': total,
        })
        self._db.put((self._cf, key), value)

    def _destroy_token(self, token_uid: bytes) -> None:
        import rocksdb

        # a writebatch works similar to a "SQL transaction" in that if it fails, either all persist or none
        key_info = self._to_key_info(token_uid)
        key_mint = self._to_key_authority(token_uid, is_mint=True)
        key_melt = self._to_key_authority(token_uid, is_mint=False)
        key_txs = self._to_key_txs(token_uid, None)
        batch = rocksdb.WriteBatch()
        batch.delete((self._cf, key_info))
        it = self._db.iterkeys(self._cf)
        # XXX: all of these should have already been deleted at this point, but just to make sure
        for seek_key in [key_mint, key_melt, key_txs]:
            it.seek(seek_key)
            for _, key in it:
                if not key.startswith(seek_key):
                    break
                self.log.warn('should have already been deleted', db_key=key.hex())
                batch.delete((self._cf, key))
        self._db.write(batch)

    def _add_transaction(self, token_uid: bytes, timestamp: int, tx_hash: bytes) -> None:
        self.log.debug('add transaction', token=token_uid.hex(), tx=tx_hash.hex(), timestamp=timestamp)
        self._db.put((self._cf, self._to_key_txs(token_uid, _TxIndex(tx_hash, timestamp))), b'')

    def _remove_transaction(self, token_uid: bytes, timestamp: int, tx_hash: bytes) -> None:
        self.log.debug('remove transaction', token=token_uid.hex(), tx=tx_hash.hex(), timestamp=timestamp)
        self._db.delete((self._cf, self._to_key_txs(token_uid, _TxIndex(tx_hash, timestamp))))

    def _add_authority_utxo(self, token_uid: bytes, tx_hash: bytes, index: int, *, is_mint: bool) -> None:
        self.log.debug('add authority utxo', token=token_uid.hex(), tx=tx_hash.hex(), index=index, is_mint=is_mint)
        self._db.put((self._cf, self._to_key_authority(token_uid, TokenUtxoInfo(tx_hash, index), is_mint=is_mint)),
                     b'')

    def _remove_authority_utxo(self, token_uid: bytes, tx_hash: bytes, index: int, *, is_mint: bool) -> None:
        self.log.debug('remove authority utxo', token=token_uid.hex(), tx=tx_hash.hex(), index=index, is_mint=is_mint)
        self._db.delete((self._cf, self._to_key_authority(token_uid, TokenUtxoInfo(tx_hash, index), is_mint=is_mint)))

    def _create_genesis_info(self) -> None:
        self._create_token_info(
            self._settings.HATHOR_TOKEN_UID,
            self._settings.HATHOR_TOKEN_NAME,
            self._settings.HATHOR_TOKEN_SYMBOL,
            self._settings.GENESIS_TOKENS,
        )

    def _add_to_total(self, token_uid: bytes, amount: int) -> None:
        key_info = self._to_key_info(token_uid)
        old_value_info = self._db.get((self._cf, key_info))
        if token_uid == self._settings.HATHOR_TOKEN_UID and old_value_info is None:
            self._create_genesis_info()
            old_value_info = self._db.get((self._cf, key_info))
        assert old_value_info is not None
        dict_info = self._from_value_info(old_value_info)
        dict_info['total'] += amount
        new_value_info = self._to_value_info(dict_info)
        self._db.put((self._cf, key_info), new_value_info)

    def _subtract_from_total(self, token_uid: bytes, amount: int) -> None:
        key_info = self._to_key_info(token_uid)
        old_value_info = self._db.get((self._cf, key_info))
        if token_uid == self._settings.HATHOR_TOKEN_UID and old_value_info is None:
            self._create_genesis_info()
            old_value_info = self._db.get((self._cf, key_info))
        assert old_value_info is not None
        dict_info = self._from_value_info(old_value_info)
        dict_info['total'] -= amount
        new_value_info = self._to_value_info(dict_info)
        self._db.put((self._cf, key_info), new_value_info)

    def _add_utxo(self, tx: BaseTransaction, index: int) -> None:
        """ Add tx to mint/melt indexes and total amount
        """
        tx_output = tx.outputs[index]
        token_uid = tx.get_token_uid(tx_output.get_token_index())

        if tx_output.is_token_authority():
            if tx_output.can_mint_token():
                # add to mint index
                self._add_authority_utxo(token_uid, tx.hash, index, is_mint=True)
            if tx_output.can_melt_token():
                # add to melt index
                self._add_authority_utxo(token_uid, tx.hash, index, is_mint=False)
        else:
            self._add_to_total(token_uid, tx_output.value)

    def _remove_utxo(self, tx: BaseTransaction, index: int) -> None:
        """ Remove tx from mint/melt indexes and total amount
        """

        tx_output = tx.outputs[index]
        token_uid = tx.get_token_uid(tx_output.get_token_index())

        if tx_output.is_token_authority():
            if tx_output.can_mint_token():
                # remove from mint index
                self._remove_authority_utxo(token_uid, tx.hash, index, is_mint=True)
            if tx_output.can_melt_token():
                # remove from melt index
                self._remove_authority_utxo(token_uid, tx.hash, index, is_mint=False)
        else:
            self._subtract_from_total(token_uid, tx_output.value)

    def add_tx(self, tx: BaseTransaction) -> None:
        # if it's a TokenCreationTransaction, update name and symbol
        self.log.debug('add_tx', tx=tx.hash_hex, ver=tx.version)
        if tx.version == TxVersion.TOKEN_CREATION_TRANSACTION:
            from hathor.transaction.token_creation_tx import TokenCreationTransaction
            tx = cast(TokenCreationTransaction, tx)
            self.log.debug('create_token_info', tx=tx.hash_hex, name=tx.token_name, symb=tx.token_symbol)
            key_info = self._to_key_info(tx.hash)
            token_info = self._db.get((self._cf, key_info))
            if token_info is None:
                self._create_token_info(tx.hash, tx.token_name, tx.token_symbol)

        if tx.is_transaction:
            # Adding this tx to the transactions key list
            assert isinstance(tx, Transaction)
            for token_uid in tx.tokens:
                self._add_transaction(token_uid, tx.timestamp, tx.hash)

        for tx_input in tx.inputs:
            spent_tx = tx.get_spent_tx(tx_input)
            self._remove_utxo(spent_tx, tx_input.index)

        for index in range(len(tx.outputs)):
            self.log.debug('add utxo', tx=tx.hash_hex, index=index)
            self._add_utxo(tx, index)

    def remove_tx(self, tx: BaseTransaction) -> None:
        for tx_input in tx.inputs:
            spent_tx = tx.get_spent_tx(tx_input)
            self._add_utxo(spent_tx, tx_input.index)

        for index in range(len(tx.outputs)):
            self._remove_utxo(tx, index)

        if tx.is_transaction:
            # Removing this tx from the transactions key list
            assert isinstance(tx, Transaction)
            for token_uid in tx.tokens:
                self._remove_transaction(token_uid, tx.timestamp, tx.hash)

        # if it's a TokenCreationTransaction, remove it from index
        if tx.version == TxVersion.TOKEN_CREATION_TRANSACTION:
            self._destroy_token(tx.hash)

    def iter_all_tokens(self) -> Iterator[tuple[bytes, TokenIndexInfo]]:
        self.log.debug('seek to start')
        it = self._db.iteritems(self._cf)
        it.seek(bytes([_Tag.INFO.value]))
        for (_cf, key), value in it:
            key_any = self._from_key_any(key)
            if key_any.tag is not _Tag.INFO:
                break
            self.log.debug('seek found', token=key_any.token_uid_internal.hex())
            info = self._from_value_info(value)
            token_uid = from_internal_token_uid(key_any.token_uid_internal)
            token_index_info = RocksDBTokenIndexInfo(self, token_uid, info)
            yield token_uid, token_index_info
        self.log.debug('seek end')

    def get_token_info(self, token_uid: bytes) -> TokenIndexInfo:
        key_info = self._to_key_info(token_uid)
        value = self._db.get((self._cf, key_info))
        if value is None:
            raise KeyError('unknown token')
        info = self._from_value_info(value)
        return RocksDBTokenIndexInfo(self, token_uid, info)

    def _iter_transactions(self, token_uid: bytes, from_tx: Optional[_TxIndex] = None,
                           *, reverse: bool = False) -> Iterator[bytes]:
        """ Iterate over all transactions of a token, by default from oldest to newest.
        """
        it = self._db.iterkeys(self._cf)
        seek_key = self._to_key_txs(token_uid, from_tx)
        self.log.debug('seek to', token_uid=token_uid.hex(), key=seek_key.hex())
        if reverse:
            it = reversed(it)
            # when reversed we increment the key by 1, which effectively goes to the end of a prefix
            it.seek_for_prev(incr_key(seek_key))
        else:
            it.seek(seek_key)
        first = True
        for _, key in it:
            key_any = self._from_key_any(key)
            this_token_uid = from_internal_token_uid(key_any.token_uid_internal)
            if key_any.tag is not _Tag.TXS or this_token_uid != token_uid:
                break
            tx_hash = key_any.tx_hash
            assert tx_hash is not None
            self.log.debug('seek found', tx=tx_hash.hex())
            # XXX: this is made such that we wouldn't skip the first element blindly, only if it is the given from_tx
            if first:
                first = False
                # from_tx transaction is never yielded
                if from_tx is not None and from_tx.tx_hash == tx_hash:
                    continue
            yield tx_hash
        self.log.debug('seek end')

    def get_transactions_count(self, token_uid: bytes) -> int:
        # TODO: maybe it's possible to optimize this with rocksdb prefix stuff
        return sum(1 for _ in self._iter_transactions(token_uid))

    def get_newest_transactions(self, token_uid: bytes, count: int) -> tuple[list[bytes], bool]:
        it = self._iter_transactions(token_uid, reverse=True)
        return collect_n(it, count)

    def get_older_transactions(self, token_uid: bytes, timestamp: int, hash_bytes: bytes, count: int
                               ) -> tuple[list[bytes], bool]:
        it = self._iter_transactions(token_uid, _TxIndex(hash_bytes, timestamp), reverse=True)
        return collect_n(it, count)

    def get_newer_transactions(self, token_uid: bytes, timestamp: int, hash_bytes: bytes, count: int
                               ) -> tuple[list[bytes], bool]:
        it = self._iter_transactions(token_uid, _TxIndex(hash_bytes, timestamp))
        return collect_n(it, count)


class RocksDBTokenIndexInfo(TokenIndexInfo):
    """Used to access a token's information and to iterate over it's mint/melt utxos"""

    _index: RocksDBTokensIndex
    _token_uid: bytes

    def __init__(self, index: RocksDBTokensIndex, token_uid: bytes, info: _InfoDict) -> None:
        """Should not be instantiated outside of this module, token_uid is already with the public format."""
        self._index = index
        self._token_uid = token_uid
        self._info = info

    def get_name(self) -> Optional[str]:
        return self._info['name']

    def get_symbol(self) -> Optional[str]:
        return self._info['symbol']

    def get_total(self) -> int:
        return self._info['total']

    def _iter_authority_utxos(self, *, is_mint: bool) -> Iterator[TokenUtxoInfo]:
        it = self._index._db.iterkeys(self._index._cf)
        seek_key = self._index._to_key_authority(self._token_uid, is_mint=is_mint)
        tag = _Tag.MINT if is_mint else _Tag.MELT
        it.seek(seek_key)
        for _, key in it:
            key_any = self._index._from_key_any(key)
            token_uid = from_internal_token_uid(key_any.token_uid_internal)
            if key_any.tag is not tag or token_uid != self._token_uid:
                break
            assert key_any.tx_hash is not None
            assert key_any.index is not None
            yield TokenUtxoInfo(key_any.tx_hash, key_any.index)

    def iter_mint_utxos(self) -> Iterator[TokenUtxoInfo]:
        return self._iter_authority_utxos(is_mint=True)

    def iter_melt_utxos(self) -> Iterator[TokenUtxoInfo]:
        return self._iter_authority_utxos(is_mint=False)
