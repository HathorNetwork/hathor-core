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

# XXX: avoid using `from __future__ import annotations` here because `make_dataclass_nc_type` doesn't support it

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import TypeVar

from hathor.conf.settings import HATHOR_TOKEN_UID
from hathor.nanocontracts.nc_types import BytesNCType, NCType
from hathor.nanocontracts.nc_types.dataclass_nc_type import make_dataclass_nc_type
from hathor.nanocontracts.storage.maybedeleted_nc_type import MaybeDeletedNCType
from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
from hathor.nanocontracts.storage.restricted_block_proxy import RestrictedBlockProxy
from hathor.nanocontracts.storage.types import _NOT_PROVIDED, DeletedKey, DeletedKeyType
from hathor.nanocontracts.types import Address, Amount, BlueprintId, TokenUid, VertexId
from hathor.serialization import Deserializer, Serializer
from hathor.transaction.token_info import TokenDescription, TokenVersion

T = TypeVar('T')
D = TypeVar('D')

_BYTES_NC_TYPE: NCType[bytes] = BytesNCType()


class _Tag(Enum):
    ATTR = b'\0'
    BALANCE = b'\1'
    METADATA = b'\2'


class TrieKey(ABC):
    @abstractmethod
    def __bytes__(self) -> bytes:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class AttrKey(TrieKey):
    nc_id: bytes
    key: bytes

    def __bytes__(self) -> bytes:
        return _Tag.ATTR.value + hashlib.sha256(self.key).digest()


@dataclass(frozen=True, slots=True)
class BalanceKey(TrieKey):
    nc_id: bytes
    token_uid: bytes

    def __bytes__(self) -> bytes:
        return _Tag.BALANCE.value + self.token_uid


@dataclass(slots=True, frozen=True, kw_only=True)
class Balance:
    """
    The balance of a token in the storage, which includes its value (amount of tokens), and the
    stored authorities. This class is immutable and therefore suitable to be used externally.
    """
    value: int
    can_mint: bool
    can_melt: bool

    def to_mutable(self) -> 'MutableBalance':
        return MutableBalance(
            value=self.value,
            can_mint=self.can_mint,
            can_melt=self.can_melt,
        )


@dataclass(slots=True, kw_only=True)
class MutableBalance:
    """
    The balance of a token in the storage, which includes its value (amount of tokens),
    and the stored authorities. This is a mutable version of the `Balance` class and
    therefore only suitable to be used in NCContractStorage and its subclasses.
    """
    value: int
    can_mint: bool
    can_melt: bool

    def grant_authorities(self, *, grant_mint: bool, grant_melt: bool) -> None:
        """Grant authorities to this balance, returning a new updated one."""
        self.can_mint = self.can_mint or grant_mint
        self.can_melt = self.can_melt or grant_melt

    def revoke_authorities(self, *, revoke_mint: bool, revoke_melt: bool) -> None:
        """Revoke authorities from this balance, returning a new updated one."""
        self.can_mint = self.can_mint and not revoke_mint
        self.can_melt = self.can_melt and not revoke_melt

    @staticmethod
    def get_default() -> 'MutableBalance':
        """Get the default empty balance."""
        return MutableBalance(value=0, can_mint=False, can_melt=False)

    def to_immutable(self) -> Balance:
        return Balance(
            value=self.value,
            can_mint=self.can_mint,
            can_melt=self.can_melt,
        )


_BALANCE_NC_TYPE: NCType[MutableBalance] = make_dataclass_nc_type(MutableBalance)


@dataclass(frozen=True, slots=True)
class MetadataKey(TrieKey):
    nc_id: bytes
    key: bytes

    def __bytes__(self) -> bytes:
        return _Tag.METADATA.value + hashlib.sha256(self.key).digest()


_BLUEPRINT_ID_KEY = b'blueprint_id'


class NCContractStorage:
    """This is the storage used by NanoContracts.

    This implementation works for both memory and rocksdb backends."""

    def __init__(self, *, trie: PatriciaTrie, nc_id: VertexId, block_proxy: RestrictedBlockProxy) -> None:
        # State (balances, metadata and attributes)
        self._trie: PatriciaTrie = trie

        # Nano contract id
        self.nc_id = nc_id

        # Flag to check whether any change or commit can be executed.
        self.is_locked = False

        self._block_proxy = block_proxy

    def has_token(self, token_id: TokenUid) -> bool:
        """Return True if token_id exists in the current block."""
        return self._block_proxy.has_token(token_id)

    def get_token(self, token_id: TokenUid) -> TokenDescription:
        """Get token description for a given token ID."""
        return self._block_proxy.get_token(token_id)

    def create_token(
        self,
        *,
        token_id: TokenUid,
        token_name: str,
        token_symbol: str,
        token_version: TokenVersion
    ) -> None:
        """Create a new token in the current block."""
        self._block_proxy.create_token(
            token_id=token_id,
            token_name=token_name,
            token_symbol=token_symbol,
            token_version=token_version
        )

    def add_address_balance(self, address: Address, amount: Amount, token_id: TokenUid) -> None:
        self._block_proxy.add_address_balance(address, amount, token_id)

    def lock(self) -> None:
        """Lock the storage for changes or commits."""
        self.is_locked = True

    def unlock(self) -> None:
        """Unlock the storage."""
        self.is_locked = False

    def check_if_locked(self) -> None:
        """Raise a runtime error if the wallet is locked."""
        if self.is_locked:
            raise RuntimeError('you cannot modify or commit if the storage is locked')

    def _serialize(self, obj: T | DeletedKeyType, nc_type: NCType[T] | None) -> bytes:
        """Serialize a obj to be stored on the trie."""
        serializer = Serializer.build_bytes_serializer()
        if nc_type is None:
            assert obj is DeletedKey, 'nc_type=None must only be used when obj=DeletedKey'
        assert not isinstance(nc_type, MaybeDeletedNCType), 'nested MaybeDeletedNCType'
        MaybeDeletedNCType(nc_type).serialize(serializer, obj)
        return bytes(serializer.finalize())

    def _deserialize(self, content: bytes, nc_type: NCType[T]) -> T | DeletedKeyType:
        """Deserialize a obj stored on the trie."""
        deserializer = Deserializer.build_bytes_deserializer(content)
        assert not isinstance(nc_type, MaybeDeletedNCType), 'nested MaybeDeletedNCType'
        obj = MaybeDeletedNCType(nc_type).deserialize(deserializer)
        if isinstance(obj, DeletedKeyType):
            return DeletedKey
        return obj

    def _trie_has_key(self, trie_key: TrieKey) -> bool:
        """Returns True if trie-key exists and is not deleted."""
        try:
            value_bytes = self._trie.get(bytes(trie_key))
        except KeyError:
            return False
        if MaybeDeletedNCType.is_deleted_key(value_bytes):
            return False
        return True

    def _trie_get_obj(self, trie_key: TrieKey, nc_type: NCType[T], *, default: D = _NOT_PROVIDED) -> T | D:
        """Internal method that gets the object stored at a given trie-key."""
        obj: T | DeletedKeyType
        key_bytes = bytes(trie_key)
        try:
            content = self._trie.get(key_bytes)
        except KeyError:
            obj = DeletedKey
        else:
            # XXX: extra variable used so mypy can infer the correct type
            obj_t = self._deserialize(content, nc_type)
            obj = obj_t
        if obj is DeletedKey:
            if default is _NOT_PROVIDED:
                raise KeyError(f'trie_key={key_bytes!r}')
            return default
        assert not isinstance(obj, DeletedKeyType)
        return obj

    def _trie_update(self, trie_key: TrieKey, nc_type: NCType[T] | None, obj: T | DeletedKeyType) -> None:
        """Internal method that updates the object stored at a given trie-key

        For convenience `nc_type=None` is accepted when `obj=DeletedKey`, since it doesn't affect the serialization, so
        knowing the actual NCType isn't needed.
        """
        content = self._serialize(obj, nc_type)
        self._trie.update(bytes(trie_key), content)

    def _to_attr_key(self, key: bytes) -> AttrKey:
        """Return the actual key used in the storage."""
        assert isinstance(key, bytes)
        return AttrKey(self.nc_id, key)

    def get_obj(self, key: bytes, nc_type: NCType[T], *, default: D = _NOT_PROVIDED) -> T | D:
        """Return the object stored at the given `key`, deserialized with the given NCType.

        XXX: using a different NCType to deserialize than was used to serialize can result in successful
        deserialization and cause silent errors.

        It raises KeyError if key is not found and a default is not provided.
        """
        obj_key = self._to_attr_key(key)
        try:
            obj = self._trie_get_obj(obj_key, nc_type, default=default)
        except KeyError as e:
            raise KeyError(f'key={key!r} key_bytes={bytes(obj_key)!r}') from e
        return obj

    def put_obj(self, key: bytes, nc_type: NCType[T], obj: T) -> None:
        """Store the `object` for the provided `key` serialized with the given NCType.
        """
        self.check_if_locked()
        obj_key = self._to_attr_key(key)
        self._trie_update(obj_key, nc_type, obj)

    def del_obj(self, key: bytes) -> None:
        """Delete `key` from storage.
        """
        self.check_if_locked()
        obj_key = self._to_attr_key(key)
        self._trie_update(obj_key, None, DeletedKey)

    def has_obj(self, key: bytes) -> bool:
        """whether an object with the given `key` exists in the storage, also False if the object was deleted."""
        obj_key = self._to_attr_key(key)
        return self._trie_has_key(obj_key)

    def _get_metadata(self, key: bytes) -> bytes:
        """Return the metadata stored at the given key."""
        metadata_key = MetadataKey(self.nc_id, key)
        return self._trie_get_obj(metadata_key, _BYTES_NC_TYPE)

    def _put_metadata(self, key: bytes, metadata_bytes: bytes) -> None:
        """Store a new metadata at the given key."""
        metadata_key = MetadataKey(self.nc_id, key)
        self._trie_update(metadata_key, _BYTES_NC_TYPE, metadata_bytes)

    def get_blueprint_id(self) -> BlueprintId:
        """Return the blueprint id of the contract."""
        return BlueprintId(VertexId(self._get_metadata(_BLUEPRINT_ID_KEY)))

    def set_blueprint_id(self, blueprint_id: BlueprintId, /) -> None:
        """Set a new blueprint id for the contract."""
        self.check_if_locked()
        return self._put_metadata(_BLUEPRINT_ID_KEY, blueprint_id)

    def get_balance(self, token_uid: bytes) -> Balance:
        """Return the contract balance for a token."""
        return self._get_mutable_balance(token_uid).to_immutable()

    def _get_mutable_balance(self, token_uid: bytes) -> MutableBalance:
        """Return the mutable balance for a token. For internal use only."""
        balance_key = BalanceKey(self.nc_id, TokenUid(token_uid))
        balance = self._trie_get_obj(balance_key, _BALANCE_NC_TYPE, default=MutableBalance.get_default())
        assert isinstance(balance, MutableBalance)
        return balance

    def get_all_balances(self) -> dict[BalanceKey, Balance]:
        """Return the contract balances of all tokens."""
        balances: dict[BalanceKey, Balance] = {}
        balance_tag = self._trie._encode_key(_Tag.BALANCE.value)

        node = self._trie._find_nearest_node(balance_tag)
        if node.key.startswith(balance_tag):
            balance_root = node
        else:
            for prefix, child_id in node.children.items():
                child = self._trie.get_node(child_id)
                if child.key.startswith(balance_tag):
                    balance_root = child
                    break
            else:
                # No balance found.
                return balances

        for node, _, is_leaf in self._trie.iter_dfs(node=balance_root):
            if node.content is None:
                # Skip all nodes with no content.
                continue
            # Found a token.
            assert node.content is not None
            balance = self._deserialize(node.content, _BALANCE_NC_TYPE)
            assert isinstance(balance, MutableBalance)
            token_uid = TokenUid(self._trie._decode_key(node.key)[1:])
            key = BalanceKey(self.nc_id, token_uid)
            balances[key] = balance.to_immutable()
        return balances

    def add_balance(self, token_uid: bytes, amount: int) -> None:
        """Change the contract balance value for a token. The amount will be added to the previous balance value.

        Note that the provided `amount` might be negative, but not the result."""
        self.check_if_locked()
        balance_key = BalanceKey(self.nc_id, TokenUid(token_uid))
        balance = self._trie_get_obj(balance_key, _BALANCE_NC_TYPE, default=MutableBalance.get_default())
        assert isinstance(balance, MutableBalance)
        balance.value += amount
        assert balance.value >= 0, f'balance cannot be negative: {balance.value}'
        self._trie_update(balance_key, _BALANCE_NC_TYPE, balance)

    def grant_authorities(self, token_uid: bytes, *, grant_mint: bool, grant_melt: bool) -> None:
        """Grant authorities to the contract for a token."""
        assert token_uid != HATHOR_TOKEN_UID
        self.check_if_locked()
        balance_key = BalanceKey(self.nc_id, TokenUid(token_uid))
        balance = self._trie_get_obj(balance_key, _BALANCE_NC_TYPE, default=MutableBalance.get_default())
        assert isinstance(balance, MutableBalance)
        balance.grant_authorities(grant_mint=grant_mint, grant_melt=grant_melt)
        self._trie_update(balance_key, _BALANCE_NC_TYPE, balance)

    def revoke_authorities(self, token_uid: bytes, *, revoke_mint: bool, revoke_melt: bool) -> None:
        """Revoke authorities from the contract for a token."""
        assert token_uid != HATHOR_TOKEN_UID
        self.check_if_locked()
        balance_key = BalanceKey(self.nc_id, TokenUid(token_uid))
        balance = self._trie_get_obj(balance_key, _BALANCE_NC_TYPE, default=MutableBalance.get_default())
        assert isinstance(balance, MutableBalance)
        balance.revoke_authorities(revoke_mint=revoke_mint, revoke_melt=revoke_melt)
        self._trie_update(balance_key, _BALANCE_NC_TYPE, balance)

    def commit(self) -> None:
        """Flush all local changes to the storage."""
        self.check_if_locked()
        self._trie.commit()

    def get_root_id(self) -> bytes:
        """Return the current merkle root id of the trie."""
        return self._trie.root.id
