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

from typing import TYPE_CHECKING, Any, Type

from hathor.nanocontracts.fields import Field
from hathor.nanocontracts.types import Address, Amount, Timestamp, TokenUid, TxOutputScript, VertexId

if TYPE_CHECKING:
    from hathor.nanocontracts.blueprint import Blueprint


class DictField(Field):
    """This is the field for Python's `dict` type.

    Note that this field is not the dict itself. A dict-like object will be returned
    when one tries to access the dict.
    """
    VALID_KEY_TYPES = set([str,
                           bytes,
                           int,
                           tuple,
                           Address,
                           Amount,
                           Timestamp,
                           TokenUid,
                           TxOutputScript,
                           VertexId])

    def __init__(self, name: str, key_field: Field, value_field: Field) -> None:
        self.name = name
        self.key_field = key_field
        self.value_field = value_field

    @classmethod
    def create_from_type(cls, name: str, _type: Type[Any]) -> Field:
        from hathor.nanocontracts.fields import get_field_for_attr

        args = _type.__args__
        # TODO The correct criteria is that the key must be serializable.
        args0_origin = getattr(args[0], '__origin__', args[0])
        if args0_origin not in cls.VALID_KEY_TYPES:
            raise TypeError(f'{name}: invalid key type {args[0]} {args0_origin}')
        key_field = get_field_for_attr('', args[0])
        value_field = get_field_for_attr('', args[1])
        return cls(name, key_field, value_field)

    def __set__(self, blueprint, value):
        """Forbid attribution of a new object as a replacement of this dict."""
        raise Exception('cannot set a dict')

    def __get__(self, blueprint, objtype):
        """Return the StorageDict object for the given blueprint."""
        if self.name in blueprint._cache:
            return blueprint._cache[self.name]

        storage_dict = StorageDict(blueprint, self.name, self.key_field, self.value_field)
        blueprint._cache[self.name] = storage_dict
        return storage_dict

    def isinstance(cls, value: Any) -> bool:
        raise RuntimeError

    def to_bytes(self, value: Any) -> bytes:
        raise RuntimeError

    def to_python(self, raw: bytes) -> Any:
        raise RuntimeError


class StorageDict:
    """This is a dict-like object."""
    def __init__(self, blueprint: 'Blueprint', name: str, key_field: Field, value_field: Field) -> None:
        self.blueprint = blueprint
        self.name = name
        self._separator = ':'
        self.key_field = key_field
        self.value_field = value_field

    def _to_db_key(self, key):
        return f'{self.name}{self._separator}{key}'

    def __setitem__(self, key, item):
        """Store `item` at `key` in the storage."""
        db_key = self._to_db_key(key)
        self.blueprint._storage.put(db_key, item)

    def __getitem__(self, key):
        """Get the data from the storage."""
        db_key = self._to_db_key(key)
        return self.blueprint._storage.get(db_key)

    def __delitem__(self, key):
        """Delete the key from the storage."""
        db_key = self._to_db_key(key)
        self.blueprint._storage.delete(db_key)

    def __contains__(self, key):
        """Return true if the `key` exists."""
        try:
            self[key]
        except KeyError:
            return False
        else:
            return True

    def get(self, key, default=None):
        """Return the value for key if key is in the storage, else default."""
        try:
            return self[key]
        except KeyError:
            return default
