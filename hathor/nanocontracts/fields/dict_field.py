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

from typing import Any

from typing_extensions import Self, override

from hathor.nanocontracts.fields import Field
from hathor.nanocontracts.fields.container_field import KEY_SEPARATOR, ContainerField, StorageContainer
from hathor.nanocontracts.types import (
    Address,
    Amount,
    BlueprintId,
    ContractId,
    Timestamp,
    TokenUid,
    TxOutputScript,
    VertexId,
)


class DictField(ContainerField['StorageDict']):
    """This is the field for Python's `dict` type.

    Note that this field is not the dict itself. A dict-like object will be returned
    when one tries to access the dict.
    """
    __slots__ = ()

    VALID_KEY_TYPES = {
        str,
        bytes,
        int,
        tuple,
        Address,
        Amount,
        BlueprintId,
        ContractId,
        Timestamp,
        TokenUid,
        TxOutputScript,
        VertexId,
    }

    @classmethod
    @override
    def create_from_name(cls, name: str, value_field: Field) -> Self:
        return cls(name, value_field, StorageDict)

    @classmethod
    @override
    def _validate_type_args(cls, name: str, args: list[Any]) -> Field:
        from hathor.nanocontracts.fields import get_field_for_attr
        if len(args) != 2:
            raise TypeError(f'dict field `{name}` should have exactly two type arguments')
        # TODO The correct criteria is that the key must be serializable.
        args0_origin = getattr(args[0], '__origin__', args[0])
        if args0_origin not in cls.VALID_KEY_TYPES:
            raise TypeError(f'{name}: invalid key type {args[0]} {args0_origin}')
        # check that key and value types are valid
        _ = get_field_for_attr('', args[0])
        value_field = get_field_for_attr('', args[1])
        return value_field


class StorageDict(StorageContainer):
    """This is a dict-like object."""

    __slots__ = ()

    def _to_db_key(self, key):
        return f'{self.__field_name__}{KEY_SEPARATOR}{key}'

    def __setitem__(self, key, item):
        """Store `item` at `key` in the storage."""
        db_key = self._to_db_key(key)
        self.__storage__.put(db_key, item)

    def __getitem__(self, key):
        """Get the data from the storage."""
        db_key = self._to_db_key(key)
        return self.__storage__.get(db_key)

    def __delitem__(self, key):
        """Delete the key from the storage."""
        db_key = self._to_db_key(key)
        self.__storage__.delete(db_key)

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
