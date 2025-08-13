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

from collections.abc import Hashable, Iterator, Mapping
from typing import TypeVar, get_args, get_origin, overload

from typing_extensions import Self, override

from hathor.nanocontracts.faux_immutable import __get_inner_shell_type__
from hathor.nanocontracts.fields.container_field import KEY_SEPARATOR, ContainerField, StorageContainer
from hathor.nanocontracts.fields.field import Field
from hathor.nanocontracts.nc_types import NCType, VarUint32NCType
from hathor.nanocontracts.nc_types.utils import is_origin_hashable
from hathor.nanocontracts.storage import NCContractStorage
from hathor.util import not_none

K = TypeVar('K', bound=Hashable)
V = TypeVar('V')
_T = TypeVar('_T')
_LENGTH_KEY: str = '__length__'
_LENGTH_NC_TYPE = VarUint32NCType()


class DictStorageContainer(StorageContainer[Mapping[K, V]]):
    """This is a dict-like object.

    Based on the implementation of UserDict, see:
    - https://github.com/python/cpython/blob/main/Lib/collections/__init__.py
    """

    __slots__ = ('__storage', '__name', '__key', '__value', '__length_key')
    __storage: NCContractStorage
    __name: str
    __key: NCType[K]
    __value: NCType[V]
    __length_key: bytes

    def __init__(self, storage: NCContractStorage, name: str, key: NCType[K], value: NCType[V]) -> None:
        self.__storage = storage
        self.__name = name
        self.__key = key
        self.__value = value
        self.__length_key = f'{name}{KEY_SEPARATOR}{_LENGTH_KEY}'.encode()

    # Methods needed by StorageContainer:

    @override
    @classmethod
    def __check_name_and_type__(cls, name: str, type_: type[Mapping[K, V]]) -> None:
        if not name.isidentifier():
            raise TypeError('field name must be a valid identifier')
        origin_type: type[Mapping[K, V]] = not_none(get_origin(type_))
        if not issubclass(origin_type, Mapping):
            raise TypeError('expected Mapping type')
        args = get_args(type_)
        if not args or len(args) != 2:
            raise TypeError(f'expected {type_.__name__}[<key type>, <value type>]')
        key_type, value_type = args
        actual_key_type = __get_inner_shell_type__(key_type)
        if not is_origin_hashable(actual_key_type):
            raise TypeError(f'{actual_key_type} is not hashable')

    @override
    @classmethod
    def __from_name_and_type__(
        cls,
        storage: NCContractStorage,
        name: str,
        type_: type[Mapping[K, V]],
        /,
        *,
        type_map: Field.TypeMap,
    ) -> Self:
        key_type, value_type = get_args(type_)
        key_nc_type = NCType.from_type(key_type, type_map=type_map.to_nc_type_map())
        assert key_nc_type.is_hashable(), 'hashable "types" must produce hashable "values"'
        value_nc_type = NCType.from_type(value_type, type_map=type_map.to_nc_type_map())
        return cls(storage, name, key_nc_type, value_nc_type)

    # INTERNAL METHODS: all of these must be __dunder_methods so they aren't accessible from an OCB

    def __to_db_key(self, key: K) -> bytes:
        # We don't need to explicitly hash the key here, because the trie already does it internally.
        return f'{self.__name}{KEY_SEPARATOR}'.encode() + self.__key.to_bytes(key)

    def __get_length(self) -> int:
        return self.__storage.get_obj(self.__length_key, _LENGTH_NC_TYPE, default=0)

    def __increase_length(self) -> None:
        self.__storage.put_obj(self.__length_key, _LENGTH_NC_TYPE, self.__get_length() + 1)

    def __decrease_length(self) -> None:
        length = self.__get_length()
        assert length > 0
        self.__storage.put_obj(self.__length_key, _LENGTH_NC_TYPE, length - 1)

    # Methods needed by MutableMapping (and to behave like a dict)

    def __len__(self) -> int:
        return self.__get_length()

    def __getitem__(self, key: K, /) -> V:
        # get the data from the storage
        db_key = self.__to_db_key(key)
        return self.__storage.get_obj(db_key, self.__value)

    def __setitem__(self, key: K, value: V, /) -> None:
        if key not in self:
            self.__increase_length()
        # store `value` at `key` in the storage
        self.__storage.put_obj(self.__to_db_key(key), self.__value, value)

    def __delitem__(self, key: K, /) -> None:
        if key not in self:
            return
        self.__decrease_length()
        # delete the key from the storage
        self.__storage.del_obj(self.__to_db_key(key))

    def __iter__(self) -> Iterator[K]:
        raise NotImplementedError

    # Methods provided by MutableMapping (currently not implemented):

    # def pop(self, key, default=__marker):
    # def popitem(self):
    # def clear(self):
    # def update(self, other=(), /, **kwds):
    # def setdefault(self, key, default=None):

    # Modify __contains__ and get() to work like dict does when __missing__ is present.

    def __contains__(self, key: K, /) -> bool:
        # return true if the `key` exists in the collection
        try:
            self[key]
        except KeyError:
            return False
        else:
            return True

    @overload
    def get(self, key: K, /) -> V:
        ...

    @overload
    def get(self, key: K, default: V | _T | None, /) -> V | _T | None:
        ...

    # XXX: `misc` is ignored because mypy thinks this function does not accept all arguments of the second get overload
    def get(self, key: K, default: V | _T | None = None, /) -> V | _T | None:  # type: ignore[misc]
        # return the value for key if key is in the storage, else default
        try:
            return self[key]
        except KeyError:
            return default

    # Now, add the methods in dicts but not in MutableMapping

    # def __repr__(self):
    #     raise NotImplementedError

    def __or__(self, value, /):
        raise NotImplementedError

    def __ror__(self, value, /):
        raise NotImplementedError

    def __ior__(self, value, /):
        raise NotImplementedError

    def __copy__(self):
        raise NotImplementedError

    def copy(self):
        raise NotImplementedError

    @classmethod
    def fromkeys(cls, iterable, value=None, /):
        raise NotImplementedError


DictField = ContainerField[DictStorageContainer[K, V]]
