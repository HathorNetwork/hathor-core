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

from collections.abc import Container as ContainerAbc, Hashable, Iterator, Mapping
from typing import Generic, TypeVar, get_args, get_origin, overload

from typing_extensions import Self, override

from hathor.nanocontracts.blueprint_env import NCAttrCache
from hathor.nanocontracts.fields.container import KEY_SEPARATOR, Container, ContainerNode, ContainerNodeFactory
from hathor.nanocontracts.fields.field import Field
from hathor.nanocontracts.nc_types import NCType, VarUint32NCType
from hathor.nanocontracts.nc_types.utils import is_origin_hashable
from hathor.nanocontracts.storage import NCContractStorage
from hathor.util import not_none

K = TypeVar('K', bound=Hashable)
V = TypeVar('V')
_T = TypeVar('_T')
_LENGTH_KEY: bytes = b'__length__'
_LENGTH_NC_TYPE = VarUint32NCType()


class DictContainer(Container[K], Generic[K, V]):
    """ This is a dict-like object.

    Based on the implementation of UserDict, see:
    - https://github.com/python/cpython/blob/main/Lib/collections/__init__.py
    """

    __slots__ = ('__storage__', '__prefix__', '__key', '__value_node', '__length_key')
    __key: NCType[K]
    __value_node: ContainerNode[V]
    __length_key: bytes

    def __init__(self, storage: NCContractStorage, prefix: bytes, key: NCType[K], value: ContainerNode[V]) -> None:
        self.__storage__ = storage
        self.__prefix__ = prefix
        self.__key = key
        self.__value_node = value
        self.__length_key = KEY_SEPARATOR.join([self.__prefix__, _LENGTH_KEY])

    # Methods needed by Container:

    @override
    @classmethod
    def __check_type__(cls, type_: type[ContainerAbc[K]], type_map: Field.TypeMap) -> None:
        origin_type: type[ContainerAbc[K]] = not_none(get_origin(type_))
        if not issubclass(origin_type, Mapping):
            raise TypeError('expected Mapping type')
        args = get_args(type_)
        if not args or len(args) != 2:
            raise TypeError('expected exactly 2 type arguments')
        key_type, value_type = args
        if not is_origin_hashable(key_type):
            raise TypeError(f'{key_type} is not hashable')
        NCType.check_type(key_type, type_map=type_map.to_nc_type_map())
        _ = ContainerNodeFactory.check_is_container(value_type, type_map)

    @override
    @classmethod
    def __from_prefix_and_type__(
        cls,
        storage: NCContractStorage,
        prefix: bytes,
        type_: type[ContainerAbc[K]],
        /,
        *,
        cache: NCAttrCache,
        type_map: Field.TypeMap,
    ) -> Self:
        key_type, value_type = get_args(type_)
        key_nc_type = NCType.from_type(key_type, type_map=type_map.to_nc_type_map())
        assert key_nc_type.is_hashable(), 'hashable "types" must produce hashable "values"'
        value_node = ContainerNode.from_type(storage, value_type, cache=cache, type_map=type_map)
        return cls(storage, prefix, key_nc_type, value_node)

    @override
    def __init_storage__(self, initial_value: ContainerAbc[K] | None = None) -> None:
        self.__storage__.put_obj(self.__length_key, _LENGTH_NC_TYPE, 0)
        if initial_value is not None:
            if not isinstance(initial_value, Mapping):
                raise TypeError('expected initial_value to be a Mapping')
            self.update(initial_value)

    # INTERNAL METHODS: all of these must be __dunder_methods so they aren't accessible from an OCB

    def __to_db_key(self, key: K) -> bytes:
        # We don't need to explicitly hash the key here, because the trie already does it internally.
        return KEY_SEPARATOR.join([self.__prefix__, self.__key.to_bytes(key)])

    def __get_length(self) -> int:
        return self.__storage__.get_obj(self.__length_key, _LENGTH_NC_TYPE)

    def __increase_length(self) -> None:
        self.__storage__.put_obj(self.__length_key, _LENGTH_NC_TYPE, self.__get_length() + 1)

    def __decrease_length(self) -> None:
        length = self.__get_length()
        assert length > 0
        self.__storage__.put_obj(self.__length_key, _LENGTH_NC_TYPE, length - 1)

    # Methods needed by MutableMapping (and to behave like a dict)

    def __len__(self) -> int:
        return self.__get_length()

    def __getitem__(self, key: K, /) -> V:
        # get the data from the storage
        db_key = self.__to_db_key(key)
        try:
            return self.__value_node.get_value(db_key)
        except (KeyError, ValueError):
            raise KeyError(key)

    def __setitem__(self, key: K, value: V, /) -> None:
        db_key = self.__to_db_key(key)
        if key not in self:
            self.__increase_length()
        # store `value` at `key` in the storage
        self.__value_node.set_value(db_key, value)

    def __delitem__(self, key: K, /) -> None:
        db_key = self.__to_db_key(key)
        if key not in self:
            return
        try:
            # delete the key from the storage
            self.__value_node.del_value(db_key)
        except KeyError:
            raise KeyError(key)
        else:
            self.__decrease_length()

    def __eq__(self, value: object, /) -> bool:
        if isinstance(value, dict):
            if len(value) != len(self):
                return False
            for k in value.keys():
                if k not in self:
                    return False
                if self[k] != value[k]:
                    return False
            return True
        elif isinstance(value, DictContainer):
            # XXX: only return True if they point to the same data
            if self.__prefix__ == value.__prefix__:
                return True
            else:
                raise ValueError('cannot compare dict-containers that point to different data')
        else:
            raise TypeError(f'cannot compare with value of type {type(value)}')

    def __iter__(self) -> Iterator[K]:
        raise NotImplementedError

    def update(self, other=(), /, **kwds):
        # builtin docstring:
        # D.update([E, ]**F) -> None.  Update D from dict/iterable E and F.
        # If E is present and has a .keys() method, then does:  for k in E: D[k] = E[k]
        # If E is present and lacks a .keys() method, then does:  for k, v in E: D[k] = v
        # In either case, this is followed by: for k in F:  D[k] = F[k]

        if hasattr(other, 'keys'):
            for k in other.keys():
                self[k] = other[k]
        else:
            for k, v in other:
                self[k] = v
        for k, v in kwds.items():
            self[k] = v

    # Methods provided by MutableMapping (currently not implemented):

    # def pop(self, key, default=__marker):
    # def popitem(self):
    # def clear(self):
    # def setdefault(self, key, default=None):

    # Modify __contains__ and get() to work like dict does when __missing__ is present.

    def __contains__(self, key: K, /) -> bool:
        db_key = self.__to_db_key(key)
        has_key = self.__value_node.has_value(db_key)
        return has_key

    @overload
    def get(self, key: K, /) -> V:
        ...

    @overload
    def get(self, key: K, default: V | _T | None, /) -> V | _T | None:
        ...

    def get(self, key: K, default: V | _T | None = None, /) -> V | _T | None:
        # return the value for key if key is in the storage, else default
        if key in self:
            return self[key]
        # XXX: default is a special case because we have to return that the container-node would return if the key
        #      existed and it was queried with the given key, the slight difference in behavior is that in case we are
        #      returning a nested container (that is a ContainerProxy) the nested container will be added to the
        #      storage (throug self), before being returned, so that writes to the nested container will be written
        #      to the storage (and a later assignment to the key would not be necessary, but also not wrong)
        if self.__value_node.is_leaf:
            return default
        db_key = self.__to_db_key(key)
        self.__increase_length()
        self.__value_node.set_value(db_key, default)  # type: ignore[arg-type]
        return self.__value_node.get_value(db_key)

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
