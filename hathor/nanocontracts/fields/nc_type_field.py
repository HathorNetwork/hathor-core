#  Copyright 2025 Hathor Labs
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

from typing import TypeVar

from typing_extensions import Self

from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.exception import NCAttributeError
from hathor.nanocontracts.fields.field import Field
from hathor.nanocontracts.nc_types import NCType

T = TypeVar('T')


class NCTypeField(Field[T]):
    """ This class models a Field after a NCType, where acessing the field implies deserializing the value from the db.

    This is modeled after a Python descriptor, similar to the built in `property`, see:

    - https://docs.python.org/3/reference/datamodel.html#implementing-descriptors
    """
    __slots__ = ('__name', '__nc_type')

    __name: str
    __nc_type: NCType[T]

    @classmethod
    def _from_name_and_type(cls, name: str, type_: type[T], /, *, type_map: Field.TypeMap) -> Self:
        field = cls()
        field.__name = name
        field.__nc_type = NCType.from_type(type_, type_map=type_map.to_nc_type_map())
        return field

    def __storage_key(self) -> bytes:
        return self.__name.encode('utf-8')

    def __set__(self, instance: Blueprint, obj: T) -> None:
        instance.syscall.__storage__.put_obj(self.__storage_key(), self.__nc_type, obj)
        cache = instance.syscall.__cache__
        if cache is not None:
            cache[self.__name] = obj

    def __get__(self, instance: Blueprint, owner: object | None = None) -> T:
        cache = instance.syscall.__cache__
        if cache is not None and self.__name in cache:
            return cache[self.__name]

        try:
            obj = instance.syscall.__storage__.get_obj(self.__storage_key(), self.__nc_type)
            if cache is not None:
                cache[self.__name] = obj
            return obj
        except KeyError:
            raise NCAttributeError(f'Contract has no attribute \'{self.__name}\'')

    def __delete__(self, instance: Blueprint) -> None:
        instance.syscall.__storage__.del_obj(self.__storage_key())
