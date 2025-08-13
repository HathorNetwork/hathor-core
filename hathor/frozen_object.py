#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from __future__ import annotations

from typing import final

from hathor.nanocontracts.faux_immutable import FauxImmutable, __set_faux_immutable__


def __freeze__(obj):
    # TODO: Prevent onions
    # if obj is FrozenWrapper:
    #     return ty
    return FrozenObject(obj)


@final
class FrozenObject(FauxImmutable):
    __slots__ = ('__obj', '__allowed_access')
    __skip_faux_immutability_validation__ = True

    def __init__(self, obj: object) -> None:
        from hathor.nanocontracts.allowed_access import get_allowed_access
        from hathor.nanocontracts.allowed_access import AllowedAccess
        self.__obj: object
        self.__allowed_access: AllowedAccess

        allowed = get_allowed_access(obj)
        __set_faux_immutable__(self, '_FrozenObject__obj', obj)
        __set_faux_immutable__(self, '_FrozenObject__allowed_access', allowed)

    def __getattr__(self, name):
        if name in self.__allowed_access.attrs:
            return __freeze__(getattr(self.__obj, name))

        if name in self.__allowed_access.methods:
            return __freeze__(getattr(self.__obj, name))

        raise AttributeError(f'FORBIDDEN! {name} on "{self.__obj}"')

    def __getitem__(self, key):
        if '__getitem__' in self.__allowed_access.methods:
            return __freeze__(self.__obj[key])

        raise AttributeError(f'FORBIDDEN! __getitem__ on "{self.__obj}"')

    def __call__(self, *args, **kwargs):
        if '__call__' in self.__allowed_access.methods:
            return __freeze__(self.__obj(*args, **kwargs))

        raise AttributeError(f'FORBIDDEN! __call__ on "{self.__obj}"')

    def __dir__(self):
        return tuple(self.__allowed_access.all())


def __is_instance_frozen__(obj: object, type_: object) -> bool:
    if isinstance(obj, FrozenObject):
        obj = obj._FrozenObject__obj

    if isinstance(type_, FrozenObject):
        type_ = type_._FrozenObject__obj

    assert not isinstance(obj, FrozenObject)
    assert not isinstance(type_, FrozenObject)
    return isinstance(obj, type_)

def __is_frozen__(obj1: object, obj2: object) -> bool:
    if isinstance(obj1, FrozenObject):
        obj1 = obj1._FrozenObject__obj

    if isinstance(obj2, FrozenObject):
        obj2 = obj2._FrozenObject__obj

    assert not isinstance(obj1, FrozenObject)
    assert not isinstance(obj2, FrozenObject)
    return obj1 is obj2

def __get_frozen_inner__(obj: object) -> object:
    return obj._FrozenObject__obj if isinstance(obj, FrozenObject) else obj

# @final
# class FrozenWrapperCallable(FauxImmutable):
#     __slots__ = ('__callable',)
#
#     def __init__(self, callable_: object) -> None:
#         assert callable(callable_)
#         __set_faux_immutable__(self, '_FrozenWrapperCallable__callable', callable_)
#
#     def __call__(self, *args, **kwargs):
#         return self.__callable(*args, **kwargs)
