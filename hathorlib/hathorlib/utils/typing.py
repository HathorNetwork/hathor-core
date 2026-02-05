# Copyright 2025 Hathor Labs
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

from __future__ import annotations

from types import UnionType
from typing import Generic, TypeVar, get_args as _typing_get_args, get_origin as _typing_get_origin
from weakref import WeakValueDictionary

from typing_extensions import Self

T = TypeVar('T')


def get_origin(t: type | UnionType, /) -> type | None:
    """Extension of typing.get_origin to also work with classes that use InnerTypeMixin"""
    if isinstance(t, type) and issubclass(t, InnerTypeMixin):
        return getattr(t, '__origin__', None)
    return _typing_get_origin(t)


def get_args(t: type | UnionType, /) -> tuple[type, ...] | None:
    """Extension of typing.get_args to also work with classes that use InnerTypeMixin"""
    if isinstance(t, type) and issubclass(t, InnerTypeMixin):
        return getattr(t, '__args__', None)
    return _typing_get_args(t)


class InnerTypeMixin(Generic[T]):
    """
    Mixin class that exposes its single type‐argument at runtime as `self.__inner_type__`,
    enforces exactly one type argument at subscription time, caches parameterized subclasses
    so C[int] is C[int], and provides a clean repr listing public fields.

    >>> from typing import TypeVar
    >>> U = TypeVar('U')
    >>> class MyData(InnerTypeMixin, Generic[T]):
    ...     def __init__(self, data: T):
    ...         self.data = data
    ...
    >>> class MyCounter(InnerTypeMixin, Generic[T]):
    ...     def __init__(self, first: T, count: int):
    ...         self.first = first
    ...         self.count = count
    ...

    # 1) You must supply exactly one type argument:
    >>> try:
    ...     MyData(1)
    ... except TypeError as e:
    ...     print(e)
    MyData[...] requires exactly one type argument, got none

    >>> try:
    ...     MyData[int, str](1)
    ... except TypeError as e:
    ...     print(e)
    MyData[...] expects exactly one type argument; got 2

    # You may write MyData[U] for signatures, but instantiation will reject a bare TypeVar:
    >>> MyData[U]    # no error
    <class 'hathor.utils.typing.MyData'>

    >>> try:
    ...     MyData[U]()
    ... except TypeError as e:
    ...     print(e)
    MyData[...] requires a concrete type argument, got ~U

    # Correct usage with a concrete type:
    >>> sd = MyData[int](123)
    >>> MyData[int] is MyData[int]
    True
    >>> sd.__inner_type__ is int
    True
    >>> print(sd)
    MyData[int](data=123)

    # Works with multiple fields too:
    >>> h = MyCounter[str]("foo", 42)
    >>> h.__inner_type__ is str
    True
    >>> print(h)
    MyCounter[str](first='foo', count=42)
    """

    # cache shared by all subclasses, maps concrete inner_type -> subclass, but doesn't keep subclasses alive if it has
    # no live references anymore, this keeps the cache from growing indefinitely in case of dynamically generated
    # classes, there's no point in holding unreferenced classes here
    __type_cache: WeakValueDictionary[tuple[type, type], type[Self]] = WeakValueDictionary()

    # this class will expose this instance property
    __inner_type__: type[T]

    @classmethod
    def __extract_inner_type__(cls, args: tuple[type, ...], /) -> type[T]:
        """Defines how to convert the recived argument tuples into the stored type.

        If customization is needed, this class method is the place to do it. I could be used so only the origin-type is
        stored, or to accept multiple arguments and store a tuple of types, or to convert the arguments into different
        types.
        """
        if len(args) != 1:
            raise TypeError(f'{cls.__name__}[...] expects exactly one type argument; got {len(args)}')
        inner_type, = args
        return inner_type

    @classmethod
    def __class_getitem__(cls, params):
        # parameterizing the mixin itself delegates to Generic
        if cls is InnerTypeMixin:
            return super().__class_getitem__(params)

        # normalize to a 1-tuple
        args = params if isinstance(params, tuple) else (params,)
        inner_type = cls.__extract_inner_type__(args)

        cache = cls.__type_cache
        key = (cls, inner_type)
        sub = cache.get(key)
        if sub is None:
            # subclass keeps the same name for clean repr
            sub = type(cls.__name__, (cls,), {})
            sub.__inner_type__ = inner_type
            sub.__origin__ = cls
            sub.__args__ = (inner_type,)
            sub.__module__ = cls.__module__
            sub.__type_cache = cache
            cache[key] = sub
        return sub

    def __new__(cls, *args, **kwargs):
        # reject unsubscripted class
        if not get_args(cls):
            raise TypeError(f'{cls.__name__}[...] requires exactly one type argument, got none')

        # reject if the subscribed‐in type is still a TypeVar
        inner_type = getattr(cls, '__inner_type__', None)
        if isinstance(inner_type, TypeVar):
            raise TypeError(f'{cls.__name__}[...] requires a concrete type argument, got {inner_type!r}')

        # build instance and copy down the inner type
        self = super().__new__(cls)
        self.__inner_type__ = inner_type
        return self

    def __repr__(self) -> str:
        name = type(self).__name__
        t = self.__inner_type__
        tname = getattr(t, '__name__', repr(t))
        public = [(n, v) for n, v in vars(self).items() if not n.startswith('_')]
        if public:
            body = ', '.join(f'{n}={v!r}' for n, v in public)
            return f'{name}[{tname}]({body})'
        return f'{name}[{tname}]()'


def is_subclass(cls: type, class_or_tuple: type | tuple[type] | UnionType, /) -> bool:
    """ Reimplements issubclass() with support for recursive NewType classes.

    Normal behavior from `issubclass`:

    >>> is_subclass(int, int)
    True
    >>> is_subclass(bool, int)
    True
    >>> is_subclass(bool, (int, str))
    True
    >>> is_subclass(bool, int | str)
    True
    >>> is_subclass(bool, bytes | str)
    False
    >>> is_subclass(str, int)
    False

    But `is_subclass` also works when a NewType is given as arg 1:

    >>> from typing import NewType
    >>> N = NewType('N', int)
    >>> is_subclass(N, int)
    True
    >>> is_subclass(N, int | str)
    True
    >>> is_subclass(N, str)
    False
    >>> M = NewType('M', N)
    >>> is_subclass(M, int)
    True
    >>> is_subclass(M, str)
    False
    >>> try:
    ...     is_subclass(M, N)
    ... except TypeError as e:
    ...     print(*e.args)
    issubclass() arg 2 must be a class, a tuple of classes, or a union

    It is also expeced to fail in the same way as `issubclass` when the resolving the NewType doesn't lead to a class:

    >>> F = NewType('F', 'not a class')
    >>> try:
    ...     is_subclass(F, str)
    ... except TypeError as e:
    ...     print(*e.args)
    issubclass() arg 1 must be a class
    """
    while (super_type := getattr(cls, '__supertype__', None)) is not None:
        cls = super_type
    return issubclass(cls, class_or_tuple)
