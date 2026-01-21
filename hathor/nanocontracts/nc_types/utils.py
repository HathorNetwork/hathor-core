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

from collections.abc import Hashable, Mapping
from functools import reduce
from operator import or_
from types import MappingProxyType as mappingproxy, NoneType, UnionType
# XXX: ignore attr-defined because mypy doesn't recognize it, even though all version of python that we support; have
#      this defined, even if it's an internal class
from typing import _UnionGenericAlias  # type: ignore[attr-defined]
from typing import TYPE_CHECKING, Iterator, NamedTuple, TypeAlias, TypeVar, Union, cast

from structlog import get_logger

from hathor.utils.typing import get_args, get_origin, is_subclass

if TYPE_CHECKING:
    from hathor.nanocontracts.nc_types import NCType


logger = get_logger()

T = TypeVar('T')
TypeAliasMap: TypeAlias = Mapping[type | UnionType, type]
TypeToNCTypeMap: TypeAlias = Mapping[type | UnionType | tuple[type, ...], type['NCType']]


def get_origin_classes(type_: type) -> Iterator[type]:
    """ This util function is useful to generalize over a type T and unions A | B.

    A simple type T would be yielded directly, and an union will yield each type in it. This way if you need to check a
    property either on a type that should be checked for each element in an union, this function simplifies the
    process. Also, only origin types are yielded, arguments are discarded, because normally that's what's needed in
    those situations.

    It is guaranteed that each yielded type is not an UnionType.

    XXX: on IPython [int] gets represented as '[int]', however on the Python terminal it shows as "<class 'int'>"
    because that's what's returned by repr/str, so these doctests are formatted in the way that Python would format it.

    >>> list(get_origin_classes(int))
    [<class 'int'>]
    >>> list(get_origin_classes(int | str))
    [<class 'int'>, <class 'str'>]
    >>> list(get_origin_classes(set))
    [<class 'set'>]
    >>> list(get_origin_classes(set[int]))
    [<class 'set'>]
    >>> list(get_origin_classes(set | dict))
    [<class 'set'>, <class 'dict'>]
    >>> list(get_origin_classes(set[int] | dict[int, str]))
    [<class 'set'>, <class 'dict'>]
    """
    origin_type: type = get_origin(type_) or type_
    if origin_type is UnionType:
        for arg_type in get_args(type_) or tuple():
            origin_arg_type: type = get_origin(arg_type) or arg_type
            assert origin_arg_type is not UnionType, 'this is impossible to construct'
            yield origin_arg_type
    else:
        yield origin_type


def is_origin_hashable(type_: type) -> bool:
    """ Checks whether the given type signature satisfies `collections.abc.Hashable`.

    This check ignores type arguments, but takes into account all types of an union.

    >>> is_origin_hashable(int)
    True
    >>> is_origin_hashable(str)
    True
    >>> is_origin_hashable(bytes)
    True
    >>> is_origin_hashable(int | str | bytes)
    True
    >>> is_origin_hashable(int | str | bytes | set)
    False
    >>> is_origin_hashable(int | str | bytes | frozenset)
    True
    >>> is_origin_hashable(set)
    False
    >>> is_origin_hashable(set[int])
    False
    >>> is_origin_hashable(frozenset)
    True
    >>> is_origin_hashable(frozenset[int])
    True
    >>> is_origin_hashable(frozenset[int])
    True
    >>> is_origin_hashable(dict)
    False
    >>> is_origin_hashable(mappingproxy)
    False
    >>> is_origin_hashable(list)
    False
    >>> is_origin_hashable(tuple)
    True

    Even though list is not hashable, a frozenset[list] is, simply because arguments are ignored:
    >>> is_origin_hashable(frozenset[list])
    True

    Callers should recurse on their own if they need to deal with type arguments. In practice when building a NCType
    from a type the recursion of the build process will deal with that.
    """
    return all(_is_origin_hashable(origin_class) for origin_class in get_origin_classes(type_))


def _is_origin_hashable(origin_class: type) -> bool:
    """ Inner implementation of is_origin_hashable, only checks a single origin class. """
    # XXX: on Python 3.11, `is_subclass(mappingproxy, Hashable) == False`, but on Python 3.12 it's `True`, in practice,
    #      for all the cases that we support `hash(mapping_proxy_instance)` fails with a `TypeError`, so `False` is the
    #      most useful result, even if there are technical reasons for why it should be `True` in 3.12
    # XXX: even though mappingproxy is not supported, this behavior is now consistent between different Python versions
    if origin_class is mappingproxy:
        return False
    return is_subclass(origin_class, Hashable)


def pretty_type(type_: type | UnionType) -> str:
    """ Shows a cleaner string representation for a type.
    """
    if type_ is NoneType or type_ is None:
        return 'None'
    elif hasattr(type_, '__args__'):
        return str(type_)
    else:
        return type_.__name__


# XXX: _verbose argument is used to help with doctest
def get_aliased_type(type_: type | UnionType, alias_map: TypeAliasMap, *, _verbose: bool = True) -> type:
    """ Map a type to its usable alias including the type's arguments.

    For example, `set` is mapped to `frozenset`  in the default alias map:

    >>> orig_type = tuple[str, frozenset[set[dict[int, set[str]]]], set[int], bool]
    >>> from hathor.nanocontracts.nc_types import DEFAULT_TYPE_ALIAS_MAP as alias_map
    >>> get_aliased_type(orig_type, alias_map, _verbose=False)
    tuple[str, frozenset[frozenset[dict[int, frozenset[str]]]], frozenset[int], bool]
    """
    new_type, replaced = _get_aliased_type(type_, alias_map)
    if replaced and _verbose:
        logger.debug('type replaced', old=pretty_type(type_), new=pretty_type(new_type))
    return new_type


def _get_aliased_type(type_: type | UnionType, alias_map: TypeAliasMap) -> tuple[type, bool]:
    """ Implementation of get_aliased_type with indication of whether there was a replacement.
    """
    origin_type = get_origin(type_) or type_
    # XXX: special case, replace typing.Union with types.UnionType
    aliased_origin: type
    replaced = False

    if origin_type is Union:
        aliased_origin = UnionType
    elif origin_type in alias_map:
        aliased_origin = alias_map[origin_type]
        replaced = True
    else:
        # XXX: erase UnionType from origin_type, it only gets in the way further on
        aliased_origin = cast(type, origin_type)

    if hasattr(type_, '__args__'):
        type_args = get_args(type_)
        assert isinstance(type_args, tuple)

        # use _get_aliased_type for recursion so we don't warn multiple times when a replacement happens
        # aliased_args_replaced is list of [(arg1, replaced1), (arg2, replaced2), ...]
        aliased_args_replaced = [_get_aliased_type(arg, alias_map) for arg in type_args]
        # unzip the list so we have [arg1, arg2, ...] and [replaced1, replaced2, ...]
        aliased_args, args_replaced = zip(*aliased_args_replaced)
        # update replaced status
        replaced |= any(args_replaced)

        # XXX: special case, UnionType can't be instantiated directly, this is the simplest way to do it
        if aliased_origin is UnionType:
            final_type = reduce(or_, aliased_args)  # = type_args[0] | type_args[1] | ... | type_args[N]
            # XXX: for some reason, only sometimes doing T | None, results in typing.Union instead of types.UnionType
            assert isinstance(final_type, (UnionType, _UnionGenericAlias)), '| of types results in union'
            return final_type, replaced  # type: ignore[return-value]

        # XXX: special case, when going from list -> tuple, we need to add an ellipsis, that is to say, the equivalent
        #      type for `list[T]` is `tuple[T, ...]`
        elif isinstance(origin_type, type) and issubclass(origin_type, list) and issubclass(aliased_origin, tuple):
            if len(aliased_args) != 1:
                raise TypeError('to make an alias from `list` to `tuple` exactly 1 argument is required')
            aliased_arg, = aliased_args
            return aliased_origin[aliased_arg, ...], replaced  # type: ignore[index]

        # normal case when there are type arguments (even if the arguments are empty, like tuple[()])
        # XXX: ignore index because mypy doesn't know aliased_origin is indexable even with the assert
        else:
            assert hasattr(aliased_origin, '__class_getitem__'), 'we must have an indexable class at this point'
            new_type = aliased_origin[*aliased_args]  # type: ignore[index]
            return new_type, replaced
    else:
        # normal case when there aren't type arguments
        return aliased_origin, replaced


def get_usable_origin_type(
    type_: type[T] | UnionType,
    /,
    *,
    type_map: 'NCType.TypeMap',
    _verbose: bool = True,
) -> type | tuple[type, ...]:
    """ The purpose of this function is to map a given type into a type that is usable in a NCType.TypeMap

    It takes into account type-aliasing according to NCType.TypeMap.alias_map. If the given type cannot be used in the
    given type_map, a TypeError exception will be raised.

    The returned type is such that it is guaranteed to exist in `type_map.nc_types_map`.

    For example, if we have a type `set[int]` it cannot be used to index the default types map, its origin
    however, is `dict`, which also isn't in the default map, but after applying the alias it becomes a `frozenset`,
    which is in the default map, `get_usable_origin_type` is a shortcut for doing this consistently and also raising a
    `TypeError` to indicate that the given type is not supported:

    >>> type_ = set[int]
    >>> from hathor.nanocontracts.nc_types import _FIELD_TYPE_MAP as default_type_map
    >>> origin = get_usable_origin_type(type_, type_map=default_type_map, _verbose=False)
    >>> assert origin in default_type_map.nc_types_map
    >>> origin
    <class 'frozenset'>
    """
    if isinstance(type_, str):
        raise NotImplementedError('string annotations are not currently supported')

    # if we have a `dict[int, int]` we use `get_origin()` to get the `dict` part, since it's a different instance
    aliased_type: type = get_aliased_type(type_, type_map.alias_map, _verbose=_verbose)
    origin_aliased_type: type | tuple[type, ...] = get_origin(aliased_type) or aliased_type

    if origin_aliased_type is UnionType:
        # When it's an union and None is not in it, it's not Optional,
        # so we must index by args which is a tuple of types.
        # This is done for support of specific union types such as CallerId (Address | ContractId)
        args = get_args(aliased_type)
        assert args is not None
        if NoneType not in args:
            origin_aliased_type = args

    if origin_aliased_type in type_map.nc_types_map:
        return origin_aliased_type

    if NamedTuple in type_map.nc_types_map and NamedTuple in getattr(type_, '__orig_bases__', tuple()):
        return NamedTuple

    raise TypeError(f'type {type_} is not supported by any NCType class')
