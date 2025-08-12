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

from typing import Callable, TypeVar, final

from typing_extensions import ParamSpec

from hathor.nanocontracts import Context
from hathor.nanocontracts.types import NCActionType


def _validate_faux_immutable_meta(name: str, bases: tuple[type, ...], attrs: dict[str, object]) -> None:
    """Run validations during faux-immutable class creation."""
    required_attrs = frozenset({
        '__slots__',
    })

    for attr in required_attrs:
        if attr not in attrs:
            raise TypeError(f'faux-immutable class `{name}` must define `{attr}`')

    allowed_dunder = frozenset({
        '__module__',
        '__qualname__',
        '__doc__',
        '__init__',
    })

    # Prohibit all other dunder attributes/methods.
    for attr in attrs:
        if '__' in attr and attr not in required_attrs | allowed_dunder:
            raise TypeError(f'faux-immutable class `{name}` must not define `{attr}`')

    # Prohibit inheritance on faux-immutable classes, this may be less strict in the future,
    # but we may only allow bases where `type(base) is _FauxImmutableMeta`.
    if len(bases) != 1 or not bases[0] is FauxImmutable:
        raise TypeError(f'faux-immutable class `{name}` must inherit from `FauxImmutable` only')


class _FauxImmutableMeta(type):
    """
    A metaclass for faux-immutable classes.
    This means the class objects themselves are immutable, that is, `__setattr__` always raises AttributeError.
    Don't use this metaclass directly, inherit from `FauxImmutable` instead.
    """
    __slots__ = ()

    def __new__(cls, name, bases, attrs, **kwargs):
        # validations are just a sanity check to make sure we only apply this metaclass to classes
        # that will actually become immutable, for example, using this metaclass doesn't provide
        # complete faux-immutability if the class doesn't define `__slots__`.
        if not attrs.get('__skip_faux_immutability_validation__', False):
            _validate_faux_immutable_meta(name, bases, attrs)
        return super().__new__(cls, name, bases, attrs, **kwargs)

    def __setattr__(cls, name: str, value: object) -> None:
        raise AttributeError(f'cannot set attribute `{name}` on faux-immutable class')


class FauxImmutable(metaclass=_FauxImmutableMeta):
    """
    Utility superclass for creating faux-immutable classes.
    Simply inherit from it to define a faux-immutable class.
    """
    __slots__ = ()
    __skip_faux_immutability_validation__: bool = True  # Skip validation to bypass the no dunder rule.

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError(f'cannot set attribute `{name}` on faux-immutable object')


T = TypeVar('T', bound=FauxImmutable)
P = ParamSpec('P')


def create_with_shell(cls: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
    """Mimic `cls.__call__` method behavior, but wrapping the created instance with an ad-hoc shell class."""
    # Keep the same name as the original class.
    assert isinstance(cls, type)
    name = cls.__name__

    # The original class is the shell's only base.
    bases = (cls,)

    # The shell doesn't have any slots and must skip validation to bypass the inheritance rule.
    attrs = dict(__slots__=(), __skip_faux_immutability_validation__=True)

    # Create a dynamic class that is only used on this call.
    shell_type: type[T] = type(name, bases, attrs)

    # Use it to instantiate the object, init it, and return it. This mimics the default `__call__` behavior.
    obj: T = cls.__new__(shell_type)
    shell_type.__init__(obj, *args, **kwargs)
    return obj


def __set_faux_immutable__(obj: FauxImmutable, name: str, value: object) -> None:
    """
    When setting attributes on the `__init__` method of a faux-immutable class,
    use this utility function to bypass the protections.
    Only use it when you know what you're doing.
    """
    if name.startswith('__') and not name.endswith('__'):
        # Account for Python's name mangling.
        name = f'_{obj.__class__.__name__}{name}'

    # This shows that a faux-immutable class is never actually immutable.
    # It's always possible to mutate it via `object.__setattr__`.
    object.__setattr__(obj, name, value)


def __freeze__(obj: object) -> object:
    ty = obj if isinstance(obj, type) else type(obj)
    if ty is FrozenWrapper:
        return ty

    if ty not in _FREEZABLE_TYPES:
        # TODO: Can't freeze
        return ty

    return FrozenWrapper(obj, ty)


@final
class FrozenWrapperCallable(FauxImmutable):
    __slots__ = ('__callable',)

    def __init__(self, callable: object) -> None:
        __set_faux_immutable__(self, '__callable', callable)

    def __call__(self, *args, **kwargs):
        return self.__callable(*args, **kwargs)


@final
class FrozenWrapper(FauxImmutable):
    __slots__ = ('__obj', '__ty')

    def __init__(self, obj: object, ty: type) -> None:
        __set_faux_immutable__(self, '__obj', obj)
        __set_faux_immutable__(self, '__ty', ty)

    def __getattr__(self, name):
        allowed_attrs, allowed_methods = _FREEZABLE_TYPES[self.__ty]

        if name in allowed_attrs:
            return __freeze__(getattr(self.__obj, name))

        if name in allowed_methods:
            return FrozenWrapperCallable(getattr(self.__obj, name))

        raise AttributeError(f'FORBIDDEN! FORBIDDEN! {name}')

    def __is__(self, obj: object) -> bool:
        return self.__obj is obj

    def __dir__(self):
        allowed_attrs, allowed_methods = _FREEZABLE_TYPES[self.__ty]
        return tuple(allowed_attrs | allowed_methods)


_FREEZABLE_TYPES: dict[type, tuple[frozenset[str], frozenset[str]]] = {
    NCActionType: (
        frozenset({
            'DEPOSIT',
            'WITHDRAWAL',
            'GRANT_AUTHORITY',
            'ACQUIRE_AUTHORITY',
        }),
        frozenset(),
    ),
    Context: (
        frozenset({
            'vertex',
            'address',
            'timestamp',
            'actions',
            'actions_list',
        }),
        frozenset({
            'get_single_action',
        }),
    )
}
