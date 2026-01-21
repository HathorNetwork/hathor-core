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

from typing import Callable, TypeVar

from typing_extensions import ParamSpec

# special attrs:
SKIP_VALIDATION_ATTR: str = '__skip_faux_immutability_validation__'
ALLOW_INHERITANCE_ATTR: str = '__allow_faux_inheritance__'
ALLOW_DUNDER_ATTR: str = '__allow_faux_dunder__'


def _validate_faux_immutable_meta(name: str, bases: tuple[type, ...], attrs: dict[str, object]) -> None:
    """Run validations during faux-immutable class creation."""
    required_attrs = frozenset({
        '__slots__',
    })

    for attr in required_attrs:
        if attr not in attrs:
            raise TypeError(f'faux-immutable class `{name}` must define `{attr}`')

    custom_allowed_dunder_value: tuple[str, ...] = attrs.pop(ALLOW_DUNDER_ATTR, ())  # type: ignore[assignment]
    custom_allowed_dunder = frozenset(custom_allowed_dunder_value)
    allowed_dunder = frozenset({
        '__module__',
        '__qualname__',
        '__doc__',
        '__init__',
        '__call__',
    }) | custom_allowed_dunder

    # pop the attribute so the created class doesn't have it and it isn't inherited
    allow_inheritance = attrs.pop(ALLOW_INHERITANCE_ATTR, False)

    # Prohibit all other dunder attributes/methods.
    for attr in attrs:
        if '__' in attr and attr not in required_attrs | allowed_dunder:
            raise TypeError(f'faux-immutable class `{name}` must not define `{attr}`')

    # Prohibit inheritance on faux-immutable classes, this may be less strict in the future,
    # but we may only allow bases where `type(base) is FauxImmutableMeta`.
    if len(bases) != 1:
        raise TypeError('faux-immutable only allows one base')

    base, = bases
    if base is not FauxImmutable and not allow_inheritance:
        raise TypeError(f'faux-immutable class `{name}` must inherit from `FauxImmutable` only')


class FauxImmutableMeta(type):
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
        if not attrs.get(SKIP_VALIDATION_ATTR, False):
            _validate_faux_immutable_meta(name, bases, attrs)
        return super().__new__(cls, name, bases, attrs, **kwargs)

    def __setattr__(cls, name: str, value: object) -> None:
        raise AttributeError(f'cannot set attribute `{name}` on faux-immutable class')


class FauxImmutable(metaclass=FauxImmutableMeta):
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
    obj: T = cls.__new__(shell_type)  # type: ignore[call-overload]
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
