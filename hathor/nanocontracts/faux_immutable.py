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

import inspect
import typing
from typing import Callable, TypeVar, final

from typing_extensions import ParamSpec

from hathor.nanocontracts.allowed_access import get_allowed_access


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


def init_with_shell(cls: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
    """
    Mimic `cls.__call__` method behavior, but wrapping the created instance with an ad-hoc shell class.
    Use this for wrapping instances of classes that should be faux-immutable.
    """
    # Keep the same name as the original class, with the shell identifier.
    assert inspect.isclass(cls)
    name = f'{cls.__name__}__Shell'

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


# TODO: Rename?
def create_function_shell(f: Callable[P, T]) -> Callable[P, T]:
    """
    Wrap the provided function with an ad-hoc shell class.
    Use this for wrapping functions that should be faux-immutable.
    """
    # Keep the same name as the original callable, with the shell identifier.
    if (
        not callable(f)
        or inspect.isclass(f)
        or type(f) is typing._SpecialForm
        or f is typing.NamedTuple
    ):
        return f
    name = f'{f.__name__}__Shell'

    # No base classes.
    bases = ()

    def call(_self: object, *args: P.args, **kwargs: P.kwargs) -> T:
        return f(*args, **kwargs)

    # The shell doesn't have any slots and must skip validation to bypass the inheritance rule.
    # The callable is stored in the `__call__` method.
    attrs = dict(
        __slots__=(),
        __skip_faux_immutability_validation__=True,
        __shell_inner__=f,
        __call__=call,
    )

    # Create a dynamic class that is only used on this call.
    shell_type = type(name, bases, attrs)

    # Use it to instantiate the object and return it. Mypy doesn't like this.
    return shell_type.__new__(shell_type)  # type: ignore[call-overload]


def __set_faux_immutable__(obj: object, name: str, value: object) -> None:
    """
    When setting attributes on the `__init__` method of a faux-immutable class,
    use this utility function to bypass the protections.
    Only use it when you know what you're doing.
    """
    # This shows that a faux-immutable class is never actually immutable.
    # It's always possible to mutate it via `object.__setattr__`.
    object.__setattr__(obj, name, value)


def __get_inner_shell_type__(shell: typing.Any) -> typing.Any:
    return getattr(shell, '__shell_inner__', shell)


def __freeze__(obj):
    # if obj is FrozenWrapper:
    #     return ty

    if get_allowed_access(obj) is None:
        # TODO: Can't freeze
        return obj

    return FrozenObject(obj)



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


@final
class FrozenObject(FauxImmutable):
    __slots__ = ('__obj',)
    __skip_faux_immutability_validation__ = True

    def __init__(self, obj: object) -> None:
        self.__obj: object
        __set_faux_immutable__(self, '_FrozenObject__obj', obj)

    def __getattr__(self, name):
        allowed = get_allowed_access(self.__obj)

        if name in allowed.attrs:
            # TODO: Wrap return
            return __freeze__(getattr(self.__obj, name))

        if name in allowed.methods:
            # TODO: Wrap return
            # return FrozenWrapperCallable(getattr(self.__obj, name))
            return getattr(self.__obj, name)

        raise AttributeError(f'FORBIDDEN! {name} on {self.__obj}')

    def __getitem__(self, key):
        allowed = get_allowed_access(self.__obj)

        if '__getitem__' in allowed.methods:
            return __freeze__(self.__obj[key])

        raise AttributeError(f'FORBIDDEN! __getitem__ on {self.__obj}')

    def __dir__(self):
        allowed = get_allowed_access(self.__obj)
        return tuple(allowed.all())


def __is_instance_frozen__(obj: object, type_: object) -> bool:
    if isinstance(obj, FrozenObject):
        obj = obj._FrozenObject__obj

    if isinstance(type_, FrozenObject):
        type_ = type_._FrozenObject__obj

    return isinstance(obj, type_)
