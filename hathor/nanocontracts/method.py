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

from __future__ import annotations

from collections.abc import Callable, Iterable
from inspect import Parameter, Signature, _empty as EMPTY, signature
from types import FunctionType, MethodType
from typing import Any, TypeVar

from typing_extensions import Self, assert_never, override

from hathor.nanocontracts import Context
from hathor.nanocontracts.exception import NCFail, NCSerializationArgTooLong, NCSerializationError
from hathor.nanocontracts.nc_types import (
    NCType,
    VarUint32NCType,
    make_nc_type_for_arg_type,
    make_nc_type_for_return_type,
)
from hathor.nanocontracts.utils import is_nc_public_method
from hathor.serialization import Deserializer, SerializationError, Serializer
from hathor.serialization.adapters import MaxBytesExceededError

_num_args_nc_type = VarUint32NCType()
T = TypeVar('T')

MAX_BYTES_SERIALIZED_ARG: int = 1000


def _deserialize_map_exception(nc_type: NCType[T], data: bytes) -> T:
    """ Internal handy method to deserialize `bytes` to `T` while mapping the exceptions."""
    try:
        deserializer = Deserializer.build_bytes_deserializer(data)
        value = nc_type.deserialize(deserializer)
        deserializer.finalize()
        return value
    except MaxBytesExceededError as e:
        raise NCSerializationArgTooLong from e
    except SerializationError as e:
        raise NCSerializationError from e
    except NCFail:
        raise
    except Exception as e:
        raise NCFail from e


def _serialize_map_exception(nc_type: NCType[T], value: T) -> bytes:
    """ Internal handy method to serialize `T` to `bytes` while mapping the exceptions."""
    try:
        serializer = Serializer.build_bytes_serializer()
        nc_type.serialize(serializer, value)
        return bytes(serializer.finalize())
    except MaxBytesExceededError as e:
        raise NCSerializationArgTooLong from e
    except SerializationError as e:
        raise NCSerializationError from e
    except NCFail:
        raise
    except Exception as e:
        raise NCFail from e


class _ArgsNCType(NCType):
    """ Inner implementation of a callable "args" using the NCType model.
    """

    _args: tuple[NCType, ...]
    _max_bytes: int

    def __init__(self, args_nc_types: Iterable[NCType], max_bytes: int) -> None:
        self._args = tuple(args_nc_types)
        self._max_bytes = max_bytes

    @override
    def _check_value(self, value: Any, /, *, deep: bool) -> None:
        # XXX: we take either a tuple or a list as input
        if not isinstance(value, (tuple, list)):
            raise TypeError('expected tuple or list')
        if len(value) > len(self._args):
            raise TypeError('too many arguments')
        if deep:
            for i, arg_nc_type in zip(value, self._args):
                arg_nc_type._check_value(i, deep=deep)

    @override
    def _serialize(self, serializer: Serializer, args: tuple[Any, ...] | list[Any], /) -> None:
        with serializer.with_max_bytes(self._max_bytes) as serializer:
            num_args = len(args)
            if num_args > len(self._args):
                raise TypeError('too many arguments')
            # XXX: default arguments are currently not supported, thus we reject too few arguments too
            if num_args < len(self._args):
                raise TypeError('too few arguments')
            _num_args_nc_type.serialize(serializer, num_args)
            for value, arg in zip(self._args, args):
                value.serialize(serializer, arg)

    @override
    def _deserialize(self, deserializer: Deserializer, /) -> tuple[Any, ...]:
        with deserializer.with_max_bytes(self._max_bytes) as deserializer:
            # TODO: normalize exceptions
            num_args = _num_args_nc_type.deserialize(deserializer)
            if num_args > len(self._args):
                raise TypeError('too many arguments')
            # XXX: default arguments are currently not supported, thus we reject too few arguments too
            if num_args < len(self._args):
                raise TypeError('too few arguments')
            args = []
            for value, _ in zip(self._args, range(num_args)):
                args.append(value.deserialize(deserializer))
            return tuple(args)

    @override
    def _json_to_value(self, json_value: NCType.Json, /) -> tuple[Any, ...]:
        if not isinstance(json_value, list):
            raise ValueError('expected list')
        return tuple(v.json_to_value(i) for (i, v) in zip(json_value, self._args))

    @override
    def _value_to_json(self, value: tuple[Any, ...], /) -> NCType.Json:
        return [v.value_to_json(i) for (i, v) in zip(value, self._args)]


class ArgsOnly:
    """ This class is used to parse only arguments of a call, when all that is provided is a list of argument types.

    Its primary use is for implementing `NCRawArgs.try_parse_as`.
    """
    args: _ArgsNCType

    def __init__(self, args_nc_type: _ArgsNCType) -> None:
        """Do not build directly, use `ArgsOnly.from_arg_types`"""
        self.args = args_nc_type

    @classmethod
    def from_arg_types(cls, arg_types: tuple[type, ...]) -> Self:
        args_nc_types: list[NCType] = []
        for arg_type in arg_types:
            args_nc_types.append(make_nc_type_for_arg_type(arg_type))

        return cls(_ArgsNCType(args_nc_types, max_bytes=MAX_BYTES_SERIALIZED_ARG))

    def serialize_args_bytes(self, args: tuple[Any, ...] | list[Any]) -> bytes:
        """ Shortcut to serialize args directly to a bytes instead of using a serializer.
        """
        return _serialize_map_exception(self.args, args)

    def deserialize_args_bytes(self, data: bytes) -> tuple[Any, ...]:
        """ Shortcut to deserialize args directly from bytes instead of using a deserializer.
        """
        return _deserialize_map_exception(self.args, data)


class ReturnOnly:
    """
    This class is used to parse only the return of a method.

    Its primary use is for validating the fallback method.
    """
    return_nc_type: NCType

    def __init__(self, return_nc_type: NCType) -> None:
        self.return_nc_type = return_nc_type

    @classmethod
    def from_callable(cls, method: Callable) -> Self:
        method_signature = _get_method_signature(method)
        nc_type = make_nc_type_for_return_type(method_signature.return_annotation)
        return cls(nc_type)

    def serialize_return_bytes(self, return_value: Any) -> bytes:
        """Shortcut to serialize a return value directly to bytes instead of using a serializer."""
        return _serialize_map_exception(self.return_nc_type, return_value)

    def deserialize_return_bytes(self, data: bytes) -> Any:
        """Shortcut to deserialize a return value directly from bytes instead of using a deserializer."""
        return _deserialize_map_exception(self.return_nc_type, data)


# XXX: currently the relationship between the method's signature's types and the `NCType`s type's cannot be described
#      with Python/mypy's typing system
class Method:
    """ This class abstracts a method's type signature in relation similarly to how NCType and Field abstract a loose
    "value" or a classe's "field".

    This abstraction is used to (de)serialize the arguments of a method call, and (de)serialize the result of a method
    call. It may also be used to transmit values when a nano-method calls another nano-method.

    For arguments, `make_nc_type_for_arg_type` is used, which tends to preserve original types as much as possible, but
    for return types `make_nc_type_for_return_type` is used, which supports `None`.
    """
    name: str
    arg_names: tuple[str, ...]
    args: _ArgsNCType
    return_: NCType

    def __init__(
        self,
        *,
        name: str,
        arg_names: Iterable[str],
        args_nc_type: _ArgsNCType,
        return_nc_type: NCType,
    ) -> None:
        """Do not build directly, use `Method.from_callable`"""
        self.name = name
        self.arg_names = tuple(arg_names)
        self.args = args_nc_type
        self.return_ = return_nc_type

    @classmethod
    def from_callable(cls, method: Callable) -> Self:
        method_signature = _get_method_signature(method)

        # XXX: bound methods don't have the self argument
        is_bound_method: bool

        match method:
            case MethodType():
                is_bound_method = True
            case FunctionType():
                is_bound_method = False
            case _:
                raise TypeError(f'{method!r} is neither a function or a bound method')

        for param in method_signature.parameters.values():
            if isinstance(param.annotation, str):
                raise TypeError('string annotations (including `from __future__ import annotations`), '
                                'are not supported')

        arg_names = []
        args_nc_types = []
        iter_params = iter(method_signature.parameters.values())

        # XXX: bound methods don't expose the self argument
        if not is_bound_method:
            try:
                self_param = next(iter_params)
            except StopIteration:
                raise TypeError('missing self argument')
            if self_param.name != 'self':
                # XXX: self_param is not technically required to be named 'self', it can be named anything, but it
                #      should at least be a warning because it's possible the author forgot the 'self' argument
                raise TypeError('first argument should be self')

        if is_nc_public_method(method):
            try:
                ctx_param = next(iter_params)
            except StopIteration:
                raise TypeError('missing ctx argument')
            if ctx_param.annotation is not Context:
                raise TypeError('context argument must be annotated as `ctx: Context`')

        for param in iter_params:
            match param.kind:
                case Parameter.POSITIONAL_ONLY:  # these are arguments before /
                    # we accept these
                    pass
                case Parameter.POSITIONAL_OR_KEYWORD:  # there are normal arguments
                    # we accept these
                    pass
                case Parameter.VAR_POSITIONAL:  # these are *args kind of arguments
                    # XXX: we can technically support this, since these can be annotated
                    raise TypeError('variable *args arguments are not supported')
                case Parameter.KEYWORD_ONLY:  # these are arguments after * or *args, which are keyword-only
                    raise TypeError('keyword-only arguments are not supported')
                case Parameter.VAR_KEYWORD:  # these are **kwargs arguments
                    raise TypeError('variable **kwargs arguments are not supported')
                case _ as impossible_kind:  # no other type of argument exist
                    assert_never(impossible_kind)
            # XXX: this can (and probably will) be implemented in the future
            if param.default is not EMPTY:
                raise TypeError('default values are not supported')
            arg_names.append(param.name)
            args_nc_types.append(make_nc_type_for_arg_type(param.annotation))

        return cls(
            name=method.__name__,
            arg_names=arg_names,
            args_nc_type=_ArgsNCType(args_nc_types, max_bytes=MAX_BYTES_SERIALIZED_ARG),
            return_nc_type=make_nc_type_for_return_type(method_signature.return_annotation),
        )

    def serialize_args_bytes(self, args: tuple[Any, ...] | list[Any], kwargs: dict[str, Any] | None = None) -> bytes:
        """ Shortcut to serialize args directly to a bytes instead of using a serializer.
        """
        if len(args) > len(self.arg_names):
            raise NCFail('too many arguments')

        merged: dict[str, Any] = {}
        for index, arg in enumerate(args):
            name = self.arg_names[index]
            merged[name] = arg

        kwargs = kwargs or {}
        for name, arg in kwargs.items():
            if name not in self.arg_names:
                raise NCFail(f"{self.name}() got an unexpected keyword argument '{name}'")
            if name in merged:
                raise NCFail(f"{self.name}() got multiple values for argument '{name}'")
            merged[name] = arg

        ordered_args = []
        for name in self.arg_names:
            if name not in merged:
                raise NCFail(f"{self.name}() missing required argument: '{name}'")
            ordered_args.append(merged[name])

        return _serialize_map_exception(self.args, tuple(ordered_args))

    def deserialize_args_bytes(self, data: bytes) -> tuple[Any, ...]:
        """ Shortcut to deserialize args directly from bytes instead of using a deserializer.
        """
        return _deserialize_map_exception(self.args, data)

    def serialize_return_bytes(self, return_value: Any) -> bytes:
        """ Shortcut to serialize a return value directly to a bytes instead of using a serializer.
        """
        return _serialize_map_exception(self.return_, return_value)

    def deserialize_return_bytes(self, data: bytes) -> Any:
        """ Shortcut to deserialize a return value directly from bytes instead of using a deserializer.
        """
        return _deserialize_map_exception(self.return_, data)


def _get_method_signature(method: Callable) -> Signature:
    if not callable(method):
        raise TypeError(f'{method!r} is not a callable object')

    # XXX: explicit all arguments to explain the choices, even if default
    return signature(
        method,
        follow_wrapped=True,  # we're interested in the implementation's signature, so we follow wrappers
        globals=None,  # don't expose any global
        locals=None,  # don't expose any local
        # XXX: do not evaluate strings, this means `from __future__ import annotations` is not supported, ideally
        #      we should support it because it's very convenient, but it must be done with care, otherwise we could
        #      run into cases that do `def foo(self, i: '2**100**100') -> None`, which is syntactically legal
        eval_str=False,
    )
