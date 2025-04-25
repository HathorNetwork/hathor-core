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

import inspect
from typing import Any, Callable

from structlog import get_logger

from hathor.conf.get_settings import get_global_settings
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCSerializationError
from hathor.serialization import BytesDeserializer, BytesSerializer, SerializationError

logger = get_logger()


class NCMethodParser:
    """Utility class to serialize and deserialize method arguments."""
    def __init__(self, method: Callable) -> None:
        self.method = method
        self._settings = get_global_settings()
        self._max_bytes = self._settings.NC_MAX_LENGTH_SERIALIZED_ARG

    def get_arg_types(self) -> tuple[type, ...]:
        """Return the list of the type of each argument for the method."""
        from hathor.nanocontracts.utils import is_nc_public_method
        argspec = inspect.getfullargspec(self.method)
        assert argspec.args[0] == 'self'
        if is_nc_public_method(self.method):
            begin_idx = 2
            assert argspec.args[1] == 'ctx'
            if argspec.annotations['ctx'] is not Context:
                raise TypeError('ctx must be of type Context')
        else:
            begin_idx = 1
        args = []
        for arg_name in argspec.args[begin_idx:]:
            arg_type = argspec.annotations[arg_name]
            args.append(arg_type)
        return tuple(args)

    def serialize_args(self, args: tuple[Any, ...] | list[Any]) -> bytes:
        """Serialize a list of arguments into bytes according to the types."""
        from hathor.nanocontracts.exception import NCSerializationArgTooLong
        from hathor.serialization import TooLongError

        arg_types_tuple = self.get_arg_types()
        if len(args) != len(arg_types_tuple):
            # XXX: we don't yet support arguments with default values, when we do it will be enough to check that
            #      len(args) <= len(arg_types_tuple) in order to proceed
            raise NCSerializationError('number of args mismatch')

        serializer = BytesSerializer()
        serializer.write_leb128_unsigned(len(args))
        try:
            serializer.write_type_tuple(arg_types_tuple, tuple(args), max_bytes=self._max_bytes)
        except TooLongError as e:
            raise NCSerializationArgTooLong() from e
        return bytes(serializer.finalize())

    def deserialize_args(self, args_bytes: bytes) -> tuple[Any, ...]:
        """Parse bytes into a list of arguments according to the types."""
        deserializer = BytesDeserializer(args_bytes)
        num_args = deserializer.read_leb128_unsigned()
        arg_types_tuple = self.get_arg_types()
        if num_args != len(arg_types_tuple):
            # XXX: we don't yet support arguments with default values, when we do it will be enough to check that
            #      num_args <= len(arg_types_tuple) in order to proceed
            raise NCSerializationError('number of args mismatch')
        try:
            args = deserializer.read_type_tuple(arg_types_tuple)
        except SerializationError as e:
            raise NCSerializationError() from e
        # XXX: all bytes must be consumed
        if not deserializer.is_empty():
            raise NCSerializationError('unexpected extra bytes')
        return args
