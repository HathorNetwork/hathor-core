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

import struct
from abc import ABC, abstractmethod
from typing import Any, TypeVar, cast, final

from .consts import DEFAULT_BYTES_MAX_LENGTH, DEFAULT_LEB128_MAX_BYTES
from .exceptions import BadDataError, TooLongError, UnsupportedTypeError

T = TypeVar('T')


class Deserializer(ABC):
    @abstractmethod
    def is_empty(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def peek_byte(self) -> int:
        """Read a single byte but don't consume from buffer."""
        raise NotImplementedError

    @abstractmethod
    def peek_bytes(self, n: int) -> memoryview:
        """Read n single byte but don't consume from buffer."""
        raise NotImplementedError

    def peek_struct(self, format: str) -> tuple[Any, ...]:
        size = struct.calcsize(format)
        data = self.peek_bytes(size)
        return struct.unpack(format, data)

    @abstractmethod
    def read_byte(self) -> int:
        """Read a single byte as unsigned int."""
        raise NotImplementedError

    @abstractmethod
    def _read_bytes(self, n: int) -> memoryview:
        # XXX: it is recommended that implementors of Deserializer specialize this implementation
        return memoryview(bytes(self.read_byte() for _ in range(n)))

    @final
    def read_bytes(self, n: int, *, max_bytes: int | None = DEFAULT_BYTES_MAX_LENGTH) -> memoryview:
        """Read n bytes, errors if there isn't enough data"""
        if max_bytes is not None and n > max_bytes:
            raise TooLongError('requested length exceeds maximum length')
        return self._read_bytes(n)

    @abstractmethod
    def read_all(self) -> memoryview:
        """Read all bytes until the reader is empty."""
        # XXX: it is recommended that implementors of Deserializer specialize this implementation
        def iter_bytes():
            while not self.is_empty():
                yield self.read_byte()
        return memoryview(bytes(iter_bytes()))

    def read_struct(self, format: str, *, max_bytes: int | None = DEFAULT_BYTES_MAX_LENGTH) -> tuple[Any, ...]:
        size = struct.calcsize(format)
        data = self.read_bytes(size, max_bytes=max_bytes)
        return struct.unpack_from(format, data)

    def read_leb128_unsigned(self, *, max_bytes: int | None = DEFAULT_LEB128_MAX_BYTES) -> int:
        from hathor.utils.leb128 import deserialize_leb128
        return deserialize_leb128(self, signed=False, max_bytes=max_bytes)

    def read_leb128_signed(self, *, max_bytes: int | None = DEFAULT_LEB128_MAX_BYTES) -> int:
        from hathor.utils.leb128 import deserialize_leb128
        return deserialize_leb128(self, signed=True, max_bytes=max_bytes)

    def read_type(self, type_: type[T]) -> T:
        """ Deserialize a given type from the given buffer and return the value.

        The effect on the buffer is consuming only the serialized bytes.
        """
        from hathor.nanocontracts.fields import SingleValueField, get_field_class_for_attr
        field_class = get_field_class_for_attr(type_)
        if not issubclass(field_class, SingleValueField):
            raise UnsupportedTypeError(f'type not supported: {type_}')
        field = field_class.create_from_type('', type_)
        value = field.deserialize(self)
        assert field.isinstance(value)
        return cast(T, value)

    # TODO: fix read_type so it can handle a tuple directly
    def read_type_tuple(self, types_tuple: tuple[type[Any], ...]) -> tuple[Any, ...]:
        values_tuple = tuple(self.read_type(type_) for type_ in types_tuple)
        if len(types_tuple) != len(values_tuple):
            raise BadDataError('Unable to parse: different number of arguments')
        return values_tuple

    def read_output_value(self) -> int:
        """Read a value using our custom "output value" format."""
        from hathor.transaction.util import MAX_OUTPUT_VALUE_32
        value_high_byte, = self.peek_struct('!b')
        try:
            if value_high_byte < 0:
                raw_value, = self.read_struct('!q')
                value = -raw_value
            else:
                value, = self.read_struct('!i')
        except struct.error as e:
            raise BadDataError('Invalid byte struct for output') from e
        assert value >= 0
        if value < MAX_OUTPUT_VALUE_32 and value_high_byte < 0:
            raise ValueError('Value fits in 4 bytes but is using 8 bytes')
        return value
