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

from abc import ABC, abstractmethod
from typing import Any, TypeVar, final

from .consts import DEFAULT_BYTES_MAX_LENGTH, DEFAULT_LEB128_MAX_BYTES
from .exceptions import TooLongError, UnsupportedTypeError

T = TypeVar('T')


class Serializer(ABC):
    @abstractmethod
    def cur_pos(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def write_byte(self, data: int) -> None:
        """Write a single byte."""
        raise NotImplementedError

    @abstractmethod
    def _write_bytes(self, data: bytes | memoryview) -> None:
        # XXX: it is recommended that implementors of Serializer specialize this implementation
        for byte in data:
            self.write_byte(byte)

    @final
    def write_bytes(self, data: bytes | memoryview, *, max_bytes: int | None = DEFAULT_BYTES_MAX_LENGTH) -> None:
        """Write a byte sequence.

        To avoid accidental big writes, there is a default limit on the length of data written per call, the limit can
        be removed with `max_bytes=None` or set to what is appropriate.
        """
        if max_bytes is not None and len(data) > max_bytes:
            raise TooLongError('result is too long')
        self._write_bytes(data)

    def write_leb128_unsigned(self, value: int, *, max_bytes: int | None = DEFAULT_LEB128_MAX_BYTES) -> None:
        """Write a value as an unsigned LEB128 encoded value.

        To avoid accidental big writes, there is a default limit on the length of data written per call, the limit can
        be removed with `max_bytes=None` or set to what is appropriate.
        """
        from hathor.utils.leb128 import serialize_leb128
        serialize_leb128(value, self, signed=False, max_bytes=max_bytes)

    def write_leb128_signed(self, value: int, *, max_bytes: int | None = DEFAULT_LEB128_MAX_BYTES) -> None:
        """Write a value as an signed LEB128 encoded value.

        To avoid accidental big writes, there is a default limit on the length of data written per call, the limit can
        be removed with `max_bytes=None` or set to what is appropriate.
        """
        from hathor.utils.leb128 import serialize_leb128
        serialize_leb128(value, self, signed=True, max_bytes=max_bytes)

    def write_type(self, type_: type[T], value: T) -> None:
        """Write a value using the default encoder for the given type.

        The default encoder is the same as what would be used for serializing an NC method call or immutable NC field.
        """
        from hathor.nanocontracts.fields import SingleValueField, get_field_class_for_attr
        field_class = get_field_class_for_attr(type_)
        if not issubclass(field_class, SingleValueField):
            raise UnsupportedTypeError(f'type not supported: {type_}')
        field = field_class.create_from_type('', type_)
        assert field.isinstance(value)
        field.serialize(self, value)

    # TODO: fix write_type so it can handle a tuple directly
    # XXX: variadic arguments is implemented in Python 3.11, which would help with the type interface
    def write_type_tuple(
        self,
        types_tuple: tuple[type[Any], ...],
        values_tuple: tuple[Any, ...],
        *,
        max_bytes: int | None = None,
    ) -> None:
        """Write a tuple of values using the default encoder for each type given as a tuple.

        Eventually this method will be replaced by using write_type() directly as:

            serializer.write_type(tuple[int, str], (1, 'foo'))

        Instead of:

            serializer.write_type_tuple((int, str), (1, 'foo'))

        The choice of encoder is the same as when using write_type().
        """
        assert len(values_tuple) == len(types_tuple), f'{len(values_tuple)} != {len(types_tuple)} ({types_tuple})'
        pos0 = self.cur_pos()
        for type_, value in zip(types_tuple, values_tuple):
            self.write_type(type_, value)
        pos1 = self.cur_pos()
        if max_bytes is not None and pos1 - pos0 > max_bytes:
            raise TooLongError('result is too long')

    def write_output_value(self, number: int) -> None:
        """Write a value using our custom "output value" format."""
        from hathor.transaction.util import MAX_OUTPUT_VALUE_32
        if number <= 0:
            raise ValueError('Number must be strictly positive')
        # XXX: `signed` makes no difference, but oh well
        if number > MAX_OUTPUT_VALUE_32:
            self.write_bytes((-number).to_bytes(8, byteorder='big', signed=True))
        else:
            self.write_bytes(number.to_bytes(4, byteorder='big', signed=True))
