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

from abc import ABC
from typing import Any, Type

from typing_extensions import Self

from hathor.nanocontracts.exception import NCAttributeError
from hathor.nanocontracts.fields.base import Field
from hathor.serialization import Deserializer, Serializer
from hathor.transaction.util import bytes_to_int, decode_string_utf8, int_to_bytes

MAX_BYTES_LENGTH = 2**16  # 64 KiB


class SingleValueField(Field, ABC):
    """Base class for single-value fields."""
    type: Any

    def __init__(self, name: str) -> None:
        self.name = name

    @classmethod
    def create_from_type(cls, name: str, _type: Type[Any]) -> Self:
        return cls(name)

    def isinstance(self, value: Any) -> bool:
        return isinstance(value, self.type)

    def __set__(self, blueprint, value):
        """Store the value in the storage."""
        blueprint.syscall.__storage__.put(self.name, value)
        blueprint.syscall.__cache__[self.name] = value

    def __get__(self, blueprint, objtype):
        """Return the value from the storage."""
        if self.name in blueprint.syscall.__cache__:
            return blueprint.syscall.__cache__[self.name]

        try:
            value = blueprint.syscall.__storage__.get(self.name)
            blueprint.syscall.__cache__[self.name] = value
            return value
        except KeyError:
            raise NCAttributeError(f'Contract has no attribute \'{self.name}\'')


class StrField(SingleValueField):
    """This is the field for Python's `str` type."""
    type = str

    def serialize(self, serializer: Serializer, value: Any) -> None:
        assert isinstance(value, str)
        data = value.encode('utf-8')
        serializer.write_leb128_unsigned(len(data))
        serializer.write_bytes(data, max_bytes=MAX_BYTES_LENGTH)

    def deserialize(self, deserializer: Deserializer) -> Any:
        size = deserializer.read_leb128_unsigned()
        data = bytes(deserializer.read_bytes(size, max_bytes=MAX_BYTES_LENGTH))
        return decode_string_utf8(data, 'str')


class BytesField(SingleValueField):
    """This is the field for Python's `bytes` type."""
    type = bytes

    def serialize(self, serializer: Serializer, value: Any) -> None:
        assert isinstance(value, bytes)
        serializer.write_leb128_unsigned(len(value))
        serializer.write_bytes(value, max_bytes=MAX_BYTES_LENGTH)

    def deserialize(self, deserializer: Deserializer) -> Any:
        size = deserializer.read_leb128_unsigned()
        data = bytes(deserializer.read_bytes(size, max_bytes=MAX_BYTES_LENGTH))
        return bytes(data)


class BoundedInt(SingleValueField, ABC):
    """This is an abstract base class for Python's `int` type, with a specific size in bytes, and signed."""
    type = int
    size: int

    def serialize(self, serializer: Serializer, value: Any) -> None:
        assert isinstance(value, int)
        raw = int_to_bytes(number=value, size=self.size, signed=True)
        serializer.write_bytes(raw)

    def deserialize(self, deserializer: Deserializer) -> Any:
        raw = deserializer.read_bytes(self.size)
        return bytes_to_int(raw, signed=True)


class Int32Field(BoundedInt):
    """This is the field for Python's `int` type, with exactly 32 bits, and signed."""
    size = 4


class VarIntField(SingleValueField):
    """
    This is the field for Python's `int` type, with varying size, up to 256 bits, and signed.
    It uses LEB128 for encoding.
    """
    type = int

    def serialize(self, serializer: Serializer, value: Any) -> None:
        assert isinstance(value, int)
        serializer.write_leb128_signed(value, max_bytes=32)

    def deserialize(self, deserializer: Deserializer) -> Any:
        return deserializer.read_leb128_signed(max_bytes=32)


class AmountField(SingleValueField):
    """This is the field for Python's `int` type when representing an Amount, that is, an output value."""
    type = int

    def serialize(self, serializer: Serializer, value: Any) -> None:
        assert isinstance(value, int)
        serializer.write_output_value(value)

    def deserialize(self, deserializer: Deserializer) -> Any:
        return deserializer.read_output_value()


class BooleanField(SingleValueField):
    """This is the field for Python's `bool` type."""
    type = bool

    def serialize(self, serializer: Serializer, value: Any) -> None:
        assert isinstance(value, bool)
        serializer.write_byte(0x01 if value else 0x00)

    def deserialize(self, deserializer: Deserializer) -> Any:
        i = deserializer.read_byte()
        if i == 0:
            return False
        elif i == 1:
            return True
        else:
            raw = bytes([i])
            raise ValueError(f'{raw!r} is not a valid boolean')
