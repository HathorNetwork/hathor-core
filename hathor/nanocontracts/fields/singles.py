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
from hathor.transaction.base_transaction import bytes_to_output_value, output_value_to_bytes
from hathor.transaction.util import bytes_to_int, decode_string_utf8, int_to_bytes
from hathor.utils import leb128


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
        blueprint._storage.put(self.name, value)
        blueprint._cache[self.name] = value

    def __get__(self, blueprint, objtype):
        """Return the value from the storage."""
        if self.name in blueprint._cache:
            return blueprint._cache[self.name]

        try:
            value = blueprint._storage.get(self.name)
            blueprint._cache[self.name] = value
            return value
        except KeyError:
            raise NCAttributeError(f'Contract has no attribute \'{self.name}\'')


class StrField(SingleValueField):
    """This is the field for Python's `str` type."""
    type = str

    def to_bytes(self, value: Any) -> bytes:
        assert isinstance(value, str)
        return value.encode('utf-8')

    def to_python(self, raw: bytes) -> str:
        return decode_string_utf8(raw, 'str')


class BytesField(SingleValueField):
    """This is the field for Python's `bytes` type."""
    type = bytes

    def to_bytes(self, value: Any) -> bytes:
        assert isinstance(value, bytes)
        return value

    def to_python(self, raw: bytes) -> bytes:
        return raw


class BoundedInt(SingleValueField, ABC):
    """This is an abstract base class for Python's `int` type, with a specific size in bytes, and signed."""
    type = int
    size: int

    def to_bytes(self, value: Any) -> bytes:
        assert isinstance(value, int)
        return int_to_bytes(number=value, size=self.size, signed=True)

    def to_python(self, raw: bytes) -> int:
        return bytes_to_int(data=raw, signed=True)


class Int32Field(BoundedInt):
    """This is the field for Python's `int` type, with exactly 32 bits, and signed."""
    size = 4


class VarIntField(SingleValueField):
    """
    This is the field for Python's `int` type, with varying size, up to 256 bits, and signed.
    It uses LEB128 for encoding.
    """
    type = int

    def to_bytes(self, value: Any) -> bytes:
        assert isinstance(value, int)
        return leb128.encode_signed(value, max_bytes=32)

    def to_python(self, raw: bytes) -> int:
        value, buf = leb128.decode_signed(raw, max_bytes=32)
        assert len(buf) == 0  # TODO: this will be updated before mainnet
        return value


class AmountField(SingleValueField):
    """This is the field for Python's `int` type when representing an Amount, that is, an output value."""
    type = int

    def to_bytes(self, value: int) -> bytes:
        assert isinstance(value, int)
        return output_value_to_bytes(value)

    def to_python(self, raw: bytes) -> int:
        value, raw = bytes_to_output_value(raw)
        assert len(raw) == 0
        return value


class BooleanField(SingleValueField):
    """This is the field for Python's `bool` type."""
    type = bool

    def to_bytes(self, value: Any) -> bytes:
        assert isinstance(value, bool)
        return b'\x01' if value else b'\x00'

    def to_python(self, raw: bytes) -> bool:
        assert len(raw) == 1
        if raw == b'\x00':
            return False
        elif raw == b'\x01':
            return True
        else:
            raise ValueError(f'{raw!r} is not a valid boolean')
