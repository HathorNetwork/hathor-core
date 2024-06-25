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

import struct
from typing import Any, Type

from hathor.nanocontracts.exception import NCAttributeError
from hathor.nanocontracts.fields.base import Field
from hathor.transaction.util import decode_string_utf8, unpack


class SingleValueField(Field):
    """Base class for single-value fields."""
    type: Any

    def __init__(self, name: str) -> None:
        self.name = name

    @classmethod
    def create_from_type(cls, name: str, _type: Type[Any]) -> Field:
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


class IntegerField(SingleValueField):
    """This is the field for Python's `int` type."""
    type = int

    def to_bytes(self, value: Any) -> bytes:
        assert isinstance(value, int)
        return struct.pack('>l', value)

    def to_python(self, raw: bytes) -> int:
        (value,), raw = unpack('>l', raw)
        assert len(raw) == 0
        return value


class FloatField(SingleValueField):
    """This is the field for Python's `float` type."""
    type = (int, float)

    def to_bytes(self, value: Any) -> bytes:
        assert isinstance(value, (int, float))
        return struct.pack('>d', value)

    def to_python(self, raw: bytes) -> float:
        (value,), raw = unpack('>d', raw)
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
