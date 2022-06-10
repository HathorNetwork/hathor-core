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
from typing import Any, Optional, Type, Union, get_args, get_origin

from hathor.nanocontracts.fields.base import Field
from hathor.nanocontracts.fields.singles import SingleValueField
from hathor.nanocontracts.types import SignedData
from hathor.transaction.util import unpack


def to_n(raw: bytes) -> tuple[int, bytes]:
    (n,), raw = unpack('!H', raw)
    return n, raw


def from_n(n: int) -> bytes:
    return struct.pack('!H', n)


class OptionalField(SingleValueField):
    def __init__(self, name: str, field: Field) -> None:
        self.name = name
        self.field = field

    @classmethod
    def create_from_type(cls, name: str, _type: Type[Any]) -> Field:
        from hathor.nanocontracts.fields import get_field_for_attr

        origin = get_origin(_type)
        assert origin is Union

        args = get_args(_type)
        assert len(args) == 2
        subtype = args[0]
        if isinstance(None, subtype):
            subtype = args[1]
        assert not isinstance(None, subtype)
        field = get_field_for_attr('', subtype)
        return cls(name, field)

    def isinstance(self, value: Any) -> bool:
        if value is None:
            return True
        elif self.field.isinstance(value):
            return True
        return False

    def to_bytes(self, value: Any) -> bytes:
        if value is None:
            return b'\x00'
        return b'\x01' + self.field.to_bytes(value)

    def to_python(self, raw: bytes) -> Optional[Any]:
        assert len(raw) > 0
        if raw.startswith(b'\x00'):
            assert len(raw) == 1
            return None
        assert raw.startswith(b'\x01')
        return self.field.to_python(raw[1:])


class SignedDataField(SingleValueField):
    def __init__(self, name: str, field: Field) -> None:
        self.name = name
        self.field = field

    @classmethod
    def create_from_type(cls, name: str, _type: Type[Any]) -> Field:
        from hathor.nanocontracts.fields import get_field_for_attr

        args = get_args(_type)
        assert len(args) == 1
        subtype = args[0]
        field = get_field_for_attr('', subtype)
        return cls(name, field)

    def isinstance(self, signed_value: Any) -> bool:
        if not isinstance(signed_value, SignedData):
            return False
        if not self.field.isinstance(signed_value.data):
            return False
        return True

    def to_bytes(self, signed_value: Any) -> bytes:
        assert self.isinstance(signed_value)
        from hathor.nanocontracts.fields import BytesField
        data_bytes = self.field.to_bytes(signed_value.data)
        script_input_bytes = BytesField('').to_bytes(signed_value.script_input)
        return from_n(len(data_bytes)) + data_bytes + script_input_bytes

    def to_python(self, raw: bytes) -> Optional[Any]:
        from hathor.nanocontracts.fields import BytesField
        n, raw = to_n(raw)
        data = self.field.to_python(raw[:n])
        script_input = BytesField('').to_python(raw[n:])
        return SignedData(data, script_input)


class TupleField(SingleValueField):
    def __init__(self, name: str, fields: list[Field]) -> None:
        self.name = name
        self.fields = fields

    @classmethod
    def create_from_type(cls, name: str, _type: Type[Any]) -> Field:
        from hathor.nanocontracts.fields import get_field_for_attr

        origin = get_origin(_type)
        assert origin is tuple

        args = get_args(_type)
        fields = []
        for subtype in args:
            fields.append(get_field_for_attr('', subtype))
        return cls(name, fields)

    def isinstance(self, values: Any) -> bool:
        if not isinstance(values, tuple):
            return False
        if len(values) != len(self.fields):
            return False
        for field, x in zip(self.fields, values):
            if not field.isinstance(x):
                return False
        return True

    def to_bytes(self, values: Any) -> bytes:
        assert self.isinstance(values)
        ret = []
        for field, x in zip(self.fields, values):
            x_bytes = field.to_bytes(x)
            ret.append(from_n(len(x_bytes)))
            ret.append(x_bytes)
        return b''.join(ret)

    def to_python(self, raw: bytes) -> Optional[Any]:
        ret = []
        for field in self.fields:
            x_len, raw = to_n(raw)
            ret.append(field.to_python(raw[:x_len]))
            raw = raw[x_len:]
        return tuple(ret)
