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

from typing import Any, Type, Union, get_args, get_origin

from typing_extensions import Self

from hathor.nanocontracts.fields.base import Field
from hathor.nanocontracts.fields.singles import SingleValueField
from hathor.nanocontracts.types import SignedData
from hathor.serialization import Deserializer, Serializer


class OptionalField(SingleValueField):
    def __init__(self, name: str, field: Field) -> None:
        self.name = name
        self.field = field

    @classmethod
    def create_from_type(cls, name: str, type_: Type[Any]) -> Self:
        from hathor.nanocontracts.fields import get_field_for_attr

        origin = get_origin(type_)
        assert origin is Union

        args = get_args(type_)
        assert len(args) == 2
        subtype = args[0]
        if subtype is type(None):
            subtype = args[1]
        assert subtype is not type(None)
        field = get_field_for_attr('', subtype)
        return cls(name, field)

    def isinstance(self, value: Any) -> bool:
        if value is None:
            return True
        elif self.field.isinstance(value):
            return True
        return False

    def serialize(self, serializer: Serializer, value: Any) -> None:
        if value is None:
            serializer.write_byte(0x00)
        else:
            serializer.write_byte(0x01)
            self.field.serialize(serializer, value)

    def deserialize(self, deserializer: Deserializer) -> Any:
        b = deserializer.read_byte()
        if b == 0:
            return None
        else:
            assert b == 1
        return self.field.deserialize(deserializer)


class SignedDataField(SingleValueField):
    def __init__(self, name: str, field: Field) -> None:
        self.name = name
        self.field = field

    @classmethod
    def create_from_type(cls, name: str, type_: Type[Any]) -> Self:
        from hathor.nanocontracts.fields import get_field_for_attr

        args = get_args(type_)
        assert len(args) == 1
        subtype = args[0]
        field = get_field_for_attr('', subtype)
        return cls(name, field)

    def isinstance(self, value: Any) -> bool:
        if not isinstance(value, SignedData):
            return False
        if not self.field.isinstance(value.data):
            return False
        return True

    def serialize(self, serializer: Serializer, value: Any) -> None:
        assert self.isinstance(value)
        from hathor.nanocontracts.fields import BytesField
        self.field.serialize(serializer, value.data)
        BytesField('').serialize(serializer, value.script_input)

    def deserialize(self, deserializer: Deserializer) -> Any:
        from hathor.nanocontracts.fields import BytesField
        data = self.field.deserialize(deserializer)
        script_input = BytesField('').deserialize(deserializer)
        return SignedData(data, script_input)


class TupleField(SingleValueField):
    def __init__(self, name: str, fields: list[Field]) -> None:
        self.name = name
        self.fields = fields

    @classmethod
    def create_from_type(cls, name: str, type_: Type[Any]) -> Self:
        from hathor.nanocontracts.fields import get_field_for_attr

        origin = get_origin(type_)
        assert origin is tuple

        args = get_args(type_)
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

    def serialize(self, serializer: Serializer, value: Any) -> None:
        assert self.isinstance(value)
        for field, individual_value in zip(self.fields, value):
            field.serialize(serializer, individual_value)

    def deserialize(self, deserializer: Deserializer) -> Any:
        return tuple(field.deserialize(deserializer) for field in self.fields)
