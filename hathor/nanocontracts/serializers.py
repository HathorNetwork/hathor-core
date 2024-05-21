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

from typing import Any, Type

from hathor import serialization
from hathor.nanocontracts.exception import UnknownFieldType


class Serializer:
    """Serializers from Python's types to bytes."""

    # TODO: compatibility method, refactor out
    def from_type(self, type_: Type[Any], value: Any) -> bytes:
        """Serialize the given value as the given type and return the resulting bytes."""
        se = serialization.BytesSerializer()
        self.serialize_type(type_, value, se)
        return bytes(se.finalize())

    def serialize_type(self, type_: Type[Any], value: Any, serializer: serialization.Serializer) -> None:
        """ Serialize the given value as the given type and write the result into the given buffer.

        The only observable effect on the buffer is the addition of the serialized bytes.
        """
        from hathor.nanocontracts.fields import SingleValueField, get_field_class_for_attr
        field_class = get_field_class_for_attr(type_)
        if not issubclass(field_class, SingleValueField):
            raise UnknownFieldType(f'type not supported: {type_}')
        field = field_class.create_from_type('', type_)
        assert field.isinstance(value)
        field.serialize(serializer, value)


class Deserializer:
    """Deserializer from bytes to Python's types."""

    # TODO: compatibility method, refactor out
    def from_type(self, type_: Type[Any], raw: bytes) -> Any:
        """Deserialize a given type from the given bytes and return the value."""
        de = serialization.BytesDeserializer(raw)
        value = self.deserialize_type(type_, de)
        # XXX: all bytes must be consumed
        if not de.is_empty():
            raise ValueError('unexpected extra bytes')
        return value

    def deserialize_type(self, type_: Type[Any], deserializer: serialization.Deserializer) -> Any:
        """Deserialize a given type from the given buffer and return the value.

        The effect on the buffer is consuming only the serialized bytes.
        """
        from hathor.nanocontracts.fields import SingleValueField, get_field_class_for_attr
        field_class = get_field_class_for_attr(type_)
        if not issubclass(field_class, SingleValueField):
            raise UnknownFieldType(f'type not supported: {type_}')
        field = field_class.create_from_type('', type_)
        value = field.deserialize(deserializer)
        assert field.isinstance(value)
        return value
