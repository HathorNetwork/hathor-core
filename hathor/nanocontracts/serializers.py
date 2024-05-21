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

from hathor.nanocontracts.exception import UnknownFieldType


class Serializer:
    """Serializers from Python's types to bytes."""

    def from_type(self, _type: Type[Any], value: Any) -> bytes:
        """Serialize from supported types."""
        from hathor.nanocontracts.fields import SingleValueField, get_field_class_for_attr
        field_class = get_field_class_for_attr(_type)
        if not issubclass(field_class, SingleValueField):
            raise UnknownFieldType(f'type not supported: {_type}')
        field = field_class.create_from_type('', _type)
        assert field.isinstance(value)
        return field.to_bytes(value)


class Deserializer:
    """Deserializer from bytes to Python's types."""

    def from_type(self, _type: Type[Any], raw: bytes) -> Any:
        """Deserialize supported types."""
        from hathor.nanocontracts.fields import SingleValueField, get_field_class_for_attr
        field_class = get_field_class_for_attr(_type)
        if not issubclass(field_class, SingleValueField):
            raise UnknownFieldType(f'type not supported: {_type}')
        field = field_class.create_from_type('', _type)
        value = field.to_python(raw)
        assert field.isinstance(value)
        return value
