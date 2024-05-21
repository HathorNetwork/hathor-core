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

from abc import ABC, abstractmethod
from typing import Any, Type

from typing_extensions import Self

from hathor.serialization import Deserializer, Serializer


class Field(ABC):
    __slots__ = ()

    def to_bytes(self, value: Any) -> bytes:
        """Serialize the `value` to bytes, useful for a oneshot conversion, otherwise use self.serializer."""
        from hathor.serialization import BytesSerializer
        serializer = BytesSerializer()
        self.serialize(serializer, value)
        return bytes(serializer.finalize())

    @abstractmethod
    def serialize(self, serializer: Serializer, value: Any) -> None:
        """Serialize the `value` to a serializer."""
        raise NotImplementedError

    @abstractmethod
    def deserialize(self, deserializer: Deserializer) -> Any:
        """Deserialize bytes in value from a buffer, only consume the relevant bytes."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def create_from_type(cls, name: str, _type: Type[Any]) -> Self:
        """Return a field object given a type."""
        raise NotImplementedError

    @abstractmethod
    def isinstance(self, value: Any) -> bool:
        """Check if value is instance of the type related to this field."""
        raise NotImplementedError
