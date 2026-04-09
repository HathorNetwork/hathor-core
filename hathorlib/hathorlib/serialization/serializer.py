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

from __future__ import annotations

import struct
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, TypeVar, overload

from typing_extensions import Self

from .types import Buffer

if TYPE_CHECKING:
    from .adapters import MaxBytesSerializer
    from .bytes_serializer import BytesSerializer

T = TypeVar('T')


class Serializer(ABC):
    def finalize(self) -> Buffer:
        """Get the resulting byte sequence, the serializer cannot be reused after this."""
        raise TypeError('this serializer does not support finalization')

    @abstractmethod
    def cur_pos(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def write_byte(self, data: int) -> None:
        """Write a single byte."""
        raise NotImplementedError

    @abstractmethod
    def write_bytes(self, data: Buffer) -> None:
        # XXX: it is recommended that implementors of Serializer specialize this implementation
        for byte in bytes(memoryview(data)):
            self.write_byte(byte)

    def write_struct(self, data: tuple[Any, ...], format: str) -> None:
        data_bytes = struct.pack(format, *data)
        self.write_bytes(data_bytes)

    def with_max_bytes(self, max_bytes: int) -> MaxBytesSerializer[Self]:
        """Helper method to wrap the current serializer with MaxBytesSerializer."""
        from .adapters import MaxBytesSerializer
        return MaxBytesSerializer(self, max_bytes)

    @overload
    def with_optional_max_bytes(self, max_bytes: None) -> Self:
        ...

    @overload
    def with_optional_max_bytes(self, max_bytes: int) -> MaxBytesSerializer[Self]:
        ...

    def with_optional_max_bytes(self, max_bytes: int | None) -> Self | MaxBytesSerializer[Self]:
        """Helper method to optionally wrap the current serializer."""
        if max_bytes is None:
            return self
        return self.with_max_bytes(max_bytes)

    @staticmethod
    def build_bytes_serializer() -> BytesSerializer:
        from .bytes_serializer import BytesSerializer
        return BytesSerializer()
