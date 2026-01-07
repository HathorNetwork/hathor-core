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
from typing import TYPE_CHECKING, Any, Iterator, TypeVar, overload

from typing_extensions import Self

from .types import Buffer

if TYPE_CHECKING:
    from .adapters import MaxBytesDeserializer
    from .bytes_deserializer import BytesDeserializer

T = TypeVar('T')


class Deserializer(ABC):
    def finalize(self) -> None:
        """Check that all bytes were consumed, the deserializer cannot be used after this."""
        raise TypeError('this deserializer does not support finalization')

    @staticmethod
    def build_bytes_deserializer(data: Buffer) -> BytesDeserializer:
        from .bytes_deserializer import BytesDeserializer
        return BytesDeserializer(data)

    @abstractmethod
    def is_empty(self) -> bool:
        raise NotImplementedError

    @abstractmethod
    def peek_byte(self) -> int:
        """Read a single byte but don't consume from buffer."""
        raise NotImplementedError

    @abstractmethod
    def peek_bytes(self, n: int, *, exact: bool = True) -> Buffer:
        """Read n single byte but don't consume from buffer."""
        raise NotImplementedError

    def peek_struct(self, format: str) -> tuple[Any, ...]:
        size = struct.calcsize(format)
        data = self.peek_bytes(size)
        return struct.unpack(format, data)

    @abstractmethod
    def read_byte(self) -> int:
        """Read a single byte as unsigned int."""
        raise NotImplementedError

    @abstractmethod
    def read_bytes(self, n: int, *, exact: bool = True) -> Buffer:
        """Read n bytes, when exact=True it errors if there isn't enough data"""
        # XXX: this is a blanket implementation that is an example of the behavior, this implementation has to be
        #      explicitly used if needed
        def iter_bytes() -> Iterator[int]:
            for _ in range(n):
                if not exact and self.is_empty():
                    break
                yield self.read_byte()
        return bytes(iter_bytes())

    @abstractmethod
    def read_all(self) -> Buffer:
        """Read all bytes until the reader is empty."""
        # XXX: it is recommended that implementors of Deserializer specialize this implementation
        def iter_bytes() -> Iterator[int]:
            while not self.is_empty():
                yield self.read_byte()
        return bytes(iter_bytes())

    def read_struct(self, format: str) -> tuple[Any, ...]:
        size = struct.calcsize(format)
        data = self.read_bytes(size)
        return struct.unpack_from(format, data)

    def with_max_bytes(self, max_bytes: int) -> MaxBytesDeserializer[Self]:
        """Helper method to wrap the current deserializer with MaxBytesDeserializer."""
        from .adapters import MaxBytesDeserializer
        return MaxBytesDeserializer(self, max_bytes)

    @overload
    def with_optional_max_bytes(self, max_bytes: None) -> Self:
        ...

    @overload
    def with_optional_max_bytes(self, max_bytes: int) -> MaxBytesDeserializer[Self]:
        ...

    def with_optional_max_bytes(self, max_bytes: int | None) -> Self | MaxBytesDeserializer[Self]:
        """Helper method to optionally wrap the current deserializer."""
        if max_bytes is None:
            return self
        return self.with_max_bytes(max_bytes)
