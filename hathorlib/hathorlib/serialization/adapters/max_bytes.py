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

from typing import TypeVar

from typing_extensions import override

from hathorlib.serialization.deserializer import Deserializer
from hathorlib.serialization.exceptions import SerializationError
from hathorlib.serialization.serializer import Serializer

from ..types import Buffer
from .generic_adapter import GenericDeserializerAdapter, GenericSerializerAdapter

S = TypeVar('S', bound=Serializer)
D = TypeVar('D', bound=Deserializer)


class MaxBytesExceededError(SerializationError):
    """ This error is raised when the adapted serializer reached its maximum bytes write/read.

    After this exception is raised the adapted serializer cannot be used anymore. Handlers of this exception are
    expected to either: bubble up the exception (or an equivalente exception), or return an error. Handlers should not
    try to write again on the same serializer.

    It is possible that the inner serializer is still usable, but the point where the serialized stopped writing or
    reading might leave the rest of the data unusable, so for that reason it should be considered a failed
    (de)serialization overall, and not simply a failed "read/write" operation.
    """
    pass


class MaxBytesSerializer(GenericSerializerAdapter[S]):
    def __init__(self, serializer: S, max_bytes: int) -> None:
        super().__init__(serializer)
        self._bytes_left = max_bytes

    def _check_update_exceeds(self, write_size: int) -> None:
        self._bytes_left -= write_size
        if self._bytes_left < 0:
            raise MaxBytesExceededError

    @override
    def write_byte(self, data: int) -> None:
        self._check_update_exceeds(1)
        super().write_byte(data)

    @override
    def write_bytes(self, data: Buffer) -> None:
        data_view = memoryview(data)
        self._check_update_exceeds(len(data_view))
        super().write_bytes(data_view)


class MaxBytesDeserializer(GenericDeserializerAdapter[D]):
    def __init__(self, deserializer: D, max_bytes: int) -> None:
        super().__init__(deserializer)
        self._bytes_left = max_bytes

    def _check_update_exceeds(self, read_size: int) -> None:
        self._bytes_left -= read_size
        if self._bytes_left < 0:
            raise MaxBytesExceededError

    @override
    def read_byte(self) -> int:
        self._check_update_exceeds(1)
        return super().read_byte()

    @override
    def read_bytes(self, n: int, *, exact: bool = True) -> Buffer:
        self._check_update_exceeds(n)
        return super().read_bytes(n, exact=exact)

    @override
    def read_all(self) -> Buffer:
        result = super().read_bytes(self._bytes_left, exact=False)
        if not self.is_empty():
            raise MaxBytesExceededError
        return result
