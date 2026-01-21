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

from typing_extensions import override

from .serializer import Serializer
from .types import Buffer


class BytesSerializer(Serializer):
    """Simple implementation of Serializer to write to memory.

    This implementation defers joining everything until finalize is called, before that every write is stored as a
    memoryview in a list.
    """

    def __init__(self) -> None:
        self._parts: list[memoryview] = []
        self._pos: int = 0

    @override
    def finalize(self) -> memoryview:
        result = memoryview(b''.join(self._parts))
        del self._parts
        del self._pos
        return result

    @override
    def cur_pos(self) -> int:
        return self._pos

    @override
    def write_byte(self, data: int) -> None:
        # int.to_bytes checks for correct range
        self._parts.append(memoryview(int.to_bytes(data, length=1, byteorder='big')))
        self._pos += 1

    @override
    def write_bytes(self, data: Buffer) -> None:
        part = memoryview(data)
        self._parts.append(part)
        self._pos += len(part)
