# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
