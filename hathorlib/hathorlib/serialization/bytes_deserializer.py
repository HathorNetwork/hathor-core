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

from .deserializer import Deserializer
from .exceptions import OutOfDataError
from .types import Buffer

_EMPTY_VIEW = memoryview(b'')


class BytesDeserializer(Deserializer):
    """Simple implementation of a Deserializer to parse values from a byte sequence.

    This implementation maintains a memoryview that is shortened as the bytes are read.
    """

    def __init__(self, data: Buffer) -> None:
        self._view = memoryview(data)

    @override
    def finalize(self) -> None:
        if not self.is_empty():
            raise ValueError('trailing data')
        del self._view

    @override
    def is_empty(self) -> bool:
        # XXX: least amount of OPs, "not" converts to bool with the correct semantics of "is empty"
        return not self._view

    @override
    def peek_byte(self) -> int:
        if not len(self._view):
            raise OutOfDataError('not enough bytes to read')
        return self._view[0]

    @override
    def peek_bytes(self, n: int, *, exact: bool = True) -> memoryview:
        if n < 0:
            raise ValueError('value cannot be negative')
        if exact and len(self._view) < n:
            raise OutOfDataError('not enough bytes to read')
        return self._view[:n]

    @override
    def read_byte(self) -> int:
        b = self.peek_byte()
        self._view = self._view[1:]
        return b

    @override
    def read_bytes(self, n: int, *, exact: bool = True) -> memoryview:
        b = self.peek_bytes(n, exact=exact)
        if exact and len(self._view) < n:
            raise OutOfDataError('not enough bytes to read')
        self._view = self._view[n:]
        return b

    @override
    def read_all(self) -> memoryview:
        b = self._view
        self._view = _EMPTY_VIEW
        return b
