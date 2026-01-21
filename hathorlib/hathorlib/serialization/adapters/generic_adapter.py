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

from types import TracebackType
from typing import Generic, TypeVar, Union

from typing_extensions import Self, override

from hathorlib.serialization.deserializer import Deserializer
from hathorlib.serialization.serializer import Serializer

from ..types import Buffer

S = TypeVar('S', bound=Serializer)
D = TypeVar('D', bound=Deserializer)


class GenericSerializerAdapter(Serializer, Generic[S]):
    inner: S

    def __init__(self, serializer: S) -> None:
        self.inner = serializer

    @override
    def finalize(self) -> Buffer:
        return self.inner.finalize()

    @override
    def cur_pos(self) -> int:
        return self.inner.cur_pos()

    @override
    def write_byte(self, data: int) -> None:
        self.inner.write_byte(data)

    @override
    def write_bytes(self, data: Buffer) -> None:
        self.inner.write_bytes(data)

    # allow using this adapter as a context manager:

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: Union[type[BaseException], None],
        exc_value: Union[BaseException, None],
        traceback: Union[TracebackType, None],
    ) -> None:
        pass


class GenericDeserializerAdapter(Deserializer, Generic[D]):
    inner: D

    def __init__(self, deserializer: D) -> None:
        self.inner = deserializer

    @override
    def finalize(self) -> None:
        return self.inner.finalize()

    @override
    def is_empty(self) -> bool:
        return self.inner.is_empty()

    @override
    def peek_byte(self) -> int:
        return self.inner.peek_byte()

    @override
    def peek_bytes(self, n: int, *, exact: bool = True) -> Buffer:
        return self.inner.peek_bytes(n, exact=exact)

    @override
    def read_byte(self) -> int:
        return self.inner.read_byte()

    @override
    def read_bytes(self, n: int, *, exact: bool = True) -> Buffer:
        return self.inner.read_bytes(n, exact=exact)

    @override
    def read_all(self) -> Buffer:
        return self.inner.read_all()

    # allow using this adapter as a context manager:

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: Union[type[BaseException], None],
        exc_value: Union[BaseException, None],
        traceback: Union[TracebackType, None],
    ) -> None:
        pass
