# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from types import TracebackType
from typing import Generic, TypeVar

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
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
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
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        pass
