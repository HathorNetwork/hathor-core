# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import Any, TypeVar

from typing_extensions import override

from hathor.nanocontracts.nc_types import NCType
from hathor.nanocontracts.storage import NCContractStorage
from hathor.nanocontracts.storage.types import _NOT_PROVIDED

T = TypeVar('T')
D = TypeVar('D')


class MockNCStorage(NCContractStorage):
    __slots__ = ('store',)

    def __init__(self) -> None:
        self.store: dict[bytes, Any] = {}

    @override
    def get_obj(self, key: bytes, value: NCType[T], *, default: D = _NOT_PROVIDED) -> T | D:
        if key in self.store:
            return self.store[key]
        if default is _NOT_PROVIDED:
            raise KeyError(key)
        return default

    @override
    def put_obj(self, key: bytes, value: NCType[T], data: T) -> None:
        self.store[key] = data

    @override
    def del_obj(self, key: bytes) -> None:
        del self.store[key]

    @override
    def has_obj(self, key: bytes) -> bool:
        return key in self.store
