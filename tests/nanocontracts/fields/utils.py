#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

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
