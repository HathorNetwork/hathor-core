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

from typing import Any

from typing_extensions import override

from hathor.nanocontracts.storage import NCStorage
from hathor.nanocontracts.storage.types import _NOT_PROVIDED


class MockNCStorage(NCStorage):
    __slots__ = ('store',)

    def __init__(self) -> None:
        self.store: dict[str, Any] = {}

    @override
    def get(self, key: str, default: Any = _NOT_PROVIDED) -> Any:
        if item := self.store.get(key, default):
            return item
        if default is _NOT_PROVIDED:
            raise KeyError
        return default

    @override
    def put(self, key: str, value: Any) -> None:
        self.store[key] = value

    @override
    def delete(self, key: str) -> None:
        del self.store[key]

    @override
    def contains(self, key: str) -> bool:
        return key in self.store
