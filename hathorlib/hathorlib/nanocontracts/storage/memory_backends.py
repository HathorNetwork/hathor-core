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

from typing import TYPE_CHECKING

from typing_extensions import override

from hathorlib.nanocontracts.storage.backends import NodeTrieStore

if TYPE_CHECKING:
    from hathorlib.nanocontracts.storage.patricia_trie import Node


class InMemoryNodeTrieStore(NodeTrieStore):
    """In-memory implementation of NodeTrieStore for testing and simulation."""

    def __init__(self) -> None:
        self._store: dict[bytes, Node] = {}

    @override
    def __getitem__(self, key: bytes) -> Node:
        try:
            return self._store[key]
        except KeyError:
            raise KeyError(key.hex())

    @override
    def __setitem__(self, key: bytes, item: Node) -> None:
        self._store[key] = item

    @override
    def __len__(self) -> int:
        return len(self._store)

    @override
    def __contains__(self, key: bytes) -> bool:
        return key in self._store
