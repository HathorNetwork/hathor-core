# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
