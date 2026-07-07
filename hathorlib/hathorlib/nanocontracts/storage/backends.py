# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hathorlib.nanocontracts.storage.patricia_trie import Node


class NodeTrieStore(ABC):
    @abstractmethod
    def __getitem__(self, key: bytes) -> Node:
        raise NotImplementedError

    @abstractmethod
    def __setitem__(self, key: bytes, item: Node) -> None:
        raise NotImplementedError

    @abstractmethod
    def __len__(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def __contains__(self, key: bytes) -> bool:
        raise NotImplementedError
