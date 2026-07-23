# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hathorlib.base_transaction import BaseTransaction


class VertexBaseHeader(ABC):
    @classmethod
    @abstractmethod
    def deserialize(cls, tx: BaseTransaction, buf: bytes) -> tuple[VertexBaseHeader, bytes]:
        """Deserialize header from `buf` which starts with header id."""
        raise NotImplementedError

    @abstractmethod
    def serialize(self) -> bytes:
        """Serialize header with header id as prefix."""
        raise NotImplementedError

    @abstractmethod
    def get_sighash_bytes(self) -> bytes:
        """Return sighash bytes to check digital signatures."""
        raise NotImplementedError
