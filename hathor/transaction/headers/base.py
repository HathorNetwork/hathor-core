# Copyright 2023 Hathor Labs
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

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

from hathor.transaction.util import VerboseCallback

if TYPE_CHECKING:
    from hathor.transaction.base_transaction import BaseTransaction


class VertexBaseHeader(ABC):
    @classmethod
    @abstractmethod
    def get_header_id(cls) -> bytes:
        """Return the 1-byte header ID for this header type."""
        raise NotImplementedError

    @classmethod
    @abstractmethod
    def deserialize(
        cls,
        tx: BaseTransaction,
        buf: bytes,
        *,
        verbose: VerboseCallback = None
    ) -> tuple[VertexBaseHeader, bytes]:
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
