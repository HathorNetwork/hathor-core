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

from abc import ABC, abstractmethod
from typing import Iterator, final

from typing_extensions import override

from hathor.indexes.base_index import BaseIndex
from hathor.transaction import BaseTransaction


class VertexTimestampIndex(BaseIndex, ABC):
    """This is an abstract index to easily sort a certain type of vertex by its timestamp."""
    # TODO: Update the TimestampIndex to use this abstraction. Maybe the TxGroupIndex could be adapted too.

    @final
    @override
    def init_loop_step(self, tx: BaseTransaction) -> None:
        self.add_tx(tx)

    @abstractmethod
    def _should_add(self, tx: BaseTransaction) -> bool:
        """Return whether a tx should be added to this index."""
        raise NotImplementedError

    @final
    def add_tx(self, tx: BaseTransaction) -> None:
        """Add a tx to this index."""
        if self._should_add(tx):
            self._add_tx(tx)

    @abstractmethod
    def _add_tx(self, tx: BaseTransaction) -> None:
        """Internal method to actually add a tx to this index."""
        raise NotImplementedError

    @abstractmethod
    def del_tx(self, tx: BaseTransaction) -> None:
        """Delete a tx from this index."""
        raise NotImplementedError

    @final
    def get_newest(self) -> Iterator[bytes]:
        """Get tx ids from newest to oldest."""
        return self._iter_sorted(tx_start=None, reverse=True)

    @final
    def get_oldest(self) -> Iterator[bytes]:
        """Get tx ids from oldest to newest."""
        return self._iter_sorted(tx_start=None, reverse=False)

    @final
    def get_older(self, *, tx_start: BaseTransaction, inclusive: bool = False) -> Iterator[bytes]:
        """
        Get tx ids sorted by timestamp that are older than `tx_start`.
        The `inclusive` param sets whether `tx_start` should be included.
        """
        return self._iter_sorted(tx_start=tx_start, reverse=True, inclusive=inclusive)

    @final
    def get_newer(self, *, tx_start: BaseTransaction, inclusive: bool = False) -> Iterator[bytes]:
        """
        Get tx ids sorted by timestamp that are newer than `tx_start`.
        The `inclusive` param sets whether `tx_start` should be included.
        """
        return self._iter_sorted(tx_start=tx_start, reverse=False, inclusive=inclusive)

    @abstractmethod
    def _iter_sorted(
        self,
        *,
        tx_start: BaseTransaction | None,
        reverse: bool,
        inclusive: bool = False,
    ) -> Iterator[bytes]:
        """
        Internal method to get all txs sorted by timestamp starting from an optional `tx_start`.
        The `inclusive` param sets whether `tx_start` should be included.
        """
        raise NotImplementedError
