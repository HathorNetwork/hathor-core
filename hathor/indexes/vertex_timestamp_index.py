# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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

    @final
    def manually_add_tx(self, tx: BaseTransaction) -> None:
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
