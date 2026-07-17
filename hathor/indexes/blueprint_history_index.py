# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from abc import abstractmethod
from typing import Iterator

from hathor.indexes.scope import Scope
from hathor.indexes.tx_group_index import TxGroupIndex
from hathor.transaction import BaseTransaction, Transaction

SCOPE = Scope(
    include_blocks=False,
    include_txs=True,
    include_voided=True,
)


class BlueprintHistoryIndex(TxGroupIndex[bytes]):
    """Index of all Nano Contracts of a Blueprint."""

    def get_scope(self) -> Scope:
        return SCOPE

    def init_loop_step(self, tx: BaseTransaction) -> None:
        self.add_tx(tx)

    @abstractmethod
    def add_tx(self, tx: BaseTransaction) -> None:
        """Add tx to this index.
        """
        raise NotImplementedError

    @abstractmethod
    def remove_tx(self, tx: BaseTransaction) -> None:
        """Remove tx from this index.
        """
        raise NotImplementedError

    def _extract_keys(self, tx: BaseTransaction) -> Iterator[bytes]:
        if not tx.is_nano_contract():
            return
        assert isinstance(tx, Transaction)
        nano_header = tx.get_nano_header()
        if not nano_header.is_creating_a_new_contract():
            return
        yield nano_header.nc_id

    def get_newest(self, blueprint_id: bytes) -> Iterator[bytes]:
        """Get a list of nano_contract_ids sorted by timestamp for a given blueprint_id starting from the newest."""
        return self._get_sorted_from_key(blueprint_id, reverse=True)

    def get_oldest(self, blueprint_id: bytes) -> Iterator[bytes]:
        """Get a list of nano_contract_ids sorted by timestamp for a given blueprint_id starting from the oldest."""
        return self._get_sorted_from_key(blueprint_id)

    def get_older(self, blueprint_id: bytes, tx_start: BaseTransaction) -> Iterator[bytes]:
        """
        Get a list of nano_contract_ids sorted by timestamp for a given blueprint_id that are older than tx_start.
        """
        return self._get_sorted_from_key(blueprint_id, tx_start=tx_start, reverse=True)

    def get_newer(self, blueprint_id: bytes, tx_start: BaseTransaction) -> Iterator[bytes]:
        """
        Get a list of nano_contract_ids sorted by timestamp for a given blueprint_id that are newer than tx_start.
        """
        return self._get_sorted_from_key(blueprint_id, tx_start=tx_start)
