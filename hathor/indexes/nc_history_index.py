# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from abc import abstractmethod
from typing import Iterable, Optional

from structlog import get_logger
from typing_extensions import override

from hathor.indexes.scope import Scope
from hathor.indexes.tx_group_index import TxGroupIndex
from hathor.transaction import BaseTransaction, Transaction

logger = get_logger()

SCOPE = Scope(
    include_blocks=False,
    include_txs=True,
    include_voided=True,
)


class NCHistoryIndex(TxGroupIndex[bytes]):
    """Index of all transactions of a Nano Contract."""

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

    @override
    def _extract_keys(self, tx: BaseTransaction) -> Iterable[bytes]:
        if not tx.is_nano_contract():
            return
        assert isinstance(tx, Transaction)
        nano_header = tx.get_nano_header()
        yield nano_header.get_contract_id()

    def get_sorted_from_contract_id(self, contract_id: bytes) -> Iterable[bytes]:
        """Get a list of tx_ids sorted by timestamp for a given contract_id.
        """
        return self._get_sorted_from_key(contract_id)

    def get_newest(self, contract_id: bytes) -> Iterable[bytes]:
        """Get a list of tx_ids sorted by timestamp for a given contract_id starting from the newest.
        """
        return self._get_sorted_from_key(contract_id, reverse=True)

    def get_oldest(self, contract_id: bytes) -> Iterable[bytes]:
        """Get a list of tx_ids sorted by timestamp for a given contract_id starting from the oldest.
        """
        return self._get_sorted_from_key(contract_id, reverse=False)

    def get_older(self, contract_id: bytes, tx_start: Optional[BaseTransaction] = None) -> Iterable[bytes]:
        """Get a list of tx_ids sorted by timestamp for a given contract_id that are older than tx_start.
        """
        return self._get_sorted_from_key(contract_id, tx_start=tx_start, reverse=True)

    def get_newer(self, contract_id: bytes, tx_start: Optional[BaseTransaction] = None) -> Iterable[bytes]:
        """Get a list of tx_ids sorted by timestamp for a given contract_id that are newer than tx_start.
        """
        return self._get_sorted_from_key(contract_id, tx_start=tx_start)

    @abstractmethod
    def get_transaction_count(self, contract_id: bytes) -> int:
        """Get the count of transactions for the given contract_id."""
        raise NotImplementedError

    def get_last_tx_timestamp(self, contract_id: bytes) -> int | None:
        """Get the timestamp of the last tx in the given contract_id, or None if it doesn't exist."""
        return self.get_latest_tx_timestamp(contract_id)
