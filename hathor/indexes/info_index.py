# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from abc import abstractmethod

from structlog import get_logger

from hathor.indexes.base_index import BaseIndex
from hathor.indexes.scope import Scope
from hathor.transaction import BaseTransaction

logger = get_logger()

SCOPE = Scope(
    include_blocks=True,
    include_txs=True,
    include_voided=True,
    # XXX: this index doesn't care about the ordering
    topological_order=False,
)


class InfoIndex(BaseIndex):
    """ Index of general information about the storage
    """

    def init_loop_step(self, tx: BaseTransaction) -> None:
        self.update_timestamps(tx)
        self.update_counts(tx)

    def get_scope(self) -> Scope:
        return SCOPE

    @abstractmethod
    def update_timestamps(self, tx: BaseTransaction) -> None:
        raise NotImplementedError

    @abstractmethod
    def update_counts(self, tx: BaseTransaction, *, remove: bool = False) -> None:
        raise NotImplementedError

    @abstractmethod
    def get_block_count(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def get_tx_count(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def get_vertices_count(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def get_latest_timestamp(self) -> int:
        raise NotImplementedError

    @abstractmethod
    def get_first_timestamp(self) -> int:
        raise NotImplementedError
