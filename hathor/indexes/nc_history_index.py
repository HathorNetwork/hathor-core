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

from abc import abstractmethod
from typing import Iterable, Optional

from structlog import get_logger

from hathor.indexes.scope import Scope
from hathor.indexes.tx_group_index import TxGroupIndex
from hathor.transaction import BaseTransaction

logger = get_logger()

SCOPE = Scope(
    include_blocks=False,
    include_txs=True,
    include_voided=True,
)


class NCHistoryIndex(TxGroupIndex[str]):
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

    @abstractmethod
    def get_sorted_from_contract_id(self, contract_id: bytes) -> Iterable[bytes]:
        """Get a list of tx_ids sorted by timestamp for a given contract_id.
        """
        raise NotImplementedError

    def get_newest(self, contract_id: bytes) -> Iterable[bytes]:
        """Get a list of tx_ids sorted by timestamp for a given contract_id starting from the newest.
        """
        raise NotImplementedError

    def get_older(self, contract_id: bytes, tx_start: Optional[BaseTransaction] = None) -> Iterable[bytes]:
        """Get a list of tx_ids sorted by timestamp for a given contract_id that are older than tx_start.
        """
        raise NotImplementedError

    def get_newer(self, contract_id: bytes, tx_start: Optional[BaseTransaction] = None) -> Iterable[bytes]:
        """Get a list of tx_ids sorted by timestamp for a given contract_id that are newer than tx_start.
        """
        raise NotImplementedError
