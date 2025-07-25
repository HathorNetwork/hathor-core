# Copyright 2022 Hathor Labs
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
from enum import Enum

from intervaltree import Interval
from structlog import get_logger

from hathor.conf.settings import HathorSettings
from hathor.indexes.base_index import BaseIndex
from hathor.indexes.scope import Scope
from hathor.transaction import BaseTransaction

logger = get_logger()


class ScopeType(Enum):
    ALL = Scope(
        include_blocks=True,
        include_txs=True,
        include_voided=True,
    )
    TXS = Scope(
        include_blocks=False,
        include_txs=True,
        include_voided=False,
    )
    BLOCKS = Scope(
        include_blocks=True,
        include_txs=False,
        include_voided=True,
    )

    def get_name(self) -> str:
        return self.name.lower()


class TipsIndex(BaseIndex):
    """ Use an interval tree to quick get the tips at a given timestamp.

    The interval of a transaction is in the form [begin, end), where `begin` is
    the transaction's timestamp, and `end` is when it was first verified by another
    transaction.

    If a transaction is still a tip, `end` is equal to infinity.

    If a transaction has been verified many times, `end` is equal to `min(tx.timestamp)`.

    TODO Use an interval tree stored in disk, possibly using a B-tree.
    """

    def __init__(self, *, scope_type: ScopeType, settings: HathorSettings) -> None:
        super().__init__(settings=settings)
        self._scope_type = scope_type

    def get_scope(self) -> Scope:
        return self._scope_type.value

    @abstractmethod
    def add_tx(self, tx: BaseTransaction) -> bool:
        """ Add a new transaction to the index

        :param tx: Transaction to be added
        """
        raise NotImplementedError

    @abstractmethod
    def del_tx(self, tx: BaseTransaction, *, relax_assert: bool = False) -> None:
        """ Remove a transaction from the index.
        """
        raise NotImplementedError

    @abstractmethod
    def update_tx(self, tx: BaseTransaction, *, relax_assert: bool = False) -> None:
        """ Update a tx according to its children.
        """
        raise NotImplementedError

    @abstractmethod
    def __getitem__(self, index: float) -> set[Interval]:
        raise NotImplementedError
