# Copyright 2021 Hathor Labs
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

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Optional

from structlog import get_logger

from hathor.indexes.addresses_index import AddressesIndex
from hathor.indexes.timestamp_index import TimestampIndex
from hathor.indexes.tips_index import TipsIndex
from hathor.indexes.tokens_index import TokensIndex
from hathor.transaction import BaseTransaction

if TYPE_CHECKING:  # pragma: no cover
    from hathor.pubsub import PubSubManager

logger = get_logger()


class IndexesManager(ABC):
    all_tips: 'TipsIndex'
    block_tips: 'TipsIndex'
    tx_tips: 'TipsIndex'

    sorted_all: 'TimestampIndex'
    sorted_blocks: 'TimestampIndex'
    sorted_txs: 'TimestampIndex'

    addresses: Optional['AddressesIndex']
    tokens: Optional['TokensIndex']

    @abstractmethod
    def enable_addresses_index(self, pubsub: 'PubSubManager') -> None:
        """Enable addresses index. It does nothing if it has already been enabled."""
        raise NotImplementedError

    @abstractmethod
    def enable_tokens_index(self) -> None:
        """Enable tokens index. It does nothing if it has already been enabled."""
        raise NotImplementedError

    @abstractmethod
    def add_tx(self, tx: BaseTransaction) -> bool:
        """Add a transaction to the indexes.

        :param tx: Transaction to be added
        """
        raise NotImplementedError

    @abstractmethod
    def del_tx(self, tx: BaseTransaction, *, remove_all: bool = False, relax_assert: bool = False) -> None:
        """ Delete a transaction from the indexes

        :param tx: Transaction to be deleted
        """
        raise NotImplementedError


class MemoryIndexesManager(IndexesManager):
    """ IndexesManager manages all the indexes that we will have in the system

        The ideia is for the manager to handle all method calls to indexes,
        so it will know which index is better to use in each moment
    """

    def __init__(self) -> None:
        self.all_tips = TipsIndex()
        self.block_tips = TipsIndex()
        self.tx_tips = TipsIndex()

        self.sorted_all = TimestampIndex()
        self.sorted_blocks = TimestampIndex()
        self.sorted_txs = TimestampIndex()

        self.addresses: Optional[AddressesIndex] = None
        self.tokens: Optional[TokensIndex] = None

    def enable_addresses_index(self, pubsub: 'PubSubManager') -> None:
        """Enable addresses index."""
        if self.addresses is None:
            self.addresses = AddressesIndex(pubsub)

    def enable_tokens_index(self) -> None:
        """Enable tokens index."""
        if self.tokens is None:
            self.tokens = TokensIndex()

    def add_tx(self, tx: BaseTransaction) -> bool:
        """ Add a transaction to the indexes

        :param tx: Transaction to be added
        """
        # These two calls return False when a transaction changes from
        # voided to executed and vice-versa.
        r1 = self.all_tips.add_tx(tx)
        r2 = self.sorted_all.add_tx(tx)
        assert r1 == r2

        if tx.is_block:
            r3 = self.block_tips.add_tx(tx)
            r4 = self.sorted_blocks.add_tx(tx)
            assert r3 == r4
        else:
            r3 = self.tx_tips.add_tx(tx)
            r4 = self.sorted_txs.add_tx(tx)
            assert r3 == r4

        if self.addresses:
            self.addresses.add_tx(tx)
        if self.tokens:
            self.tokens.add_tx(tx)

        return r3

    def del_tx(self, tx: BaseTransaction, *, remove_all: bool = False, relax_assert: bool = False) -> None:
        """ Delete a transaction from the indexes

        :param tx: Transaction to be deleted
        """
        if remove_all:
            # We delete from indexes in two cases: (i) mark tx as voided, and (ii) remove tx.
            # We only remove tx from all_tips and sorted_all when it is removed from the storage.
            # For clarity, when a tx is marked as voided, it is not removed from all_tips and sorted_all.
            self.all_tips.del_tx(tx, relax_assert=relax_assert)
            self.sorted_all.del_tx(tx)
            if self.addresses:
                self.addresses.remove_tx(tx)

        if tx.is_block:
            self.block_tips.del_tx(tx, relax_assert=relax_assert)
            self.sorted_blocks.del_tx(tx)
        else:
            self.tx_tips.del_tx(tx, relax_assert=relax_assert)
            self.sorted_txs.del_tx(tx)

        if self.tokens:
            self.tokens.del_tx(tx)
