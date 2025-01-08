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

from abc import abstractmethod
from enum import Enum
from typing import Iterator, NamedTuple

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


class RangeIdx(NamedTuple):
    timestamp: int
    offset: int


class TimestampIndex(BaseIndex):
    """ Index of transactions sorted by their timestamps.
    """

    def __init__(self, *, scope_type: ScopeType, settings: HathorSettings) -> None:
        super().__init__(settings=settings)
        self._scope_type = scope_type

    def get_scope(self) -> Scope:
        return self._scope_type.value

    def init_loop_step(self, tx: BaseTransaction) -> None:
        self.add_tx(tx)

    @abstractmethod
    def add_tx(self, tx: BaseTransaction) -> bool:
        """ Add a transaction to the index

        :param tx: Transaction to be added
        :return: Whether the key was new to the index. True means we just added it, False means it was already here.
        """
        raise NotImplementedError

    @abstractmethod
    def del_tx(self, tx: BaseTransaction) -> None:
        """ Delete a transaction from the index

        :param tx: Transaction to be deleted
        """
        raise NotImplementedError

    @abstractmethod
    def get_newest(self, count: int) -> tuple[list[bytes], bool]:
        """ Get transactions or blocks from the newest to the oldest

        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        raise NotImplementedError

    @abstractmethod
    def get_older(self, timestamp: int, hash_bytes: bytes | None, count: int) -> tuple[list[bytes], bool]:
        """ Get transactions or blocks from the timestamp/hash_bytes reference to the oldest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        raise NotImplementedError

    @abstractmethod
    def get_newer(self, timestamp: int, hash_bytes: bytes | None, count: int) -> tuple[list[bytes], bool]:
        """ Get transactions or blocks from the timestamp/hash_bytes reference to the newest

        :param timestamp: Timestamp reference to start the search
        :param hash_bytes: Hash reference to start the search
        :param count: Number of transactions or blocks to be returned
        :return: List of tx hashes and a boolean indicating if has more txs
        """
        raise NotImplementedError

    @abstractmethod
    def iter(self) -> Iterator[bytes]:
        """ Iterate over the transactions in the index order, that is, sorted by timestamp.
        """
        raise NotImplementedError

    @abstractmethod
    def __contains__(self, elem: tuple[int, bytes]) -> bool:
        """ Returns whether the pair (timestamp, hash) is present in the index.
        """
        raise NotImplementedError
