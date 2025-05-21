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
from typing import Generic, Iterable, Iterator, Optional, Sized, TypeVar

from structlog import get_logger

from hathor.indexes.base_index import BaseIndex
from hathor.transaction import BaseTransaction

logger = get_logger()

KT = TypeVar('KT', bound=Sized)


class TxGroupIndex(BaseIndex, Generic[KT]):
    """This is an abstract index to easily group transactions by key. Each transaction might belong to
    more than one group. For example, when grouped by addresses, one transaction with five different
    addresses would be added to five groups.

    Implementations using this index must extract a list of keys from each transaction.
    """

    @abstractmethod
    def add_tx(self, tx: BaseTransaction) -> None:
        """Add tx to this index."""
        raise NotImplementedError

    @abstractmethod
    def remove_tx(self, tx: BaseTransaction) -> None:
        """Remove tx from this index."""
        raise NotImplementedError

    @abstractmethod
    def _extract_keys(self, tx: BaseTransaction) -> Iterable[KT]:
        """Extract the keys related to a given tx. The transaction will be added to all extracted keys."""
        raise NotImplementedError

    @abstractmethod
    def _get_sorted_from_key(self,
                             key: KT,
                             tx_start: Optional[BaseTransaction] = None,
                             reverse: bool = False) -> Iterator[bytes]:
        """Get all transactions that have a given key, sorted by timestamp.

        `tx_start` serves as a pagination marker, indicating the starting position for the iteration.
        When tx_start is None, the iteration begins from the initial element.

        `reverse` is used to get the list in the reverse order
        """
        raise NotImplementedError

    @abstractmethod
    def _is_key_empty(self, key: KT) -> bool:
        """Check whether a key is empty."""
        raise NotImplementedError

    @abstractmethod
    def get_latest_tx_timestamp(self, key: KT) -> int | None:
        """Get the timestamp of the latest tx in the given key, or None if the key is not found."""
        raise NotImplementedError

    @abstractmethod
    def add_single_key(self, key: KT, tx: BaseTransaction) -> None:
        """Add a single key to the index."""
        raise NotImplementedError

    @abstractmethod
    def remove_single_key(self, key: KT, tx: BaseTransaction) -> None:
        """Remove a single key from the index."""
        raise NotImplementedError
