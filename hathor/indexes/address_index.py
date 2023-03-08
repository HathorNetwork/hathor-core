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
from typing import TYPE_CHECKING, Iterable, List, Optional

from structlog import get_logger

from hathor.indexes.scope import Scope
from hathor.indexes.tx_group_index import TxGroupIndex
from hathor.pubsub import HathorEvents
from hathor.transaction import BaseTransaction

if TYPE_CHECKING:  # pragma: no cover
    from hathor.pubsub import EventArguments, PubSubManager

logger = get_logger()

SCOPE = Scope(
    include_blocks=True,
    include_txs=True,
    include_voided=True,
)


class AddressIndex(TxGroupIndex[str]):
    """ Index of inputs/outputs by address
    """
    pubsub: Optional['PubSubManager']

    def get_scope(self) -> Scope:
        return SCOPE

    def init_loop_step(self, tx: BaseTransaction) -> None:
        self.add_tx(tx)

    def _handle_tx_event(self, key: HathorEvents, args: 'EventArguments') -> None:
        """ This method is called when pubsub publishes an event that we subscribed
        """
        data = args.__dict__
        tx = data['tx']
        meta = tx.get_metadata()
        if meta.has_voided_by_changed_since_last_call() or meta.has_spent_by_changed_since_last_call():
            self._publish_tx(tx)

    def _subscribe_pubsub_events(self) -> None:
        """ Subscribe wallet index to receive voided/winner tx pubsub events
        """
        assert self.pubsub is not None
        # Subscribe to voided/winner events
        self.pubsub.subscribe(HathorEvents.CONSENSUS_TX_UPDATE, self._handle_tx_event)

    def _publish_tx(self, tx: BaseTransaction, *, addresses: Optional[Iterable[str]] = None) -> None:
        """ Publish WALLET_ADDRESS_HISTORY for all addresses of a transaction.
        """
        from hathor.pubsub import HathorEvents
        if not self.pubsub:
            return
        if addresses is None:
            addresses = tx.get_related_addresses()
        data = tx.to_json_extended()
        for address in addresses:
            self.pubsub.publish(HathorEvents.WALLET_ADDRESS_HISTORY, address=address, history=data)

    @abstractmethod
    def add_tx(self, tx: BaseTransaction) -> None:
        """ Add tx inputs and outputs to the wallet index (indexed by its addresses).
        """
        raise NotImplementedError

    @abstractmethod
    def remove_tx(self, tx: BaseTransaction) -> None:
        """ Remove tx inputs and outputs from the wallet index (indexed by its addresses).
        """
        raise NotImplementedError

    @abstractmethod
    def get_from_address(self, address: str) -> List[bytes]:
        """ Get list of transaction hashes of an address
        """
        raise NotImplementedError

    @abstractmethod
    def get_sorted_from_address(self, address: str) -> List[bytes]:
        """ Get a sorted list of transaction hashes of an address
        """
        raise NotImplementedError

    @abstractmethod
    def is_address_empty(self, address: str) -> bool:
        """Check whether address has no transactions at all."""
        raise NotImplementedError
