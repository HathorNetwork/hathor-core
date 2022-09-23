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

from collections import defaultdict
from typing import TYPE_CHECKING, DefaultDict, List, Optional, Set

from structlog import get_logger

from hathor.indexes.address_index import AddressIndex
from hathor.pubsub import HathorEvents
from hathor.transaction import BaseTransaction

if TYPE_CHECKING:  # pragma: no cover
    from hathor.pubsub import EventArguments, PubSubManager

logger = get_logger()


class MemoryAddressIndex(AddressIndex):
    """ Index of inputs/outputs by address
    """

    index: DefaultDict[str, Set[bytes]]

    def __init__(self, pubsub: Optional['PubSubManager'] = None) -> None:
        self.pubsub = pubsub
        self.force_clear()
        if self.pubsub:
            self.subscribe_pubsub_events()

    def get_db_name(self) -> Optional[str]:
        return None

    def force_clear(self) -> None:
        self.index = defaultdict(set)

    def subscribe_pubsub_events(self) -> None:
        """ Subscribe wallet index to receive voided/winner tx pubsub events
        """
        assert self.pubsub is not None
        # Subscribe to voided/winner events
        self.pubsub.subscribe(HathorEvents.CONSENSUS_TX_UPDATE, self.handle_tx_event)

    def add_tx(self, tx: BaseTransaction) -> None:
        """ Add tx inputs and outputs to the wallet index (indexed by its addresses).
        """
        assert tx.hash is not None

        addresses = tx.get_related_addresses()
        for address in addresses:
            self.index[address].add(tx.hash)

        self.publish_tx(tx, addresses=addresses)

    def remove_tx(self, tx: BaseTransaction) -> None:
        """ Remove tx inputs and outputs from the wallet index (indexed by its addresses).
        """
        assert tx.hash is not None

        addresses = tx.get_related_addresses()
        for address in addresses:
            self.index[address].discard(tx.hash)

    def handle_tx_event(self, key: HathorEvents, args: 'EventArguments') -> None:
        """ This method is called when pubsub publishes an event that we subscribed
        """
        data = args.__dict__
        tx = data['tx']
        meta = tx.get_metadata()
        if meta.has_voided_by_changed_since_last_call() or meta.has_spent_by_changed_since_last_call():
            self.publish_tx(tx)

    def get_from_address(self, address: str) -> List[bytes]:
        """ Get list of transaction hashes of an address
        """
        return list(self.index[address])

    def get_sorted_from_address(self, address: str) -> List[bytes]:
        """ Get a sorted list of transaction hashes of an address
        """
        return sorted(self.index[address])

    def is_address_empty(self, address: str) -> bool:
        return not bool(self.index[address])
