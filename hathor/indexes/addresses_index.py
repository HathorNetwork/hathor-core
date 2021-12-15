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
from typing import TYPE_CHECKING, DefaultDict, Iterable, List, Optional, Set

from structlog import get_logger

from hathor.pubsub import HathorEvents
from hathor.transaction import BaseTransaction
from hathor.transaction.scripts import parse_address_script

if TYPE_CHECKING:  # pragma: no cover
    from hathor.pubsub import EventArguments, PubSubManager
    from hathor.transaction import TxOutput

logger = get_logger()


class AddressesIndex:
    """ Index of inputs/outputs by address
    """
    def __init__(self, pubsub: Optional['PubSubManager'] = None) -> None:
        self.index: DefaultDict[str, Set[bytes]] = defaultdict(set)
        self.pubsub = pubsub
        if self.pubsub:
            self.subscribe_pubsub_events()

    def subscribe_pubsub_events(self) -> None:
        """ Subscribe wallet index to receive voided/winner tx pubsub events
        """
        assert self.pubsub is not None
        # Subscribe to voided/winner events
        events = [HathorEvents.STORAGE_TX_VOIDED, HathorEvents.STORAGE_TX_WINNER]
        for event in events:
            self.pubsub.subscribe(event, self.handle_tx_event)

    def _get_addresses(self, tx: BaseTransaction) -> Set[str]:
        """ Return a set of addresses collected from tx's inputs and outputs.
        """
        assert tx.storage is not None
        addresses: Set[str] = set()

        def add_address_from_output(output: 'TxOutput') -> None:
            script_type_out = parse_address_script(output.script)
            if script_type_out:
                address = script_type_out.address
                addresses.add(address)

        for txin in tx.inputs:
            tx2 = tx.storage.get_transaction(txin.tx_id)
            txout = tx2.outputs[txin.index]
            add_address_from_output(txout)

        for txout in tx.outputs:
            add_address_from_output(txout)

        return addresses

    def publish_tx(self, tx: BaseTransaction, *, addresses: Optional[Iterable[str]] = None) -> None:
        """ Publish WALLET_ADDRESS_HISTORY for all addresses of a transaction.
        """
        if not self.pubsub:
            return
        if addresses is None:
            addresses = self._get_addresses(tx)
        data = tx.to_json_extended()
        for address in addresses:
            self.pubsub.publish(HathorEvents.WALLET_ADDRESS_HISTORY, address=address, history=data)

    def add_tx(self, tx: BaseTransaction) -> None:
        """ Add tx inputs and outputs to the wallet index (indexed by its addresses).
        """
        assert tx.hash is not None

        addresses = self._get_addresses(tx)
        for address in addresses:
            self.index[address].add(tx.hash)

        self.publish_tx(tx, addresses=addresses)

    def remove_tx(self, tx: BaseTransaction) -> None:
        """ Remove tx inputs and outputs from the wallet index (indexed by its addresses).
        """
        assert tx.hash is not None

        addresses = self._get_addresses(tx)
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
