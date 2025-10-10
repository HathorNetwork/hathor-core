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
from typing import TYPE_CHECKING, Iterable, Optional

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
        assert key == HathorEvents.CONSENSUS_TX_UPDATE
        data = args.__dict__
        event_tx = data['tx']

        def handle_tx(tx: BaseTransaction, *, check_inputs: bool) -> None:
            assert tx.storage is not None
            meta = tx.get_metadata()
            updated_voided_by = meta.has_voided_by_changed_since_last_call()
            updated_spent_by = meta.has_spent_by_changed_since_last_call()

            if updated_voided_by or updated_spent_by:
                self._publish_tx(tx)

            if check_inputs and updated_voided_by:
                # We need to check our input txs because it's possible their spent_by was
                # affected even when the tx was not touched by the consensus directly.
                for tx_input in tx.inputs:
                    affected_input_tx = tx.storage.get_transaction(tx_input.tx_id)
                    handle_tx(affected_input_tx, check_inputs=False)

        handle_tx(event_tx, check_inputs=True)

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
    def get_from_address(self, address: str) -> list[bytes]:
        """ Get list of transaction hashes of an address
        """
        raise NotImplementedError

    @abstractmethod
    def get_sorted_from_address(self, address: str, tx_start: Optional[BaseTransaction] = None) -> Iterable[bytes]:
        """ Get a sorted list of transaction hashes of an address

        `tx_start` serves as a pagination marker, indicating the starting position for the iteration.
        When tx_start is None, the iteration begins from the initial element.
        """
        raise NotImplementedError

    @abstractmethod
    def is_address_empty(self, address: str) -> bool:
        """Check whether address has no transactions at all."""
        raise NotImplementedError
