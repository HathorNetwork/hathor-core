#  Copyright 2023 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from enum import Enum

from hathor.event.model.base_event import BaseEvent
from hathor.event.model.event_data import TxData, TxMetadata
from hathor.pubsub import HathorEvents


class Scenario(Enum):
    SINGLE_CHAIN = 'SINGLE_CHAIN'
    BEST_CHAIN_WITH_SIDE_CHAINS = 'BEST_CHAIN_WITH_SIDE_CHAINS'
    MULTIPLE_FORKS = 'MULTIPLE_FORKS'

    def get_events(self):
        return _SCENARIO_EVENTS[self]


_TRANSACTION_DATA_1 = TxData(
    hash='123',
    nonce=456,
    timestamp=0,
    version=1,
    weight=2,
    inputs=[],
    outputs=[],
    parents=[],
    tokens=[],
    metadata=TxMetadata(
        hash='123',
        spent_outputs=[],
        conflict_with=[],
        voided_by=[],
        received_by=[],
        children=[],
        twins=[],
        accumulated_weight=2,
        score=2,
        height=0,
        validation=''
    )
)

_TRANSACTION_1 = BaseEvent(
    peer_id='123',
    id=0,
    timestamp=0,
    type=HathorEvents.NETWORK_NEW_TX_ACCEPTED,
    data=_TRANSACTION_DATA_1
)


# TODO: We still have to actually populate the list of events for each scenario. Pending on design discussions.
_SCENARIO_EVENTS = {
    Scenario.SINGLE_CHAIN: [
        _TRANSACTION_1
    ],
    Scenario.BEST_CHAIN_WITH_SIDE_CHAINS: [
        _TRANSACTION_1
    ],
    Scenario.MULTIPLE_FORKS: [
        _TRANSACTION_1
    ],
}
