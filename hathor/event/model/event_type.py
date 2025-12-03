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

from __future__ import annotations

from enum import Enum

from hathor.event.model.event_data import (
    BaseEventData,
    EmptyData,
    NCEventData,
    ReorgData,
    TokenCreatedData,
    TxData,
    TxDataWithoutMeta,
)
from hathor.pubsub import HathorEvents


class EventType(Enum):
    LOAD_STARTED = 'LOAD_STARTED'
    LOAD_FINISHED = 'LOAD_FINISHED'
    NEW_VERTEX_ACCEPTED = 'NEW_VERTEX_ACCEPTED'
    REORG_STARTED = 'REORG_STARTED'
    REORG_FINISHED = 'REORG_FINISHED'
    VERTEX_METADATA_CHANGED = 'VERTEX_METADATA_CHANGED'
    VERTEX_REMOVED = 'VERTEX_REMOVED'
    FULL_NODE_CRASHED = 'FULL_NODE_CRASHED'
    NC_EVENT = 'NC_EVENT'
    TOKEN_CREATED = 'TOKEN_CREATED'

    @classmethod
    def from_hathor_event(cls, hathor_event: HathorEvents) -> EventType | None:
        """Create an Event Queue feature EventType from a PubSub HathorEvents."""
        return _HATHOR_EVENT_TO_EVENT_TYPE.get(hathor_event)

    def data_type(self) -> type[BaseEventData]:
        return _EVENT_TYPE_TO_EVENT_DATA[self]


_HATHOR_EVENT_TO_EVENT_TYPE = {
    HathorEvents.NETWORK_NEW_TX_ACCEPTED: EventType.NEW_VERTEX_ACCEPTED,
    HathorEvents.REORG_STARTED: EventType.REORG_STARTED,
    HathorEvents.REORG_FINISHED: EventType.REORG_FINISHED,
    HathorEvents.CONSENSUS_TX_UPDATE: EventType.VERTEX_METADATA_CHANGED,
    HathorEvents.CONSENSUS_TX_REMOVED: EventType.VERTEX_REMOVED,
    HathorEvents.NC_EVENT: EventType.NC_EVENT
}

_EVENT_TYPE_TO_EVENT_DATA: dict[EventType, type[BaseEventData]] = {
    EventType.LOAD_STARTED: EmptyData,
    EventType.LOAD_FINISHED: EmptyData,
    EventType.NEW_VERTEX_ACCEPTED: TxData,
    EventType.REORG_STARTED: ReorgData,
    EventType.REORG_FINISHED: EmptyData,
    EventType.VERTEX_METADATA_CHANGED: TxData,
    EventType.VERTEX_REMOVED: TxDataWithoutMeta,
    EventType.FULL_NODE_CRASHED: EmptyData,
    EventType.NC_EVENT: NCEventData,
    EventType.TOKEN_CREATED: TokenCreatedData,
}
