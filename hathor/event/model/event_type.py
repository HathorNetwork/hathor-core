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
from typing import Dict, Type

from hathor.event.model.event_data import BaseEventData, EmptyData, ReorgData, TxData
from hathor.pubsub import EventArguments, HathorEvents


class EventType(Enum):
    LOAD_STARTED = 'LOAD_STARTED'
    LOAD_FINISHED = 'LOAD_FINISHED'
    NEW_VERTEX_ACCEPTED = 'NEW_VERTEX_ACCEPTED'
    NEW_VERTEX_VOIDED = 'NEW_VERTEX_VOIDED'
    REORG_STARTED = 'REORG_STARTED'
    REORG_FINISHED = 'REORG_FINISHED'
    VERTEX_METADATA_CHANGED = 'VERTEX_METADATA_CHANGED'

    @classmethod
    def from_hathor_event(cls, hathor_event: HathorEvents, event_args: EventArguments) -> 'EventType':
        if hathor_event == HathorEvents.NETWORK_NEW_TX_ACCEPTED:
            metadata = event_args.tx.get_metadata()

            return cls.NEW_VERTEX_VOIDED if metadata.voided_by else cls.NEW_VERTEX_ACCEPTED

        event_map = {
            HathorEvents.MANAGER_ON_START: EventType.LOAD_STARTED,
            HathorEvents.LOAD_FINISHED: EventType.LOAD_FINISHED,
            HathorEvents.REORG_STARTED: EventType.REORG_STARTED,
            HathorEvents.REORG_FINISHED: EventType.REORG_FINISHED,
            HathorEvents.CONSENSUS_TX_UPDATE: EventType.VERTEX_METADATA_CHANGED
        }

        event = event_map.get(hathor_event)

        assert event is not None, f'Cannot create EventType from {hathor_event}'

        return event

    def data_type(self) -> Type[BaseEventData]:
        type_map: Dict[EventType, Type[BaseEventData]] = {
            EventType.LOAD_STARTED: EmptyData,
            EventType.LOAD_FINISHED: EmptyData,
            EventType.NEW_VERTEX_ACCEPTED: TxData,
            EventType.NEW_VERTEX_VOIDED: TxData,
            EventType.REORG_STARTED: ReorgData,
            EventType.REORG_FINISHED: EmptyData,
            EventType.VERTEX_METADATA_CHANGED: TxData,
        }

        return type_map[self]
