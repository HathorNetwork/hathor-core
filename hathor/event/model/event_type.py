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


class EventType(Enum):
    LOAD_STARTED = 'LOAD_STARTED'
    LOAD_FINISHED = 'LOAD_FINISHED'
    NEW_VERTEX_ACCEPTED = 'NEW_VERTEX_ACCEPTED'
    NEW_VERTEX_VOIDED = 'NEW_VERTEX_VOIDED'
    REORG_STARTED = 'REORG_STARTED'
    REORG_FINISHED = 'REORG_FINISHED'
    VERTEX_METADATA_CHANGED = 'VERTEX_METADATA_CHANGED'

    def data_type(self) -> Type[BaseEventData]:
        type_map: Dict[EventType, Type[BaseEventData]] = {
            EventType.LOAD_STARTED: EmptyData,
            EventType.LOAD_FINISHED: EmptyData,
            EventType.NEW_VERTEX_ACCEPTED: TxData,
            EventType.NEW_VERTEX_VOIDED: TxData,
            EventType.REORG_STARTED: ReorgData,
            EventType.REORG_FINISHED: ReorgData,
            EventType.VERTEX_METADATA_CHANGED: TxData,
        }

        return type_map[self]
