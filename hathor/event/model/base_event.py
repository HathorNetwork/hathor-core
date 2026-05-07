# Copyright 2022 Hathor Labs
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

from typing import Optional

from pydantic import ConfigDict, NonNegativeInt, model_validator

from hathor.event.model.event_data import EventData
from hathor.event.model.event_type import EventType
from hathor.pubsub import EventArguments
from hathor.utils.pydantic import BaseModel


class BaseEvent(BaseModel):
    model_config = ConfigDict(use_enum_values=True)

    # Event unique id, determines event order
    id: NonNegativeInt
    # Timestamp in which the event was emitted, this follows the unix_timestamp format, it's only informative, events
    # aren't guaranteed to always have sequential timestamps, for example, if the system clock changes between two
    # events it's possible that timestamps will temporarily decrease.
    timestamp: float
    # One of the event types
    type: EventType
    # Variable for event type
    data: EventData
    # Used to link events, for example, many TX_METADATA_CHANGED will have the same group_id when they belong to the
    # same reorg process
    group_id: Optional[NonNegativeInt] = None

    @classmethod
    def from_event_arguments(
        cls,
        event_id: NonNegativeInt,
        timestamp: float,
        event_type: EventType,
        event_args: EventArguments,
        group_id: Optional[NonNegativeInt]
    ) -> 'BaseEvent':
        """Creates a BaseEvent from PubSub's EventArguments."""
        event_data_type = event_type.data_type()

        return cls(
            id=event_id,
            timestamp=timestamp,
            type=event_type,
            data=event_data_type.from_event_arguments(event_args),
            group_id=group_id,
        )

    @model_validator(mode='after')
    def data_type_must_match_event_type(self) -> 'BaseEvent':
        event_type = EventType(self.type)
        expected_data_type = event_type.data_type()

        if type(self.data) is not expected_data_type:
            raise ValueError('event data type does not match event type')

        return self
