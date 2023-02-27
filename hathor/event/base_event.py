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

from typing import Optional, Union

from pydantic import NonNegativeInt

from hathor.pubsub import EventArguments, HathorEvents
from hathor.utils.pydantic import BaseModel


class BaseEventData(BaseModel):
    @classmethod
    def from_event_arguments(cls, args: EventArguments) -> 'EventData':
        raise NotImplementedError()


class EmptyData(BaseEventData):
    @classmethod
    def from_event_arguments(cls, args: EventArguments) -> 'EmptyData':
        return EmptyData()


class TxData(BaseEventData):
    hash: str
    # TODO: Other fields

    @classmethod
    def from_event_arguments(cls, args: EventArguments) -> 'TxData':
        return TxData(
            hash=args.tx.hash_hex,
        )


class ReorgData(BaseEventData):
    reorg_size: int
    previous_best_block: str
    new_best_block: str
    common_block: str

    @classmethod
    def from_event_arguments(cls, args: EventArguments) -> 'ReorgData':
        return ReorgData(
            reorg_size=args.reorg_size,
            previous_best_block=args.old_best_block.hash_hex,
            new_best_block=args.new_best_block.hash_hex,
            common_block=args.common_block.hash_hex,
        )


EventData = Union[EmptyData, TxData, ReorgData]


class BaseEvent(BaseModel, use_enum_values=True):
    # Full node id, because different full nodes can have different sequences of events
    peer_id: str
    # Event unique id, determines event order
    id: NonNegativeInt
    # Timestamp in which the event was emitted, this follows the unix_timestamp format, it's only informative, events
    # aren't guaranteed to always have sequential timestamps, for example, if the system clock changes between two
    # events it's possible that timestamps will temporarily decrease.
    timestamp: float
    # One of the event types
    type: HathorEvents
    # Variable for event type
    data: EventData
    # Used to link events, for example, many TX_METADATA_CHANGED will have the same group_id when they belong to the
    # same reorg process
    group_id: Optional[NonNegativeInt] = None
    # TODO: Custom validate that EventData is equivalent to HathorEvents
