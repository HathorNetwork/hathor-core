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

from typing import Dict, List, Optional, Type, Union

from pydantic import NonNegativeInt, validator

from hathor.pubsub import EventArguments, HathorEvents
from hathor.utils.pydantic import BaseModel


class BaseEventData(BaseModel):
    @classmethod
    def from_event_arguments(cls, args: EventArguments) -> 'EventData':
        raise NotImplementedError()


class EmptyData(BaseEventData):
    @classmethod
    def from_event_arguments(cls, args: EventArguments) -> 'EmptyData':
        return cls()


class TxData(BaseEventData):
    hash: str
    nonce: int
    timestamp: int
    version: int
    weight: float
    inputs: List['TxInput']
    outputs: List['TxOutput']
    parents: List[str]
    tokens: List[str]
    token_name: Optional[str]
    token_symbol: Optional[str]
    metadata: 'TxMetadata'

    class TxInput(BaseModel):
        tx_id: str
        index: int
        data: int

    class TxOutput(BaseModel):
        value: int
        script: str
        token_data: int

    class SpentOutput(BaseModel):
        index: int
        tx_ids: List[str]

    class SpentOutputs(BaseModel):
        spent_output: List['TxData.SpentOutput']

    class TxMetadata(BaseModel):
        hash: str
        spent_outputs: List['TxData.SpentOutputs']
        conflict_with: List[str]
        voided_by: List[str]
        received_by: List[int]
        children: List[str]
        twins: List[str]
        accumulated_weight: float
        score: float
        first_block: Optional[str]
        height: int
        validation: str

    @classmethod
    def from_event_arguments(cls, args: EventArguments) -> 'TxData':
        tx_json = args.tx.to_json(include_metadata=True)

        return cls(**tx_json)


class ReorgData(BaseEventData):
    reorg_size: int
    previous_best_block: str
    new_best_block: str
    common_block: str

    @classmethod
    def from_event_arguments(cls, args: EventArguments) -> 'ReorgData':
        return cls(
            reorg_size=args.reorg_size,
            previous_best_block=args.old_best_block.hash_hex,
            new_best_block=args.new_best_block.hash_hex,
            common_block=args.common_block.hash_hex,
        )


EventData = Union[EmptyData, TxData, ReorgData]

_EVENT_DATA_MAP: Dict[HathorEvents, Type[BaseEventData]] = {
    HathorEvents.LOAD_STARTED: EmptyData,
    HathorEvents.LOAD_FINISHED: EmptyData,
    HathorEvents.NETWORK_NEW_TX_ACCEPTED: TxData,
    HathorEvents.NETWORK_BEST_BLOCK_FOUND: TxData,
    HathorEvents.NETWORK_ORPHAN_BLOCK_FOUND: TxData,
    HathorEvents.REORG_STARTED: ReorgData,
    HathorEvents.REORG_FINISHED: EmptyData,
    HathorEvents.VERTEX_METADATA_CHANGED: TxData,
    HathorEvents.CONSENSUS_TX_UPDATE: TxData,
    HathorEvents.CONSENSUS_TX_REMOVED: TxData,
}


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

    @classmethod
    def from_event_arguments(
        cls,
        peer_id: str,
        event_id: NonNegativeInt,
        timestamp: float,
        event_type: HathorEvents,
        event_args: EventArguments,
        group_id: Optional[NonNegativeInt]
    ) -> 'BaseEvent':
        event_data_type = _EVENT_DATA_MAP.get(event_type)

        if event_data_type is None:
            raise ValueError(f'The given event type ({event_type}) is not a supported event')

        return cls(
            peer_id=peer_id,
            id=event_id,
            timestamp=timestamp,
            type=event_type,
            data=event_data_type.from_event_arguments(event_args),
            group_id=group_id,
        )

    @validator('data')
    def data_type_must_match_event_type(cls, v, values):
        event_type = HathorEvents(values['type'])
        expected_data_type = _EVENT_DATA_MAP.get(event_type)

        if type(v) != expected_data_type:
            raise ValueError('event data type does not match event type')

        return v
