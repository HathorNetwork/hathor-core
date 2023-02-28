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

from typing import List, Optional, Union

from hathor.pubsub import EventArguments
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
