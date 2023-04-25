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

from pydantic import Extra, validator

from hathor.pubsub import EventArguments
from hathor.utils.pydantic import BaseModel


class TxInput(BaseModel):
    tx_id: str
    index: int
    data: str


class TxOutput(BaseModel):
    value: int
    script: str
    token_data: int


class SpentOutput(BaseModel):
    index: int
    tx_ids: List[str]


class TxMetadata(BaseModel, extra=Extra.ignore):
    hash: str
    spent_outputs: List[SpentOutput]
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

    @validator('spent_outputs', pre=True, each_item=True)
    def parse_spent_outputs(cls, spent_output):
        if isinstance(spent_output, SpentOutput):
            return spent_output

        index, tx_ids = spent_output

        return SpentOutput(index=index, tx_ids=tx_ids)


class BaseEventData(BaseModel):
    @classmethod
    def from_event_arguments(cls, args: EventArguments) -> 'EventData':
        raise NotImplementedError()


class EmptyData(BaseEventData):
    @classmethod
    def from_event_arguments(cls, args: EventArguments) -> 'EmptyData':
        return cls()


class TxData(BaseEventData, extra=Extra.ignore):
    hash: str
    nonce: int
    timestamp: int
    version: int
    weight: float
    inputs: List['TxInput']
    outputs: List['TxOutput']
    parents: List[str]
    tokens: List[str]
    # TODO: Token name and symbol could be in a different class because they're only used by TokenCreationTransaction
    token_name: Optional[str]
    token_symbol: Optional[str]
    metadata: 'TxMetadata'

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
