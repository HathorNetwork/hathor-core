#  Copyright 2024 Hathor Labs
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

from abc import ABC, abstractmethod
from collections import defaultdict
from typing import TYPE_CHECKING, Any, Collection, Self

import msgpack
from pydantic import validator
from typing_extensions import override

from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.transaction.validation_state import ValidationState
from hathor.types import VertexId
from hathor.util import not_none
from hathor.utils.pydantic import BaseModel

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction, TransactionMetadata


class MetadataSerializer(ABC, BaseModel):
    spent_outputs: dict[int, list[VertexId]] | None
    conflict_with: list[VertexId] | None
    voided_by: set[VertexId] | None
    received_by: list[int] | None
    children: list[VertexId] | None
    twins: list[VertexId] | None
    accumulated_weight: float
    score: float
    validation: ValidationState
    min_height: int

    @classmethod
    @abstractmethod
    def _from_metadata(cls, meta: TransactionMetadata) -> Self:
        raise NotImplementedError

    @abstractmethod
    def _to_metadata(self) -> TransactionMetadata:
        from hathor.transaction import TransactionMetadata
        meta = TransactionMetadata(
            spent_outputs=defaultdict(list, self.spent_outputs) if self.spent_outputs else None,
            accumulated_weight=self.accumulated_weight,
            score=self.score,
            min_height=self.min_height,
        )

        meta.conflict_with = self.conflict_with
        meta.voided_by = self.voided_by
        meta.received_by = self.received_by if self.received_by else []
        meta.children = self.children if self.children else []
        meta.twins = self.twins if self.twins else []
        meta.validation = self.validation

        return meta

    @classmethod
    def metadata_from_bytes(cls, data: bytes, *, target: type[BaseTransaction]) -> TransactionMetadata:
        from hathor.transaction import Block, Transaction
        data_dict = msgpack.unpackb(data, strict_map_key=False)
        serializer: MetadataSerializer

        if issubclass(target, Block):
            serializer = BlockMetadataSerializer(**data_dict)
        elif issubclass(target, Transaction):
            serializer = TransactionMetadataSerializer(**data_dict)
        else:
            raise NotImplementedError

        return serializer._to_metadata()

    @classmethod
    def metadata_to_bytes(cls, meta: TransactionMetadata, *, source: type[BaseTransaction]) -> bytes:
        from hathor.transaction import Block, Transaction
        serializer_type: type[MetadataSerializer]

        if issubclass(source, Block):
            serializer_type = BlockMetadataSerializer
        elif issubclass(source, Transaction):
            serializer_type = TransactionMetadataSerializer
        else:
            raise NotImplementedError

        serializer = serializer_type._from_metadata(meta)
        data_dict = serializer.dict(exclude_none=True)

        if voided_by := data_dict.get('voided_by'):
            data_dict['voided_by'] = list(voided_by)

        return msgpack.packb(data_dict)

    @validator('spent_outputs', 'voided_by', 'received_by', 'children', 'twins')
    def convert_empty_to_none(cls, value: Collection[Any] | None) -> Collection[Any] | None:
        return value if value else None

    @validator('conflict_with')
    def convert_conflict_with(cls, conflict_with: list[VertexId] | None) -> list[VertexId] | None:
        return list(set(conflict_with)) if conflict_with else None


class BlockMetadataSerializer(MetadataSerializer):
    height: int
    feature_activation_bit_counts: list[int]
    feature_states: dict[Feature, FeatureState] | None

    @classmethod
    @override
    def _from_metadata(cls, meta: TransactionMetadata) -> Self:
        assert not meta.first_block

        return cls(
            spent_outputs=meta.spent_outputs,
            conflict_with=meta.conflict_with,
            voided_by=meta.voided_by,
            received_by=meta.received_by,
            children=meta.children,
            twins=meta.twins,
            accumulated_weight=meta.accumulated_weight,
            score=meta.score,
            validation=meta.validation,
            min_height=not_none(meta.min_height),
            height=not_none(meta.height),
            feature_activation_bit_counts=not_none(meta.feature_activation_bit_counts),
            feature_states=meta.feature_states,
        )

    @override
    def _to_metadata(self) -> TransactionMetadata:
        meta = super()._to_metadata()
        meta.height = self.height
        meta.feature_activation_bit_counts = self.feature_activation_bit_counts
        meta.feature_states = self.feature_states
        return meta


class TransactionMetadataSerializer(MetadataSerializer):
    first_block: VertexId | None

    @classmethod
    @override
    def _from_metadata(cls, meta: TransactionMetadata) -> Self:
        assert not meta.height
        assert not meta.feature_activation_bit_counts
        assert not meta.feature_states

        return cls(
            spent_outputs=meta.spent_outputs,
            conflict_with=meta.conflict_with,
            voided_by=meta.voided_by,
            received_by=meta.received_by,
            children=meta.children,
            twins=meta.twins,
            accumulated_weight=meta.accumulated_weight,
            score=meta.score,
            validation=meta.validation,
            min_height=not_none(meta.min_height),
            first_block=meta.first_block,
        )

    @override
    def _to_metadata(self) -> TransactionMetadata:
        meta = super()._to_metadata()
        meta.first_block = self.first_block
        return meta
