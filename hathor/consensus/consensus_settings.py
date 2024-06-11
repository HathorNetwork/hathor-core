# Copyright 2024 Hathor Labs
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

from abc import ABC, abstractmethod
from enum import Enum, unique
from typing import Annotated, Literal, TypeAlias

from pydantic import Field, validator
from typing_extensions import override

from hathor.transaction import TxVersion
from hathor.utils.pydantic import BaseModel


@unique
class ConsensusType(str, Enum):
    PROOF_OF_WORK = 'PROOF_OF_WORK'
    PROOF_OF_AUTHORITY = 'PROOF_OF_AUTHORITY'


class _BaseConsensusSettings(ABC, BaseModel):
    type: ConsensusType

    def is_pow(self) -> bool:
        """Return whether this is a Proof-of-Work consensus."""
        return self.type is ConsensusType.PROOF_OF_WORK

    def is_poa(self) -> bool:
        """Return whether this is a Proof-of-Authority consensus."""
        return self.type is ConsensusType.PROOF_OF_AUTHORITY

    @abstractmethod
    def _get_valid_vertex_versions(self) -> set[TxVersion]:
        """Return a set of `TxVersion`s that are valid in for this consensus type."""
        raise NotImplementedError

    def is_vertex_version_valid(self, version: TxVersion) -> bool:
        """Return whether a `TxVersion` is valid for this consensus type."""
        return version in self._get_valid_vertex_versions()


class PowSettings(_BaseConsensusSettings):
    type: Literal[ConsensusType.PROOF_OF_WORK] = ConsensusType.PROOF_OF_WORK

    @override
    def _get_valid_vertex_versions(self) -> set[TxVersion]:
        return {
            TxVersion.REGULAR_BLOCK,
            TxVersion.REGULAR_TRANSACTION,
            TxVersion.TOKEN_CREATION_TRANSACTION,
            TxVersion.MERGE_MINED_BLOCK
        }


class PoaSettings(_BaseConsensusSettings):
    type: Literal[ConsensusType.PROOF_OF_AUTHORITY] = ConsensusType.PROOF_OF_AUTHORITY

    # A list of Proof-of-Authority signer public keys that have permission to produce blocks.
    signers: tuple[bytes, ...] = ()

    @validator('signers', each_item=True)
    def parse_hex_str(cls, hex_str: str | bytes) -> bytes:
        from hathor.conf.settings import parse_hex_str
        return parse_hex_str(hex_str)

    @override
    def _get_valid_vertex_versions(self) -> set[TxVersion]:
        return {
            TxVersion.POA_BLOCK,
            TxVersion.REGULAR_TRANSACTION,
            TxVersion.TOKEN_CREATION_TRANSACTION,
        }


ConsensusSettings: TypeAlias = Annotated[PowSettings | PoaSettings, Field(discriminator='type')]
