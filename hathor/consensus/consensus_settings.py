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

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from enum import Enum, unique
from typing import TYPE_CHECKING, Annotated, Any, Literal, TypeAlias

from pydantic import Field, NonNegativeInt, PrivateAttr, validator
from typing_extensions import override

from hathor.transaction import TxVersion
from hathor.util import json_dumpb
from hathor.utils.pydantic import BaseModel

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings


@unique
class ConsensusType(str, Enum):
    PROOF_OF_WORK = 'PROOF_OF_WORK'
    PROOF_OF_AUTHORITY = 'PROOF_OF_AUTHORITY'


class _BaseConsensusSettings(ABC, BaseModel):
    type: ConsensusType
    _peer_hello_hash: str | None = PrivateAttr(default=None)

    def is_pow(self) -> bool:
        """Return whether this is a Proof-of-Work consensus."""
        return self.type == ConsensusType.PROOF_OF_WORK

    def is_poa(self) -> bool:
        """Return whether this is a Proof-of-Authority consensus."""
        return self.type == ConsensusType.PROOF_OF_AUTHORITY

    @abstractmethod
    def _get_valid_vertex_versions(self, include_genesis: bool, *, settings: HathorSettings) -> set[TxVersion]:
        """Return a set of `TxVersion`s that are valid in for this consensus type."""
        raise NotImplementedError

    def is_vertex_version_valid(
        self,
        version: TxVersion,
        *,
        settings: HathorSettings,
        include_genesis: bool = False,
    ) -> bool:
        """Return whether a `TxVersion` is valid for this consensus type."""
        return version in self._get_valid_vertex_versions(include_genesis, settings=settings)

    def get_peer_hello_hash(self) -> str | None:
        """Return a hash of consensus settings to be used in peer hello validation."""
        if self._peer_hello_hash is None:
            self._peer_hello_hash = self._calculate_peer_hello_hash()
        return self._peer_hello_hash

    def _calculate_peer_hello_hash(self) -> str | None:
        """Calculate a hash of consensus settings to be used in peer hello validation."""
        return None


class PowSettings(_BaseConsensusSettings):
    type: Literal[ConsensusType.PROOF_OF_WORK] = ConsensusType.PROOF_OF_WORK

    @override
    def _get_valid_vertex_versions(self, include_genesis: bool, *, settings: HathorSettings) -> set[TxVersion]:
        versions = {
            TxVersion.REGULAR_BLOCK,
            TxVersion.REGULAR_TRANSACTION,
            TxVersion.TOKEN_CREATION_TRANSACTION,
            TxVersion.MERGE_MINED_BLOCK,
        }

        if settings.ENABLE_NANO_CONTRACTS:
            versions.add(TxVersion.ON_CHAIN_BLUEPRINT)

        return versions

    @override
    def get_peer_hello_hash(self) -> str | None:
        return None


class PoaSignerSettings(BaseModel):
    public_key: bytes
    start_height: NonNegativeInt = 0
    end_height: NonNegativeInt | None = None

    @validator('public_key', pre=True)
    def _parse_hex_str(cls, hex_str: str | bytes) -> bytes:
        from hathor.conf.settings import parse_hex_str
        return parse_hex_str(hex_str)

    @validator('end_height')
    def _validate_end_height(cls, end_height: int | None, values: dict[str, Any]) -> int | None:
        start_height = values.get('start_height')
        assert start_height is not None, 'start_height must be set'

        if end_height is None:
            return None

        if end_height <= start_height:
            raise ValueError(f'end_height ({end_height}) must be greater than start_height ({start_height})')

        return end_height

    def to_json_dict(self) -> dict[str, Any]:
        """Return this signer settings instance as a json dict."""
        json_dict = self.dict()
        # TODO: We can use a custom serializer to convert bytes to hex when we update to Pydantic V2.
        json_dict['public_key'] = self.public_key.hex()
        return json_dict


class PoaSettings(_BaseConsensusSettings):
    type: Literal[ConsensusType.PROOF_OF_AUTHORITY] = ConsensusType.PROOF_OF_AUTHORITY

    # A list of Proof-of-Authority signer public keys that have permission to produce blocks.
    signers: tuple[PoaSignerSettings, ...]

    @validator('signers')
    def _validate_signers(cls, signers: tuple[PoaSignerSettings, ...]) -> tuple[PoaSignerSettings, ...]:
        if len(signers) == 0:
            raise ValueError('At least one signer must be provided in PoA networks')
        return signers

    @override
    def _get_valid_vertex_versions(self, include_genesis: bool, *, settings: HathorSettings) -> set[TxVersion]:
        versions = {
            TxVersion.POA_BLOCK,
            TxVersion.REGULAR_TRANSACTION,
            TxVersion.TOKEN_CREATION_TRANSACTION,
        }

        if include_genesis:
            # TODO: We have to add REGULAR_BLOCK to allow genesis deserialization.
            #  This may be removed if we refactor the way genesis is constructed.
            versions.add(TxVersion.REGULAR_BLOCK)

        if settings.ENABLE_NANO_CONTRACTS:
            versions.add(TxVersion.ON_CHAIN_BLUEPRINT)

        return versions

    @override
    def _calculate_peer_hello_hash(self) -> str | None:
        data = b''
        for signer in self.signers:
            data += json_dumpb(signer.to_json_dict())
        return hashlib.sha256(data).digest().hex()


ConsensusSettings: TypeAlias = Annotated[PowSettings | PoaSettings, Field(discriminator='type')]
