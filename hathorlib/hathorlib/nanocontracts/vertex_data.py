# Copyright 2023 Hathor Labs
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

from dataclasses import dataclass
from enum import StrEnum, unique

from hathorlib import TxVersion
from hathorlib.nanocontracts.types import TokenUid, VertexId


@dataclass(frozen=True, slots=True, kw_only=True)
class VertexData:
    version: TxVersion
    hash: bytes
    nonce: int
    signal_bits: int
    work: int
    inputs: tuple[TxInputData, ...]
    outputs: tuple[TxOutputData, ...]
    tokens: tuple[TokenUid, ...]
    parents: tuple[VertexId, ...]
    headers: tuple[HeaderData, ...]


@dataclass(frozen=True, slots=True, kw_only=True)
class TxInputData:
    tx_id: VertexId
    index: int
    data: bytes
    info: TxOutputData | None


@unique
class ScriptType(StrEnum):
    P2PKH = 'P2PKH'
    MULTI_SIG = 'MultiSig'


@dataclass(slots=True, frozen=True, kw_only=True)
class ScriptInfo:
    type: ScriptType
    address: str
    timelock: int | None


@dataclass(frozen=True, slots=True, kw_only=True)
class TxOutputData:
    value: int
    raw_script: bytes
    parsed_script: ScriptInfo | None
    token_data: int


@dataclass(frozen=True, slots=True, kw_only=True)
class BlockData:
    hash: VertexId
    timestamp: int
    height: int


class HeaderData:
    """Marker class, represents an arbitrary vertex-header."""


@dataclass(frozen=True, slots=True, kw_only=True)
class NanoHeaderData(HeaderData):
    nc_seqnum: int
    nc_id: VertexId
    nc_method: str
    nc_args_bytes: bytes
