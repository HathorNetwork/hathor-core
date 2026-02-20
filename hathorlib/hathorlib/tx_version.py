# Copyright 2021 Hathor Labs
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

from enum import IntEnum
from typing import TYPE_CHECKING, Any, Dict, Type

if TYPE_CHECKING:
    from hathorlib.base_transaction import BaseTransaction

# The int value of one byte
_ONE_BYTE = 0xFF


class TxVersion(IntEnum):
    """Versions are sequential for blocks and transactions"""

    REGULAR_BLOCK = 0
    REGULAR_TRANSACTION = 1
    TOKEN_CREATION_TRANSACTION = 2
    MERGE_MINED_BLOCK = 3
    NANO_CONTRACT = 4
    POA_BLOCK = 5
    ON_CHAIN_BLUEPRINT = 6

    @classmethod
    def _missing_(cls, value: Any) -> None:
        assert isinstance(value, int), f"Value '{value}' must be an integer"
        assert value <= _ONE_BYTE, f'Value {hex(value)} must not be larger than one byte'

        raise ValueError(f'Invalid version: {value}')


def get_vertex_cls(version: TxVersion) -> 'Type[BaseTransaction]':
    """Return the hathorlib transaction class for the given TxVersion.

    Only maps versions that have hathorlib-internal implementations.
    For the full hathor mapping (including MergeMinedBlock, PoaBlock),
    use hathor.transaction.tx_version.get_vertex_cls instead.
    """
    from hathorlib import Block, TokenCreationTransaction, Transaction
    from hathorlib.nanocontracts.nanocontract import DeprecatedNanoContract
    from hathorlib.nanocontracts.on_chain_blueprint import OnChainBlueprint

    cls_map: Dict[TxVersion, Type[BaseTransaction]] = {
        TxVersion.REGULAR_BLOCK: Block,
        TxVersion.REGULAR_TRANSACTION: Transaction,
        TxVersion.TOKEN_CREATION_TRANSACTION: TokenCreationTransaction,
        TxVersion.NANO_CONTRACT: DeprecatedNanoContract,
        TxVersion.ON_CHAIN_BLUEPRINT: OnChainBlueprint,
    }

    cls = cls_map.get(version)

    if cls is None:
        raise ValueError('Invalid version.')
    return cls
