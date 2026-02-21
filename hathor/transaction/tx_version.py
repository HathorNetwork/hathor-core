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

from typing import TYPE_CHECKING

from hathorlib.tx_version import TxVersion  # noqa: F401

if TYPE_CHECKING:
    from hathor.transaction.base_transaction import BaseTransaction


def get_vertex_cls(version: TxVersion) -> type['BaseTransaction']:
    """Return the hathor transaction class for the given TxVersion."""
    from hathor.conf.get_settings import get_global_settings
    from hathor.transaction.block import Block
    from hathor.transaction.merge_mined_block import MergeMinedBlock
    from hathor.transaction.poa import PoaBlock
    from hathor.transaction.token_creation_tx import TokenCreationTransaction
    from hathor.transaction.transaction import Transaction

    cls_map: dict[TxVersion, type[BaseTransaction]] = {
        TxVersion.REGULAR_BLOCK: Block,
        TxVersion.REGULAR_TRANSACTION: Transaction,
        TxVersion.TOKEN_CREATION_TRANSACTION: TokenCreationTransaction,
        TxVersion.MERGE_MINED_BLOCK: MergeMinedBlock,
        TxVersion.POA_BLOCK: PoaBlock,
    }

    settings = get_global_settings()
    if settings.ENABLE_NANO_CONTRACTS:
        from hathor.nanocontracts.on_chain_blueprint import OnChainBlueprint
        cls_map[TxVersion.ON_CHAIN_BLUEPRINT] = OnChainBlueprint

    cls = cls_map.get(version)

    if cls is None:
        raise ValueError('Invalid version.')
    return cls
