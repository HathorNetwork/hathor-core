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

from typing import TYPE_CHECKING

import base58

from hathor.conf.settings import HathorSettings
from hathor.mining.cpu_mining_service import CpuMiningService
from hathor.transaction import Block, Transaction, TxOutput
from hathorlib.scripts import P2PKH

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage  # noqa: F401


def get_all_genesis_hashes(settings: HathorSettings) -> list[bytes]:
    """Return all genesis hashes."""
    return [
        settings.GENESIS_BLOCK_HASH,
        settings.GENESIS_TX1_HASH,
        settings.GENESIS_TX2_HASH
    ]


def get_representation_for_all_genesis(settings: HathorSettings) -> bytes:
    """Return a single hash representing all genesis vertices."""
    import hashlib
    h = hashlib.sha256()
    for tx_hash in get_all_genesis_hashes(settings):
        h.update(tx_hash)
    return h.digest()


def is_genesis(hash_bytes: bytes, *, settings: HathorSettings) -> bool:
    """Check whether hash is from a genesis transaction."""
    return hash_bytes in get_all_genesis_hashes(settings)


def generate_new_genesis(
    *,
    tokens: int,
    address: str,
    block_timestamp: int,
    min_block_weight: float,
    min_tx_weight: float,
) -> tuple[Block, Transaction, Transaction]:
    """
    Create new genesis block and transactions. This is a convenience method to be used when creating side-dags,
    and maybe in some tests. It should never be used in runtime.
    """
    output_script = P2PKH.create_output_script(address=base58.b58decode(address))
    mining_service = CpuMiningService()

    block = Block(
        timestamp=block_timestamp,
        weight=min_block_weight,
        outputs=[TxOutput(tokens, output_script)],
    )
    mining_service.start_mining(block, update_time=False)
    block.update_hash()

    tx1 = Transaction(
        timestamp=block_timestamp + 1,
        weight=min_tx_weight,
    )
    mining_service.start_mining(tx1, update_time=False)
    tx1.update_hash()

    tx2 = Transaction(
        timestamp=block_timestamp + 2,
        weight=min_tx_weight,
    )
    mining_service.start_mining(tx2, update_time=False)
    tx2.update_hash()

    return block, tx1, tx2
