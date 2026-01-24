#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from __future__ import annotations

from typing import Iterator

from structlog import get_logger
from typing_extensions import assert_never

from hathor import __version__
from hathor.conf.settings import HathorSettings
from hathor.nanocontracts.storage.block_storage import NCBlockStorage, _Tag as BlockTag
from hathor.nanocontracts.storage.contract_storage import _Tag as ContractTag
from hathor.nanocontracts.storage.patricia_trie import Node, PatriciaTrie
from hathor.transaction import Block
from hathor.transaction.storage import TransactionStorage
from hathor.utils.pydantic import BaseModel, Hex

logger = get_logger()


class NCDump(BaseModel):
    version: str
    network: str
    blocks: dict[Hex[bytes], BlockDump]


class BlockDump(BaseModel):
    hash: Hex[bytes]
    height: int
    contracts: dict[Hex[bytes], ContractDump]
    tokens: dict[Hex[bytes], Hex[bytes]]
    addresses: dict[Hex[bytes], Hex[bytes]]


class ContractDump(BaseModel):
    hash: Hex[bytes]
    attrs: dict[Hex[bytes], Hex[bytes]]
    balances: dict[Hex[bytes], Hex[bytes]]
    metadata: dict[Hex[bytes], Hex[bytes]]


class NCDumper:
    __slots__ = ('_log', 'settings', 'tx_storage', '_visited_block_root_ids', '_visited_contract_root_ids')

    def __init__(self, *, settings: HathorSettings, tx_storage: TransactionStorage) -> None:
        self._log = logger.new()
        self.settings = settings
        self.tx_storage = tx_storage
        self._visited_block_root_ids: set[bytes] = set()
        self._visited_contract_root_ids: set[bytes] = set()  # TODO?

    def get_nc_dump(self) -> NCDump:
        blocks = {}

        for block in self._iter_blocks():
            meta = block.get_metadata()
            assert meta.nc_block_root_id is not None

            if meta.nc_block_root_id in self._visited_block_root_ids:
                self._log.info('skipping block', block_hash=block.hash.hex(), height=block.get_height())
                continue

            self._log.info('processing block', block_hash=block.hash.hex(), height=block.get_height())
            self._visited_block_root_ids.add(meta.nc_block_root_id)
            block_storage = self.tx_storage.get_nc_block_storage(block)
            block_dump = self.get_block_nc_dump(block, block_storage)
            blocks[meta.nc_block_root_id] = block_dump

        return NCDump(
            version=__version__,
            network=self.settings.NETWORK_NAME,
            blocks=blocks,
        )

    def get_block_nc_dump(self, block: Block, block_storage: NCBlockStorage) -> BlockDump:
        block_trie = block_storage._block_trie
        contracts = {}
        tokens = {}
        addresses = {}

        for iter_node in block_trie.iter_dfs():
            node = iter_node.node
            if value := node.content:
                key = block_trie._decode_key(node.key)
                tag = BlockTag(key[0:1])
                key = key[1:]

                match tag:
                    case BlockTag.CONTRACT:
                        contract_trie = block_storage._get_trie(value)
                        contract = self._get_contract_nc_dump(contract_trie, key)
                        contracts[value] = contract
                    case BlockTag.TOKEN:
                        tokens[key] = value
                    case BlockTag.ADDRESS:
                        addresses[key] = value
                    case _:
                        assert_never(tag)

        return BlockDump(
            hash=block.hash,
            height=block.get_height(),
            contracts=contracts,
            tokens=tokens,
            addresses=addresses,
        )

    def _get_contract_nc_dump(self, contract_trie: PatriciaTrie, contract_hash: bytes) -> ContractDump:
        attrs = {}
        balances = {}
        metadata = {}

        for iter_node in contract_trie.iter_dfs():
            node = iter_node.node
            if value := node.content:
                key = contract_trie._decode_key(node.key)
                tag = ContractTag(key[0:1])
                key = key[1:]

                match tag:
                    case ContractTag.ATTR:
                        attrs[key] = value
                    case ContractTag.BALANCE:
                        balances[key] = value
                    case ContractTag.METADATA:
                        metadata[key] = value
                    case _:
                        assert_never(tag)

        return ContractDump(
            hash=contract_hash,
            attrs=attrs,
            balances=balances,
            metadata=metadata,
        )

    def _iter_blocks(self) -> Iterator[Block]:
        empty_root_id = Node(key=b'', length=0).calculate_id()
        block = self.tx_storage.get_best_block()

        while block.get_metadata().nc_block_root_id not in {empty_root_id, None}:
            yield block
            block = block.get_block_parent()
