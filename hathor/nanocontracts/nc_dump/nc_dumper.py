#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from abc import ABC, abstractmethod
from collections import OrderedDict
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass
from io import TextIOBase
from typing import Any, Callable, TypeAlias

from structlog import get_logger
from typing_extensions import assert_never

from hathor import __version__
from hathor.conf.settings import HathorSettings
from hathor.nanocontracts.storage.block_storage import _Tag as BlockTrieTag
from hathor.nanocontracts.storage.patricia_trie import Node, NodeId, PatriciaTrie
from hathor.transaction import Block
from hathor.transaction.storage import TransactionRocksDBStorage
from hathor.types import VertexId

logger = get_logger()

_MAGIC_HEADER = 'HATHOR_NCDUMP\n'
_EMPTY_ROOT_ID = Node(key=b'', length=0).calculate_id()


@dataclass(slots=True, frozen=True)
class DumpUntilComplete:
    pass


@dataclass(slots=True, frozen=True)
class DumpUntilBlock:
    hash: bytes


@dataclass(slots=True, frozen=True)
class DumpUntilHeight:
    height: int


@dataclass(slots=True, frozen=True)
class DumpUntilCommon:
    pass


DumpMode: TypeAlias = DumpUntilComplete | DumpUntilBlock | DumpUntilHeight | DumpUntilCommon


class NCDumper(ABC):
    __slots__ = ('_log', '_settings', '_tx_storage', '_start_block', '_out', '_mode')

    def __init__(
        self,
        *,
        settings: HathorSettings,
        tx_storage: TransactionRocksDBStorage,
        start_block: VertexId | None,
        out: TextIOBase,
        mode: DumpMode,
    ) -> None:
        self._log = logger.new()
        self._settings = settings
        self._tx_storage = tx_storage
        self._start_block = start_block
        self._out = out
        self._mode = mode

    def _iter_local_blocks(self) -> Iterator[Block]:
        block = self._tx_storage.get_best_block()
        if self._start_block:
            block = self._tx_storage.get_block(self._start_block)

        while block.get_metadata().nc_block_root_id not in {_EMPTY_ROOT_ID, None}:
            yield block
            block = block.get_block_parent()

    @abstractmethod
    def _trie_iter_dfs(self, root_id: bytes) -> AsyncIterator[Node]:
        raise NotImplementedError

    @abstractmethod
    async def _get_block_root_id(self, block: Block) -> bytes:
        raise NotImplementedError

    async def _get_sorted_key_values_from_trie(
        self,
        root_id: bytes,
        *,
        sort_by_value: bool,
    ) -> OrderedDict[bytes, bytes]:
        key_values = {}
        async for node in self._trie_iter_dfs(root_id):
            if value := node.content:
                key = PatriciaTrie._decode_key(node.key)
                assert key not in key_values
                key_values[key] = value

        # XXX: sort by flipping the first byte of the key, so balances show up first
        key_fun: Callable[[Any], tuple[Any, ...]] = lambda kv: (-kv[0][0], kv[0][1:])
        if sort_by_value:
            key_fun = lambda kv: (-kv[0][0], kv[1], kv[0])
        return OrderedDict(sorted(key_values.items(), key=key_fun))

    async def dump(self) -> None:
        self._log.info('dump starting...')
        visited_root_ids = set()
        collected_blocks = 0

        self._out.writelines((
            _MAGIC_HEADER,
            f'VERSION: {__version__}\n',
            f'NETWORK: {self._settings.NETWORK_NAME}\n',
        ))

        for block in self._iter_local_blocks():
            block_root_id = await self._get_block_root_id(block)
            stop_reason: str | None = None

            match self._mode:
                case DumpUntilComplete():
                    pass
                case DumpUntilBlock(block_hash):
                    if block.hash == block_hash:
                        stop_reason = 'reached block hash'
                case DumpUntilHeight(height):
                    if block.get_height() <= height:
                        stop_reason = 'reached block height'
                case DumpUntilCommon():
                    meta = block.get_metadata()
                    assert meta.nc_block_root_id is not None
                    if block_root_id == meta.nc_block_root_id:
                        stop_reason = 'common root id'
                case _:
                    assert_never(self._mode)

            if block_root_id in visited_root_ids and stop_reason is None:
                continue

            visited_root_ids.add(block_root_id)
            collected_blocks += 1
            self._out.writelines([
                '---\n',
                f'HEIGHT: {block.get_height()}\n',
                f'BLOCK: {block.hash_hex}\n',
            ])
            self._log.info('dumping block', hash=block.hash_hex, height=block.get_height())

            # BLOCK STORAGE:
            if block_key_values := await self._get_sorted_key_values_from_trie(block_root_id, sort_by_value=False):
                self._out.write(f'- BLOCK ROOT: {block_root_id.hex()}\n')
                for key, value in block_key_values.items():
                    self._out.write(f'  {key.hex()}: {value.hex()}\n')

            # CONTRACT STORAGES:
            contract_root_ids: dict = {
                key[1:]: NodeId(value)
                for key, value in block_key_values.items()
                if key.startswith(BlockTrieTag.CONTRACT.value)
            }

            for contract_id, contract_root_id in contract_root_ids.items():
                if contract_root_id in visited_root_ids:
                    continue

                visited_root_ids.add(contract_root_id)
                contract_key_values = await self._get_sorted_key_values_from_trie(contract_root_id, sort_by_value=True)

                if contract_key_values:
                    self._out.write(f'- CONTRACT ROOT: {contract_root_id.hex()}\n')
                    for key, value in contract_key_values.items():
                        self._out.write(f'  {key.hex()}: {value.hex()}\n')

            if stop_reason is not None:
                self._log.info(f'stopping early, {stop_reason}', block=block.hash_hex, height=block.get_height())
                break

        self._log.info('exported', states_count=collected_blocks)
