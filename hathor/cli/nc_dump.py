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

from argparse import ArgumentParser, FileType
from typing import TYPE_CHECKING, Iterator

from hathor.cli.run_node import RunNode

if TYPE_CHECKING:
    from hathor.transaction import Block

MAGIC_HEADER = 'HATHOR_NCDUMP\n'


class NcDump(RunNode):
    def start_manager(self) -> None:
        pass

    def register_signal_handlers(self) -> None:
        pass

    @classmethod
    def create_parser(cls) -> ArgumentParser:
        parser = super().create_parser()
        parser.add_argument(
            '--dump-to',
            type=FileType('w', encoding='UTF-8'),
            required=True,
            help='Dump to this file',
        )
        return parser

    def prepare(self, *, register_resources: bool = True) -> None:
        super().prepare(register_resources=False)
        self.out_file = self._args.dump_to

    def iter_blocks(self) -> Iterator['Block']:
        from hathor.nanocontracts.storage.patricia_trie import Node

        empty_root_id = Node(key=b'', length=0).calculate_id()
        block = self.tx_storage.get_best_block()
        while block.get_metadata().nc_block_root_id not in {empty_root_id, None}:
            yield block
            block = block.get_block_parent()

    def run(self) -> None:
        from hathor import __version__
        from hathor.nanocontracts.storage.patricia_trie import NodeId
        from hathor.types import VertexId
        from hathor.util import not_none

        self.log.info('collecting nc-root-ids')
        visited_nc_root_ids = set()
        collected_blocks: list[tuple[int, VertexId, NodeId]] = []
        for block in self.iter_blocks():
            nc_root_id = NodeId(not_none(block.get_metadata().nc_block_root_id))
            if nc_root_id not in visited_nc_root_ids:
                visited_nc_root_ids.add(nc_root_id)
                collected_blocks.append((block.get_height(), block.hash, nc_root_id))

        self.log.info('export nc-states')

        self.out_file.writelines([
            MAGIC_HEADER,
            f'VERSION: {__version__}\n',
            f'NETWORK: {self.manager._settings.NETWORK_NAME}\n',
        ])
        nc_storage_factory = self.manager.consensus_algorithm.nc_storage_factory
        for block_height, block_hash, nc_root_id in collected_blocks:
            self.out_file.writelines([
                '---\n',
                f'HEIGHT: {block_height}\n',
                f'BLOCK: {block_hash.hex()}\n',
                f'ROOT: {nc_root_id.hex()}\n',
            ])
            block_trie = nc_storage_factory.get_block_storage(nc_root_id)._block_trie
            key_values = {}
            for iter_node in block_trie.iter_dfs():
                node = iter_node.node
                if node.content is not None:
                    key = block_trie._decode_key(node.key)
                    value = node.content
                    key_values[key] = value
            # XXX: sort by flipping the first byte of the key, so balances show up first
            for key, value in sorted(key_values.items(), key=(lambda kv: (-kv[0][0], kv[0][1:]))):
                self.out_file.write(f'{key.hex()}: {value.hex()}\n')

        self.log.info('exported', states_count=len(collected_blocks))


def main():
    NcDump().run()
