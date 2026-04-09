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

import io
import struct
import sys
from argparse import ArgumentParser, FileType
from typing import TYPE_CHECKING, Iterator

from hathor_cli.run_node import RunNode

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction


class DbImport(RunNode):
    def start_manager(self) -> None:
        pass

    def register_signal_handlers(self) -> None:
        pass

    @classmethod
    def create_parser(cls) -> ArgumentParser:
        parser = super().create_parser()
        parser.add_argument('--import-file', type=FileType('rb', 0), required=True,
                            help='Save the export to this file')
        return parser

    def prepare(self, *, register_resources: bool = True) -> None:
        super().prepare(register_resources=False)

        # allocating io.BufferedReader here so we "own" it
        self.in_file = io.BufferedReader(self._args.import_file)

    def run(self) -> None:
        from hathor_cli.db_export import MAGIC_HEADER
        from hathor.util import tx_progress

        header = self.in_file.read(len(MAGIC_HEADER))
        if header != MAGIC_HEADER:
            self.log.error('wrong header, not a valid file')
            sys.exit(1)

        tx_count, = struct.unpack('!I', self.in_file.read(4))
        block_count, = struct.unpack('!I', self.in_file.read(4))
        total = tx_count + block_count
        self.log.info('import database', tx_count=tx_count, block_count=block_count)
        self.tx_storage.pre_init()
        actual_tx_count = 0
        actual_block_count = 0
        for tx in tx_progress(self._import_txs(), log=self.log, total=total):
            if tx.is_block:
                actual_block_count += 1
            else:
                actual_tx_count += 1
        if actual_block_count != block_count:
            self.log.error('block count mismatch', expected=block_count, actual=actual_block_count)
        if actual_tx_count != tx_count:
            self.log.error('tx count mismatch', expected=tx_count, actual=actual_tx_count)
        del self.in_file
        self.log.info('imported', tx_count=tx_count, block_count=block_count)

    def _import_txs(self) -> Iterator['BaseTransaction']:
        from hathor.conf.get_settings import get_global_settings
        from hathor.transaction.vertex_parser import VertexParser
        settings = get_global_settings()
        parser = VertexParser(settings=settings)
        while True:
            # read tx
            tx_len_bytes = self.in_file.read(4)
            if len(tx_len_bytes) != 4:
                break
            tx_len, = struct.unpack('!I', tx_len_bytes)
            tx_bytes = self.in_file.read(tx_len)
            if len(tx_bytes) != tx_len:
                self.log.error('unexpected end of file', expected=tx_len, got=len(tx_bytes))
                sys.exit(2)
            tx = parser.deserialize(tx_bytes)
            assert tx is not None
            tx.storage = self.tx_storage
            self.manager.on_new_tx(tx, quiet=True)
            yield tx


def main():
    DbImport().run()
