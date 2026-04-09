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
from argparse import ArgumentParser, FileType
from typing import TYPE_CHECKING, Iterator, Optional

from hathor_cli.run_node import RunNode

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction

MAGIC_HEADER = b'HathDB'


class DbExport(RunNode):
    def start_manager(self) -> None:
        pass

    def register_signal_handlers(self) -> None:
        pass

    @classmethod
    def create_parser(cls) -> ArgumentParser:
        from hathor.conf.get_settings import get_global_settings
        settings = get_global_settings()

        def max_height(arg: str) -> Optional[int]:
            if arg.lower() == 'checkpoint':
                if not settings.CHECKPOINTS:
                    raise ValueError('There are no checkpoints to use')
                return settings.CHECKPOINTS[-1].height
            elif arg:
                return int(arg)
            else:
                return None

        parser = super().create_parser()
        parser.add_argument('--export-file', type=FileType('wb', 0), required=True,
                            help='Save the export to this file')
        parser.add_argument('--export-iterator', choices=['metadata', 'timestamp_index', 'dfs'], default='metadata',
                            help='Which method of iterating to use, don\'t change unless you know what it does')
        parser.add_argument('--export-max-height', type=max_height,
                            help='Make no assumption about the mempool when using this option. It may be partially'
                            'exported or not, depending on the timestamps and the traversal algorithm.')
        parser.add_argument('--export-skip-voided', action='store_true', help='Do not export voided txs/blocks')
        return parser

    def prepare(self, *, register_resources: bool = True) -> None:
        super().prepare(register_resources=False)

        # allocating io.BufferedWriter here so we "own" it
        self.out_file = io.BufferedWriter(self._args.export_file)
        if not self.out_file.seekable():
            raise ValueError('file cannot be used because it is not seekable')

        self._iter_tx: Iterator['BaseTransaction']
        if self._args.export_iterator == 'metadata':
            self._iter_tx = self.tx_storage._topological_sort_metadata()
        elif self._args.export_iterator == 'timestamp_index':
            self._iter_tx = self.tx_storage._topological_sort_timestamp_index()
        elif self._args.export_iterator == 'dfs':
            self._iter_tx = self.tx_storage._topological_sort_dfs()
        else:
            raise ValueError(f'unknown iterator "{self._args.export_iterator}"')

        self.export_height = self._args.export_max_height
        self.skip_voided = self._args.export_skip_voided

    def iter_tx(self) -> Iterator['BaseTransaction']:
        from hathor.conf.get_settings import get_global_settings
        settings = get_global_settings()
        soft_voided_ids = set(settings.SOFT_VOIDED_TX_IDS)

        for tx in self._iter_tx:
            # XXX: if we're skipping voided transactions, we have to be careful not to skip soft-voided ones
            if self.skip_voided:
                voided_by = tx.get_metadata().voided_by or set()
                soft_voided_by = voided_by & soft_voided_ids
                if voided_by and not soft_voided_by:
                    continue
            yield tx

    def run(self) -> None:
        from hathor.transaction import Block
        from hathor.util import tx_progress
        self.log.info('export')
        self.out_file.write(MAGIC_HEADER)
        tx_count = 0
        block_count = 0
        best_height = 0
        # XXX: pre-write the count to reserve the space, we will seek to it and write the correct value at the end
        write_pos_count = self.out_file.tell()
        self.out_file.write(struct.pack('!I', tx_count))
        self.out_file.write(struct.pack('!I', block_count))
        # estimated total, this will obviously be wrong if we're not exporting everything, but it's still better than
        # nothing, and it's probably better to finish sooner than expected, rather than later than expected
        total = self.tx_storage.get_vertices_count()
        for tx in tx_progress(self.iter_tx(), log=self.log, total=total):
            tx_meta = tx.get_metadata()
            if tx.is_block:
                assert isinstance(tx, Block)
                if not tx_meta.voided_by:
                    # XXX: max() shouldn't be needed, but just in case
                    best_height = max(best_height, tx.get_height())
                block_count += 1
            else:
                tx_count += 1
            # write tx
            if tx.is_genesis:
                continue
            tx_bytes = bytes(tx)
            self.out_file.write(struct.pack('!I', len(tx_bytes)))
            self.out_file.write(tx_bytes)
            # stop as soon as we reach our target height (if any) and after writing it
            if self.export_height is not None and best_height >= self.export_height:
                break
        # warn if we haven't reached self.export_height
        if self.export_height is not None and best_height < self.export_height:
            self.log.warn('max export height not reached', best_height=best_height)
        # finally, write the correct counts and close
        self.out_file.seek(write_pos_count)
        self.out_file.write(struct.pack('!I', tx_count))
        self.out_file.write(struct.pack('!I', block_count))
        self.out_file.flush()
        del self.out_file
        self.log.info('exported', tx_count=tx_count, block_count=block_count)


def main():
    DbExport().run()
