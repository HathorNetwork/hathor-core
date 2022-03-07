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

import datetime
import io
import struct
import sys
import time
from argparse import Namespace

from hathor.cli.run_node import RunNode

MAGIC_HEADER = b'HathDB'


class DbImport(RunNode):
    def start_manager(self, args: Namespace) -> None:
        pass

    def register_signal_handlers(self, args: Namespace) -> None:
        pass

    def register_resources(self, args: Namespace) -> None:
        pass

    def run(self) -> None:
        from hathor.transaction.base_transaction import tx_or_block_from_bytes
        from hathor.util import LogDuration

        f = io.BufferedReader(io.FileIO('db.bin', 'rb'))
        header = f.read(len(MAGIC_HEADER))
        if header != MAGIC_HEADER:
            self.log.error('wrong header, not a valid file')
            sys.exit(1)

        self.tx_storage.pre_init()

        t0 = time.time()
        t1 = t0
        cnt = 0
        cnt2 = 0
        t2 = t0
        h = 0

        block_count = 0
        tx_count = 0

        self.log.info('import database')
        while True:
            # read tx
            tx_len_bytes = f.read(4)
            if len(tx_len_bytes) != 4:
                break
            tx_len, = struct.unpack('!I', tx_len_bytes)
            tx_bytes = f.read(tx_len)
            if len(tx_bytes) != tx_len:
                self.log.error('unexpected end of file', expected=tx_len, got=len(tx_bytes))
                sys.exit(2)
            tx = tx_or_block_from_bytes(tx_bytes)
            assert tx is not None
            assert tx is not None
            assert tx.hash is not None
            tx.storage = self.tx_storage

            self.manager.on_new_tx(tx, quiet=True, fails_silently=False, skip_block_weight_verification=True)

            tx_meta = tx.get_metadata()
            t2 = time.time()
            dt = LogDuration(t2 - t1)
            dcnt = cnt - cnt2
            tx_rate = '?' if dt == 0 else dcnt / dt
            h = max(h, tx_meta.height)
            if dt > 30:
                ts_date = datetime.datetime.fromtimestamp(self.tx_storage.latest_timestamp)
                if h == 0:
                    self.log.debug('start importing...')
                else:
                    self.log.info('importing...', tx_rate=tx_rate, tx_new=dcnt, dt=dt,
                                  total=cnt, latest_ts=ts_date, height=h)
                t1 = t2
                cnt2 = cnt
            cnt += 1

            if tx.is_block:
                block_count += 1
            else:
                tx_count += 1

        tdt = LogDuration(t2 - t0)
        tx_rate = '?' if tdt == 0 else cnt / tdt
        self.log.info('imported', tx_count=cnt, tx_rate=tx_rate, total_dt=tdt, height=h, blocks=block_count,
                      txs=tx_count)


def main():
    DbImport().run()
