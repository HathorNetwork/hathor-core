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
import time
from argparse import Namespace
from typing import Optional

from hathor.cli.run_node import RunNode

MAGIC_HEADER = b'HathDB'


class DbExport(RunNode):
    def start_manager(self, args: Namespace) -> None:
        pass

    def register_signal_handlers(self, args: Namespace) -> None:
        pass

    def register_resources(self, args: Namespace) -> None:
        pass

    def run(self) -> None:
        from hathor.util import LogDuration

        # TODO: parametrize file_name
        # TODO: parametrize export_height
        export_height: Optional[int] = 2_200_000
        f = io.BufferedWriter(io.FileIO('db.bin', 'wb'))
        f.write(MAGIC_HEADER)

        t0 = time.time()
        t1 = t0
        cnt = 0
        cnt2 = 0
        t2 = t0
        h = 0

        block_count = 0
        tx_count = 0

        self.log.info('export database')
        for tx in self.tx_storage._topological_sort():
            assert tx.hash is not None

            tx_meta = tx.get_metadata()
            t2 = time.time()
            dt = LogDuration(t2 - t1)
            dcnt = cnt - cnt2
            tx_rate = '?' if dt == 0 else dcnt / dt
            h = max(h, tx_meta.height)
            if dt > 30:
                ts_date = datetime.datetime.fromtimestamp(self.tx_storage.latest_timestamp)
                if h == 0:
                    self.log.debug('start exporting...')
                else:
                    self.log.info('exporting...', tx_rate=tx_rate, tx_new=dcnt, dt=dt,
                                  total=cnt, latest_ts=ts_date, height=h)
                t1 = t2
                cnt2 = cnt
            cnt += 1

            # write tx
            if not tx.is_genesis:
                tx_bytes = bytes(tx)
                f.write(struct.pack('!I', len(tx_bytes)) + tx_bytes)

            if tx.is_block:
                block_count += 1
                if export_height is not None and h >= export_height:
                    break
            else:
                tx_count += 1

            dt = LogDuration(time.time() - t2)
            if dt > 1:
                self.log.warn('tx took too long to write', tx=tx.hash_hex, dt=dt)

        self.log.debug('flush')
        f.flush()
        del f

        tdt = LogDuration(t2 - t0)
        tx_rate = '?' if tdt == 0 else cnt / tdt
        self.log.info('exported', tx_count=cnt, tx_rate=tx_rate, total_dt=tdt, height=h, blocks=block_count,
                      txs=tx_count)


def main():
    DbExport().run()
