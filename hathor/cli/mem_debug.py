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
import time
from argparse import Namespace
from typing import TYPE_CHECKING, Callable, Optional

from hathor.cli.run_node import RunNode

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction
    from hathor.util import Reactor

MAGIC_HEADER = b'HathDB'


class MemDebug(RunNode):
    def __init__(self, *, argv=None):
        super().__init__(argv=argv)

    def start_manager(self, args: Namespace) -> None:
        pass

    def register_signal_handlers(self, args: Namespace) -> None:
        pass

    def register_resources(self, args: Namespace) -> None:
        pass

    def get_reactor(self) -> 'Reactor':
        return self.simulator._clock  # type: ignore

    def prepare(self, args: Namespace) -> None:
        from hathor.simulator import Simulator
        from tests.unittest import PEER_ID_POOL
        self.simulator = Simulator(with_patch=False)
        self.simulator.start()
        self.rng = self.simulator.rng
        super().prepare(args)
        self.log.info('with simulator', seed=self.simulator.seed)
        self.manager.rng = self.rng
        self.manager.connections.rng = self.rng
        self.manager.listen_addresses = []  # XXX: erase listen addresses because simulator clock cannot simulate it
        self.manager.start()
        self.simulator.run_to_completion()
        self.simulator.add_peer('main', self.manager)
        self.manager2 = self.simulator.create_peer(
            network='mainnet',
            peer_id=self.rng.choice(PEER_ID_POOL),
            soft_voided_tx_ids=self.manager.soft_voided_tx_ids,
        )
        self.simulator.add_peer('secondary', self.manager2)

    def run(self) -> None:
        from hathor.simulator import FakeConnection
        self.manager.heap_stats_dump('dump_before')
        # self.apply(self.check_noop)
        # self.apply(self.check_add_to_all_indexes)
        # self.apply(self.check_add_to_small_indexes)
        # self.apply(self.check_add_to_not_tips_indexes)
        # self.apply(self.check_add_to_only_tips_indexes)
        self.manager.heap_stats_dump('dump_just_loaded')
        self.log.info('run simulator')
        conn = FakeConnection(self.manager, self.manager2, latency=0.01)
        conn.disable_idle_timeout()
        self.simulator.add_connection(conn)
        self.simulator.run(30.0)
        self.simulator.run_until_complete(36000.0)
        self.log.info('finished', tx_count=self.manager2.tx_storage.get_count_tx_blocks())
        self.manager2.stop()
        self.log.info('simulation complete')
        self.manager.heap_stats_dump('dump_after')
        self.manager.stop()

    def apply(self, fun: Callable[['BaseTransaction'], None]) -> None:
        from hathor.util import LogDuration

        t0 = time.time()
        t1 = t0
        cnt = 0
        cnt2 = 0
        t2 = t0
        h = 0
        # max_h: Optional[int] = 2_200_000
        max_h: Optional[int] = None

        block_count = 0
        tx_count = 0

        self.log.info('walk through database to populate caches/indexes')
        for tx in self.tx_storage._topological_fast():
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
                    self.log.debug('start walking...')
                else:
                    self.log.info('walking...', tx_rate=tx_rate, tx_new=dcnt, dt=dt,
                                  total=cnt, latest_ts=ts_date, height=h)
                t1 = t2
                cnt2 = cnt
            cnt += 1

            if not tx.is_genesis:
                # apply fun
                fun(tx)

            if tx.is_block:
                block_count += 1
            else:
                tx_count += 1

            dt = LogDuration(time.time() - t2)
            if dt > 1:
                self.log.warn('tx took too long to write', tx=tx.hash_hex, dt=dt)

            if max_h is not None and h > max_h:
                break

        self.log.debug('flush')

        tdt = LogDuration(t2 - t0)
        tx_rate = '?' if tdt == 0 else cnt / tdt
        self.log.info('walked', tx_count=cnt, tx_rate=tx_rate, total_dt=tdt, height=h, blocks=block_count,
                      txs=tx_count)

    def check_noop(self, tx: 'BaseTransaction') -> None:
        pass

    def check_add_to_all_indexes(self, tx: 'BaseTransaction') -> None:
        assert tx.hash is not None
        tx_meta = tx.get_metadata()
        self.tx_storage.add_to_indexes(tx)
        if tx.is_transaction and tx_meta.voided_by:
            self.tx_storage.del_from_indexes(tx)

    def check_add_to_small_indexes(self, tx: 'BaseTransaction') -> None:
        assert tx.hash is not None
        assert self.tx_storage.indexes is not None
        assert self.tx_storage.indexes.addresses is not None
        assert self.tx_storage.indexes.tokens is not None
        tx_meta = tx.get_metadata()
        if not tx_meta.voided_by:
            self.tx_storage.indexes.addresses.add_tx(tx)
            self.tx_storage.indexes.tokens.add_tx(tx)
            if tx.is_block:
                if tx_meta.validation.is_fully_connected():
                    self.tx_storage.indexes.height.add_reorg(tx_meta.height, tx.hash, tx.timestamp)
            if tx.is_transaction:
                if tx_meta.first_block is None:
                    self.tx_storage.indexes.mempool_tips.update(tx)

    def check_add_to_not_tips_indexes(self, tx: 'BaseTransaction') -> None:
        assert tx.hash is not None
        assert self.tx_storage.indexes is not None
        assert self.tx_storage.indexes.addresses is not None
        assert self.tx_storage.indexes.tokens is not None
        tx_meta = tx.get_metadata()
        if not tx_meta.voided_by:
            self.tx_storage.indexes.addresses.add_tx(tx)
            self.tx_storage.indexes.tokens.add_tx(tx)
            self.tx_storage.indexes.sorted_all.add_tx(tx)
            if tx.is_block:
                self.tx_storage.indexes.sorted_blocks.add_tx(tx)
                if tx_meta.validation.is_fully_connected():
                    self.tx_storage.indexes.height.add_reorg(tx_meta.height, tx.hash, tx.timestamp)
            if tx.is_transaction:
                self.tx_storage.indexes.sorted_txs.add_tx(tx)
                if tx_meta.first_block is None:
                    self.tx_storage.indexes.mempool_tips.update(tx)

    def check_add_to_only_tips_indexes(self, tx: 'BaseTransaction') -> None:
        assert tx.hash is not None
        assert self.tx_storage.indexes is not None
        tx_meta = tx.get_metadata()
        if not tx_meta.voided_by:
            self.tx_storage.indexes.all_tips.add_tx(tx)
            if tx.is_block:
                self.tx_storage.indexes.block_tips.add_tx(tx)
            if tx.is_transaction:
                self.tx_storage.indexes.tx_tips.add_tx(tx)


def main():
    MemDebug().run()
