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

import os
from argparse import ArgumentParser
from typing import TYPE_CHECKING, Any, Generator

from structlog import get_logger
from twisted.internet.defer import inlineCallbacks

from hathor_cli.run_node import RunNode

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction, Block, Transaction

logger = get_logger()


class VertexHandlerWrapper:
    def __init__(self, vertex_handler, manager, n_blocks):
        self.log = logger.new()
        self._vertex_handler = vertex_handler
        self._manager = manager
        self._n_blocks = n_blocks or 0

    @inlineCallbacks
    def on_new_block(self, block: Block, *args: Any, **kwargs: Any) -> Generator[Any, Any, bool]:
        res = yield self._vertex_handler.on_new_block(block, *args, **kwargs)
        if block.get_height() >= self._n_blocks:
            self.log.info(f'successfully reached height {block.get_height()}, exit now')
            self._manager.connections.disconnect_all_peers(force=True)
            self._manager.reactor.fireSystemEvent('shutdown')
            os._exit(0)
        return res

    def on_new_mempool_transaction(self, tx: Transaction) -> bool:
        return self._vertex_handler.on_new_mempool_transaction(tx)

    def on_new_relayed_vertex(self, vertex: BaseTransaction, *args: Any, **kwargs: Any) -> bool:
        return self._vertex_handler.on_new_mempool_transaction(vertex, *args, **kwargs)


class QuickTest(RunNode):
    @classmethod
    def create_parser(cls) -> ArgumentParser:
        parser = super().create_parser()
        parser.add_argument('--no-wait', action='store_true', help='If set will not wait for a new tx before exiting')
        parser.add_argument('--quit-after-n-blocks', type=int, help='Quit the full node after N blocks have synced. '
                                                                    'This is useful for sync benchmarks.')
        return parser

    def prepare(self, *, register_resources: bool = True) -> None:
        from hathor.p2p.sync_v2.factory import SyncV2Factory
        from hathor.p2p.sync_version import SyncVersion

        super().prepare(register_resources=False)
        self._no_wait = self._args.no_wait

        self.log.info('patching vertex_handler.on_new_vertex to quit on success')
        p2p_factory = self.manager.connections.get_sync_factory(SyncVersion.V2)
        assert isinstance(p2p_factory, SyncV2Factory)
        p2p_factory.vertex_handler = VertexHandlerWrapper(
            self.manager.vertex_handler,
            self.manager,
            self._args.quit_after_n_blocks,
        )  # type: ignore

        timeout = 300
        self.log.info('exit with error code if it take too long', timeout=timeout)

        def exit_with_error():
            self.log.error('took too long to get a tx, exit with error')
            self.manager.connections.disconnect_all_peers(force=True)
            self.reactor.stop()
            os._exit(1)

        if self._args.quit_after_n_blocks is None:
            self.reactor.callLater(timeout, exit_with_error)

    def run(self) -> None:
        if self._no_wait:
            return
        super().run()


def main():
    QuickTest().run()
