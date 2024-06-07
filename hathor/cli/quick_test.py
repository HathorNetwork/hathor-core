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

import os
from argparse import ArgumentParser
from typing import Any

from hathor.cli.run_node import RunNode


class QuickTest(RunNode):

    @classmethod
    def create_parser(cls) -> ArgumentParser:
        parser = super().create_parser()
        parser.add_argument('--no-wait', action='store_true', help='If set will not wait for a new tx before exiting')
        parser.add_argument('--quit-after-n-blocks', type=int, help='Quit the full node after N blocks have synced. '
                                                                    'This is useful for sync benchmarks.')
        return parser

    def prepare(self, *, register_resources: bool = True) -> None:
        from hathor.transaction import BaseTransaction, Block
        super().prepare(register_resources=False)
        self._no_wait = self._args.no_wait

        self.log.info('patching on_new_tx to quit on success')
        orig_on_new_tx = self.manager.on_new_tx

        def patched_on_new_tx(*args: Any, **kwargs: Any) -> bool:
            res = orig_on_new_tx(*args, **kwargs)
            msg: str | None = None

            if self._args.quit_after_n_blocks is None:
                should_quit = res
                msg = 'added a tx'
            else:
                vertex = args[0]
                should_quit = False
                assert isinstance(vertex, BaseTransaction)

                if isinstance(vertex, Block):
                    should_quit = vertex.get_height() >= self._args.quit_after_n_blocks
                    msg = f'reached height {vertex.get_height()}'

            if should_quit:
                assert msg is not None
                self.log.info(f'successfully {msg}, exit now')
                self.manager.connections.disconnect_all_peers(force=True)
                self.reactor.fireSystemEvent('shutdown')
                os._exit(0)
            return res
        self.manager.on_new_tx = patched_on_new_tx

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
