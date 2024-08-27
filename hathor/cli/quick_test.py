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
        from hathor.transaction import Block, Vertex
        from hathor.transaction.base_transaction import GenericVertex
        super().prepare(register_resources=False)
        self._no_wait = self._args.no_wait

        self.log.info('patching on_new_tx to quit on success')
        orig_on_new_vertex = type(self.manager.vertex_handler).on_new_vertex
        orig_on_new_vertex_async = type(self.manager.vertex_handler).on_new_vertex_async

        def patch(vertex: Vertex, res: bool) -> bool:
            msg: str | None = None

            if self._args.quit_after_n_blocks is None:
                should_quit = res
                msg = 'added a tx'
            else:
                should_quit = False
                assert isinstance(vertex, GenericVertex)

                if isinstance(vertex, Block):
                    should_quit = vertex.get_height() >= self._args.quit_after_n_blocks
                    msg = f'reached height {vertex.get_height()}'

            if should_quit:
                assert msg is not None
                self.log.info(f'successfully {msg}, exit now')
                self.manager.connections.disconnect_all_peers(force=True)
                self.reactor.fireSystemEvent('shutdown')
                return
                os._exit(0)
            return res

        def patched_on_new_vertex(*args, **kwargs):
            vertex = args[1]
            res = orig_on_new_vertex(*args, **kwargs)
            return patch(vertex, res)

        async def patched_on_new_vertex_async(*args, **kwargs):
            vertex = args[1]
            # print(args, kwargs)
            res = await orig_on_new_vertex_async(*args, **kwargs)
            return patch(vertex, res)

        setattr(type(self.manager.vertex_handler), 'on_new_vertex', patched_on_new_vertex)
        setattr(type(self.manager.vertex_handler), 'on_new_vertex_async', patched_on_new_vertex_async)

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
