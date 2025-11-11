# Copyright 2024 Hathor Labs
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

import sys
from argparse import ArgumentParser, FileType

from twisted.internet.defer import Deferred
from twisted.internet.task import deferLater

from hathor_cli.run_node import RunNode


class LoadFromLogs(RunNode):
    @classmethod
    def create_parser(cls) -> ArgumentParser:
        parser = super().create_parser()
        parser.add_argument('--log-dump', type=FileType('r', encoding='UTF-8'), default=sys.stdin, nargs='?',
                            help='Where to read logs from, defaults to stdin. Should be pre-parsed with parse-logs.')
        return parser

    def run(self) -> None:
        self.reactor.callLater(0, lambda: Deferred.fromCoroutine(self._load_from_logs()))
        super().run()

    async def _load_from_logs(self) -> None:
        from hathor.conf.get_settings import get_global_settings
        from hathor.transaction.vertex_parser import VertexParser
        settings = get_global_settings()
        parser = VertexParser(settings=settings)

        while True:
            line_with_break = self._args.log_dump.readline()
            if not line_with_break:
                break
            if line_with_break.startswith('//'):
                continue
            line = line_with_break.strip()
            vertex_bytes = bytes.fromhex(line)
            vertex = parser.deserialize(vertex_bytes)
            await deferLater(self.reactor, 0, self.manager.on_new_tx, vertex)

        self.manager.connections.disconnect_all_peers(force=True)
        self.reactor.fireSystemEvent('shutdown')


def main():
    LoadFromLogs().run()
