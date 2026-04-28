# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
