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

import re
import sys
from argparse import ArgumentParser, FileType

from hathor.cli.run_node import RunNode


class LoadFromLogs(RunNode):
    def start_manager(self) -> None:
        pass

    def register_signal_handlers(self) -> None:
        pass

    @classmethod
    def create_parser(cls) -> ArgumentParser:
        parser = super().create_parser()
        parser.add_argument('--log-dump', type=FileType('r', encoding='UTF-8'), default=sys.stdin, nargs='?',
                            help='Where to read logs from, defaults to stdin.')
        return parser

    def prepare(self, *, register_resources: bool = True) -> None:
        super().prepare(register_resources=False)

    def run(self) -> None:
        from hathor.transaction.base_transaction import tx_or_block_from_bytes

        pattern = r'new (tx|block)    .*bytes=([^ ]*) '
        pattern = r'new (tx|block)    .*bytes=([^ ]*) '
        compiled_pattern = re.compile(pattern)

        while True:
            line_with_break = self._args.log_dump.readline()
            if not line_with_break:
                break
            line = line_with_break.strip()

            matches = compiled_pattern.findall(line)
            if len(matches) == 0:
                continue

            assert len(matches) == 1
            _, vertex_bytes_hex = matches[0]

            vertex_bytes = bytes.fromhex(vertex_bytes_hex)
            vertex = tx_or_block_from_bytes(vertex_bytes)
            self.manager.on_new_tx(vertex)


def main():
    LoadFromLogs().run()
