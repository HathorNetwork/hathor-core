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

from argparse import ArgumentParser, FileType
from enum import StrEnum, auto

from typing_extensions import assert_never

from hathor_cli.run_node import RunNode


class OutputFormat(StrEnum):
    JSON = auto()
    YAML = auto()


class NcDump(RunNode):
    def start_manager(self) -> None:
        pass

    def register_signal_handlers(self) -> None:
        pass

    @classmethod
    def create_parser(cls) -> ArgumentParser:
        parser = super().create_parser()
        parser.add_argument(
            '--dump-to',
            type=FileType('w', encoding='UTF-8'),
            required=True,
            help='Dump to this file',
        )
        parser.add_argument(
            '--format',
            type=lambda s: OutputFormat(s.lower()),
            choices=list(OutputFormat),
            default=OutputFormat.YAML,
            help='Output format (default: yaml)',
        )
        return parser

    def prepare(self, *, register_resources: bool = True) -> None:
        super().prepare(register_resources=False)
        self.out_file = self._args.dump_to
        self.output_format = self._args.format

    def run(self) -> None:
        from hathor.nanocontracts.nc_dump import NCDumper

        self.log.info('collecting nc dump')
        dumper = NCDumper(settings=self.manager._settings, tx_storage=self.tx_storage)
        nc_dump = dumper.get_nc_dump()

        self.log.info('exporting nc dump', format=self.output_format.value)
        match self.output_format:
            case OutputFormat.JSON:
                output = nc_dump.json_dumpb(sort_keys=True).decode('utf-8')
            case OutputFormat.YAML:
                output = nc_dump.yaml_dumps(sort_keys=True)
            case _:
                assert_never(self.output_format)

        self.out_file.write(output)
        self.log.info('exported', blocks_count=len(nc_dump.blocks))


def main():
    NcDump().run()
