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

from argparse import Namespace
from typing import Any, Callable

from hathor_cli.run_node import RunNode


def get_ipython(extra_args: list[Any], imported_objects: dict[str, Any]) -> Callable[[], None]:
    from IPython import start_ipython

    def run_ipython():
        start_ipython(argv=extra_args, user_ns=imported_objects)

    return run_ipython


class Shell(RunNode):
    def start_manager(self) -> None:
        pass

    def register_signal_handlers(self) -> None:
        pass

    def prepare(self, *, register_resources: bool = True) -> None:
        super().prepare(register_resources=False)

        imported_objects: dict[str, Any] = {}
        imported_objects['tx_storage'] = self.tx_storage
        if self._args.wallet:
            imported_objects['wallet'] = self.wallet
        imported_objects['manager'] = self.manager
        self.shell = get_ipython(self.extra_args, imported_objects)

        print()
        print('--- Injected globals ---')
        for name, obj in imported_objects.items():
            print(name, obj)
        print('------------------------')
        print()

    def parse_args(self, argv: list[str]) -> Namespace:
        # TODO: add help for the `--` extra argument separator
        extra_args: list[str] = []
        if '--' in argv:
            idx = argv.index('--')
            extra_args = argv[idx + 1:]
            argv = argv[:idx]
        self.extra_args = extra_args
        return self.parser.parse_args(argv)

    def run(self) -> None:
        self.shell()


def main():
    Shell().run()
