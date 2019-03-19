from argparse import Namespace
from typing import Any, Callable, Dict, List

from hathor.cli.run_node import RunNode


def get_ipython(extra_args: List, imported_objects: Dict[str, Any]) -> Callable:
    from IPython import start_ipython

    def run_ipython():
        start_ipython(argv=extra_args, user_ns=imported_objects)

    return run_ipython


class Shell(RunNode):
    def start_manager(self) -> None:
        pass

    def register_resources(self, args: Namespace) -> None:
        imported_objects: Dict[str, Any] = {}
        imported_objects['tx_storage'] = self.tx_storage
        if args.wallet:
            imported_objects['wallet'] = self.wallet
        imported_objects['manager'] = self.manager
        self.shell = get_ipython(self.extra_args, imported_objects)

        print()
        print('--- Injected globals ---')
        for name, obj in imported_objects.items():
            print(name, obj)
        print('------------------------')
        print()

    def parse_args(self, argv) -> Namespace:
        # TODO: add help for the `--` extra argument separator
        extra_args: List[str] = []
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
