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

import threading
from argparse import Namespace
from contextlib import suppress
from typing import Any, Callable, TypeVar, cast

from hathor_cli.run_node import RunNode

T = TypeVar('T')


def get_ipython(
        extra_args: list[Any],
        imported_objects: dict[str, Any],
        *,
        config: Any | None = None,
) -> Callable[[], None]:
    from IPython import start_ipython

    def run_ipython():
        start_ipython(argv=extra_args, user_ns=imported_objects, config=config)

    return run_ipython


class Shell(RunNode):
    _reactor_thread: threading.Thread | None = None
    _shell_run_node: bool = False

    @classmethod
    def create_parser(cls):
        parser = super().create_parser()
        parser.add_argument(
            '--x-run-node',
            action='store_true',
            help='Start the full node in the background while keeping the interactive shell open.'
        )
        return parser

    def start_manager(self) -> None:
        if not self._shell_run_node:
            return

        super().start_manager()
        self._start_reactor_thread()

    def register_signal_handlers(self) -> None:
        pass

    def prepare(self, *, register_resources: bool = True) -> None:
        super().prepare(register_resources=self._shell_run_node)

        imported_objects: dict[str, Any] = {}
        imported_objects['tx_storage'] = self.tx_storage
        if self._args.wallet:
            imported_objects['wallet'] = self.wallet
        imported_objects['manager'] = self.manager
        imported_objects['reactor'] = self.reactor
        ipy_config: Any | None = None

        if self._shell_run_node:
            import asyncio
            from twisted.internet.defer import Deferred
            from traitlets.config import Config

            async def await_deferred(deferred: Deferred[T]) -> T:
                loop = asyncio.get_running_loop()
                return await deferred.asFuture(loop)

            imported_objects['await_deferred'] = await_deferred
            imported_objects['asyncio'] = asyncio
            ipy_config = Config()
            ipy_config.InteractiveShellApp.extra_extensions = ['hathor_cli._shell_extension']

        self.shell = get_ipython(self.extra_args, imported_objects, config=ipy_config)

        print()
        print('--- Injected globals ---')
        for name, obj in imported_objects.items():
            print(name, obj)
        print('------------------------')
        print()
        if self._shell_run_node:
            print('Node reactor started in background. Use await_deferred() for Deferreds.')

    def parse_args(self, argv: list[str]) -> Namespace:
        # TODO: add help for the `--` extra argument separator
        argv = list(argv)
        extra_args: list[str] = []
        if '--' in argv:
            idx = argv.index('--')
            extra_args = argv[idx + 1:]
            argv = argv[:idx]
        self.extra_args = extra_args
        namespace = self.parser.parse_args(argv)
        self._shell_run_node = bool(getattr(namespace, 'x_run_node', False))
        return namespace

    def run(self) -> None:
        try:
            self.shell()
        finally:
            if self._shell_run_node:
                self._shutdown_background()

    def _start_reactor_thread(self) -> None:
        if self._reactor_thread and self._reactor_thread.is_alive():
            return

        def run_reactor() -> None:
            self.log.info('reactor thread starting')
            try:
                run = getattr(self.reactor, 'run')
                try:
                    run(installSignalHandlers=False)
                except TypeError:
                    run()
            finally:
                self.log.info('reactor thread finished')

        self._reactor_thread = threading.Thread(
            target=run_reactor,
            name='hathor-reactor',
            daemon=True,
        )
        self._reactor_thread.start()

    def _shutdown_background(self) -> None:
        thread = self._reactor_thread
        if thread and thread.is_alive():
            try:
                from twisted.internet.interfaces import IReactorFromThreads

                threaded_reactor = cast(IReactorFromThreads, self.reactor)
                threaded_reactor.callFromThread(self.reactor.stop)
            except Exception:
                self.log.exception('failed to schedule reactor shutdown from shell')
            thread.join(timeout=30)
            if thread.is_alive():
                self.log.warning('reactor thread did not finish cleanly')
        self._reactor_thread = None
        if self._shell_run_node:
            self._restore_logging_streams()

    def _restore_logging_streams(self) -> None:
        try:
            from hathor_cli import _shell_extension
        except ImportError:
            return
        with suppress(Exception):
            _shell_extension.restore_logging_streams()

    def __del__(self):
        with suppress(Exception):
            self._restore_logging_streams()


def main():
    Shell().run()
