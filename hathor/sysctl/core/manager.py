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

import io
import os
import sys
from typing import IO, Any, Optional

from hathor.manager import HathorManager
from hathor.sysctl.sysctl import Sysctl, signal_handler_safe


class HathorManagerSysctl(Sysctl):
    def __init__(self, manager: HathorManager) -> None:
        super().__init__()

        self.manager = manager
        self.register(
            'profiler.status',
            self.get_profiler_status,
            None
        )
        self.register(
            'profiler.start',
            None,
            self.set_profiler_start,
        )
        self.register(
            'profiler.stop',
            None,
            self.set_profiler_stop,
        )
        self.register(
            'pudb.set_trace.attach_tty',
            None,
            self.set_pudb_set_trace_attach_tty,
        )
        self.register(
            'pudb.set_trace.create_tty',
            None,
            self.set_pudb_set_trace_create_tty,
        )
        self.register(
            'pudb.status',
            self.get_pudb_status,
            None
        )
        self.register(
            'pudb.stop',
            None,
            self.set_pudb_stop,
        )
        self.register(
            'ipython.run.attach_tty',
            None,
            self.set_ipython_run,
        )

    def get_profiler_status(self) -> tuple[int, float]:
        """Return (enabled, duration) as a profiler status.

        enabled: 0 means disabled / 1 means enabled.
        duration: time in seconds since the profiler has been started.
        """
        if not self.manager.is_profiler_running:
            return (0, 0)
        now = self.manager.reactor.seconds()
        duration = now - self.manager.profiler_last_start_time
        return (1, duration)

    @signal_handler_safe
    def set_profiler_start(self, reset: bool) -> None:
        """Start the profiler. One can safely call start multiple times to reset it."""
        self.manager.start_profiler(reset=reset)

    @signal_handler_safe
    def set_profiler_stop(self, save_to: str | None) -> None:
        """Stop the profiler and optionally dump the statistics to a file.

        An empty save_to will skip the dump.
        """
        if not save_to:
            save_to = None
        self.manager.stop_profiler(save_to=save_to)

    @signal_handler_safe
    def set_pudb_set_trace_attach_tty(self, tty: str) -> None:
        """Stop execution and open pudb in a given tty.

        ATTENTION: This command can be destructive and the full node might not work after running it.

        Open a new terminal. First, you need to get the path of the tty of the
        terminal you want to debug from. To do that, use the standard unix
        command `tty`. It will print something like `/dev/pts/3`.

        Then you need to make sure that your terminal doesn't have a shell actively
        reading and possibly capturing some of the input that should go to pudb.
        To do that run a placeholder command that does nothing, such as `perl -MPOSIX -e pause`.
        """
        fp = open(tty, 'r+b', buffering=0)
        term_size = os.get_terminal_size(fp.fileno())
        self._run_pudb_set_trace(tty, fp, term_size=term_size)

    @signal_handler_safe
    def set_pudb_set_trace_create_tty(self, cols: int, rows: int) -> None:
        """Stop execution and open pudb for debugging in a newly created tty.

        ATTENTION: This command can be destructive and the full node might not work after running it.

        You must provide the terminal size (cols, rows).

        The newly created tty path will be printed in the logs. After you get it, you can
        connect to it using `screen <ttyname>`.
        """
        import fcntl
        import struct
        import termios

        (term_master, term_slave) = os.openpty()

        term_size = (cols, rows)
        term_size_bytes = struct.pack("HHHH", term_size[1], term_size[0], 0, 0)
        fcntl.ioctl(term_master, termios.TIOCSWINSZ, term_size_bytes)

        tty_name = os.ttyname(term_slave)
        fp = os.fdopen(term_master, 'wb+', buffering=0)

        self._run_pudb_set_trace(tty_name, fp, term_size=term_size)

    def _run_pudb_set_trace(self, tty: str, fp: IO[bytes], *, term_size: Optional[tuple[int, int]] = None) -> None:
        from pudb.debugger import Debugger

        self.log.warn('main loop paused; pudb.set_trace running', tty=tty)

        tty_file = io.TextIOWrapper(fp)
        kwargs: dict[str, Any] = {
            'stdin': tty_file,
            'stdout': tty_file,
        }
        if term_size is not None:
            kwargs['term_size'] = term_size

        if Debugger._current_debugger:
            Debugger._current_debugger.pop()

        dbg = Debugger(**kwargs)
        dbg.set_trace(sys._getframe().f_back, paused=True)

    def get_pudb_status(self) -> str:
        """Return whether the pudb is running or not."""
        from pudb.debugger import Debugger

        if not Debugger._current_debugger:
            return 'not running'

        dbg = Debugger._current_debugger[0]
        if dbg.ui.quit_event_loop:
            return 'not running'

        return 'running'

    @signal_handler_safe
    def set_pudb_stop(self) -> None:
        """Stop pudb if it is running."""
        from pudb.debugger import Debugger

        if not Debugger._current_debugger:
            return

        dbg = Debugger._current_debugger[0]
        dbg.set_quit()
        dbg.ui.quit_event_loop = True

    @signal_handler_safe
    def set_ipython_run(self, tty: str) -> None:
        """Stop execution and open an ipython shell in a given tty.

        ATTENTION: This command can be destructive and the full node might not work after running it.

        Open a new terminal. First, you need to get the path of the tty of the
        terminal you want to debug from. To do that, use the standard unix
        command `tty`. It will print something like `/dev/pts/3`.

        Then you need to make sure that your terminal doesn't have a shell actively
        reading and possibly capturing some of the input that should go to pudb.
        To do that run a placeholder command that does nothing, such as `perl -MPOSIX -e pause`.
        """
        fp = open(tty, 'r+b', buffering=0)
        tty_file = io.TextIOWrapper(fp)

        old_stdin = sys.stdin
        old_stdout = sys.stdout
        old_stderr = sys.stderr

        sys.stdin = tty_file
        sys.stdout = tty_file
        sys.stderr = tty_file

        self.log.warn('main loop paused; ipython running', tty=tty)

        from IPython import start_ipython
        user_ns: dict[str, Any] = {
            'manager': self.manager,
            'tx_storage': self.manager.tx_storage,
        }
        start_ipython(argv=[], user_ns=user_ns)

        sys.stdin = old_stdin
        sys.stdout = old_stdout
        sys.stderr = old_stderr

        self.log.warn('main loop resumed')
