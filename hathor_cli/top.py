# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import asyncio
import datetime
import signal
import sys
import time
import urllib.parse
from abc import ABC, abstractmethod
from asyncio import AbstractEventLoop
from collections import defaultdict
from math import floor
from typing import Any, Callable, Optional

# XXX: support for Windows removed, this should be un-indented
if True:
    import curses
    import curses.ascii

    from aiohttp import ClientSession

    Key = tuple[str, ...]
    ProcGroup = defaultdict[Key, list['ProcItem']]

    # Global color variable.
    Color: Optional['DefaultColor'] = None

    class ProfileData:
        """Profile data."""
        hostname: str
        version: str
        network: str
        enabled: bool
        last_update: float
        error: str
        proc_list: list['ProcItem']

        @classmethod
        def create_from_api(cls, data: dict[str, Any]) -> 'ProfileData':
            self = cls()
            self.hostname = data['hostname']
            self.version = data['version']
            self.network = data['network']
            self.enabled = data['enabled']
            self.last_update = data['last_update']
            self.error = data['error']
            self.proc_list = []
            for proc_dict in data['proc_list']:
                proc = ProcItem.create_from_api(proc_dict)
                self.proc_list.append(proc)
            return self

    class ProcItem:
        """Process item."""
        key: Key
        percent_cpu: float
        total_time: float

        @classmethod
        def create_from_api(cls, data: tuple[Key, dict[str, Any]]) -> 'ProcItem':
            self = cls()
            self.key = tuple(data[0])
            stats = data[1]
            self.percent_cpu = stats['percent_cpu']
            self.total_time = stats['total_time']
            return self

    class TreePrinter:
        """Printer of the tree of processes."""
        def __init__(self, win: Any, groups: ProcGroup, max_depth: int, max_rows: int, source_width: int):
            """Initialize the printer."""
            self.win = win
            self.groups = groups
            self.max_depth = max_depth
            self.max_rows = max_rows
            self.source_width = source_width

            self.last_child_stack: list[bool] = []
            self.rows: int = 0

        def print_tree(self) -> None:
            """Print the tree of processes."""
            for proc in self.groups[tuple()]:
                self._run(proc, depth=0, last_child=False)

        def _run(self, proc: ProcItem, *, depth: int, last_child: bool) -> None:
            """Recursive method that prints the tree."""
            assert len(proc.key) == depth + 1

            if self.rows >= self.max_rows:
                return

            self.rows += 1
            self.print_row(proc, depth, last_child)

            if depth < self.max_depth:
                children = self.groups[proc.key]
                self.last_child_stack.append(last_child)
                for idx, child in enumerate(children):
                    new_last_child = (idx + 1 == len(children))
                    self._run(child, depth=depth + 1, last_child=new_last_child)
                self.last_child_stack.pop()

        def print_row(self, proc: ProcItem, depth: int, last_child: bool) -> None:
            """Print a single row in the process list."""
            assert Color is not None

            y_begin, x_begin = self.win.getyx()
            if x_begin != 0:
                # It should never happened.
                self.win.move(y_begin, 0)

            key = proc.key[-1]

            if proc.percent_cpu < 100:
                self.win.addstr('{:4.1f} '.format(proc.percent_cpu))
            else:
                self.win.addstr('{:3.0f}. '.format(proc.percent_cpu))
            self.win.addstr('{:s} '.format(self.format_total_time(proc.total_time)))

            width = self.source_width

            if depth > 0:
                prefix_list = []
                for x in self.last_child_stack[1:]:
                    prefix_list.append('│  ' if not x else '   ')
                prefix_list.append('├─ ' if not last_child else '└─ ')
                prefix = ''.join(prefix_list)[:width]
                self.win.addstr(prefix, Color.TREE_PARTS)
                width -= len(prefix)

            parts = key.split('!', 1)
            if len(parts) == 1:
                fmt = '{{:{}s}}'.format(width)
                self.win.addstr(fmt.format(key[:width]))

            else:
                gid = parts[0][:width]
                self.win.addstr(gid, Color.SOURCE_BASENAME)
                width -= len(gid)
                other = '!{}'.format(parts[1])
                fmt = '{{:{}s}}'.format(width - 1)
                self.win.addstr(fmt.format(other[:width]))

            # We usually don't have to use a \n because the whole file has been filled
            # but it is better to check whether it really happened.
            y_end, _ = self.win.getyx()
            if y_begin == y_end:
                self.win.addstr('\n')

        def format_total_time(self, total_time: float) -> str:
            """Format total time in exactly 8 chars"""
            frac = total_time - floor(total_time)
            seconds = floor(total_time)
            hours = seconds // 3600
            seconds = seconds % 3600
            minutes = seconds // 60
            seconds = seconds % 60

            if hours >= 100:
                return '{}h'.format(hours)
            elif hours > 0:
                return '{:02d}:{:02d}:{:02d}'.format(hours, minutes, seconds)
            else:
                return '{:02d}:{:02d}.{:02d}'.format(minutes, seconds, floor(100 * frac))

    def group_by_parent(proc_list: list[ProcItem]) -> ProcGroup:
        """Group the processes by their parents.

        It converts from the format received by the API and the format used by the printer.
        """
        d = defaultdict(list)
        for proc in proc_list:
            d[tuple(proc.key[:-1])].append(proc)
        for k, v in d.items():
            v.sort(key=lambda proc: proc.percent_cpu, reverse=True)
        return d

    def group_cpu_percent(groups: ProcGroup, *, threshold: float = 0.5, separator: str = '!') -> ProcGroup:
        """Group processes that consumes less than `threadhold` of CPU."""
        new_groups: ProcGroup = defaultdict(list)
        for key, children in groups.items():
            hidden_procs: defaultdict[str, list[ProcItem]] = defaultdict(list)
            new_children: list[ProcItem] = []
            for proc in children:
                if proc.percent_cpu < threshold:
                    local_key = proc.key[-1]
                    parts = local_key.split(separator, 1)
                    if len(parts) == 1:
                        gid = ''
                    else:
                        gid = parts[0]
                    hidden_procs[gid].append(proc)
                else:
                    new_children.append(proc)

            for gid, proc_list in hidden_procs.items():
                if not proc_list:
                    continue
                if len(proc_list) == 1:
                    new_children += proc_list
                    continue
                if gid:
                    local_key = '{}!({} hidden)'.format(gid, len(proc_list))
                else:
                    local_key = '({} hidden)'.format(len(proc_list))

                placeholder = ProcItem()
                placeholder.key = tuple(key + (local_key,))
                placeholder.percent_cpu = sum(x.percent_cpu for x in proc_list)
                placeholder.total_time = sum(x.total_time for x in proc_list)
                new_children.append(placeholder)
            new_groups[key] = new_children
        assert set(groups.keys()) == set(new_groups.keys())
        return new_groups

    class Window(ABC):
        """Abstract class for a window."""

        def __init__(self, manager: 'ScreenManager', win: Any) -> None:
            self.manager = manager
            self.win = win

        def on_data_update(self) -> None:
            """Called when we get new data from the profiler."""
            pass

        def on_keypress(self, key: int) -> None:
            """Called when the user press a key."""
            pass

        @abstractmethod
        def render(self) -> None:
            """Called to render the window."""
            raise NotImplementedError

    class HelpWindow(Window):
        """Help window."""

        def on_keypress(self, key: int) -> None:
            self.manager.goto('main')

        def print_cmd(self, cmd: str, description: str) -> None:
            """Util to print a cmd in the window."""
            assert Color is not None
            self.win.addstr(cmd, Color.HELP_BOLD)
            self.win.addstr(': ', Color.HELP_BOLD)
            self.win.addstr(description)
            self.win.addstr('\n')

        def render(self) -> None:
            assert Color is not None
            self.win.addstr('hathor-top 1.0.0\n', Color.HELP_BOLD)
            self.win.addstr('\n')
            self.print_cmd('h or ?', 'show this help screen')
            self.print_cmd('f', 'freeze data fetching')
            self.print_cmd('g', 'group small cpu percent')
            self.print_cmd('+', 'increment tree depth')
            self.print_cmd('-', 'decrement tree depth')
            self.print_cmd('p', 'send commands to the profiler')
            self.print_cmd('q', 'quit')
            self.win.addstr('Press any key to return.', Color.HELP_BOLD)

    class MainWindow(Window):
        """Main window."""

        def __init__(self, manager: 'ScreenManager', win: Any) -> None:
            super().__init__(manager, win)
            self.max_depth = 5
            self.group_cpu_percent = False

        def on_keypress(self, key: int) -> None:
            if key in (curses.ascii.ESC, ord('q')):
                self.manager.quit()

            elif key in (ord('h'), ord('?')):
                self.manager.goto('help')

            elif key == ord('+'):
                if self.max_depth < 6:
                    self.max_depth += 1
                    self.manager.redraw()

            elif key == ord('-'):
                if self.max_depth > 0:
                    self.max_depth -= 1
                    self.manager.redraw()

            elif key == ord('g'):
                self.group_cpu_percent = not self.group_cpu_percent
                self.manager.redraw()

            elif key == ord('f'):
                self.manager.freeze_data = not self.manager.freeze_data
                if not self.manager.freeze_data:
                    # Update to a new data if it is available.
                    if self.manager.fetcher.latest_data is not None:
                        self.manager.on_data_update(self.manager.fetcher.latest_data)
                self.manager.redraw()

            elif key == ord('p'):
                self.manager.goto('control')

        def draw_cpu(self, win: Any, cpu_percent: float, *, width: int) -> None:
            assert Color is not None
            remaining_width = width

            label = 'CPU '
            remaining_width -= len(label) + 2

            if cpu_percent > 100:
                cpu_percent = 100

            cpu_percent_text = '{:.1f}%'.format(cpu_percent)
            bar_qty = int(remaining_width * cpu_percent / 100)
            remaining_width -= bar_qty

            attr = Color.CPU_PERCENT
            if remaining_width < len(cpu_percent_text):
                bar_qty -= len(cpu_percent_text) - remaining_width
                remaining_width = len(cpu_percent_text)
                attr = Color.CPU_NORMAL

            win.addstr(label, Color.CPU_LABEL)
            win.addstr('[', Color.CPU_BRACKET)
            win.addstr('|' * bar_qty, Color.CPU_NORMAL)
            win.addstr(' ' * (remaining_width - len(cpu_percent_text)))
            win.addstr(cpu_percent_text, attr)
            win.addstr(']', Color.CPU_BRACKET)
            win.addstr('\n')
            win.addstr('\n')

        def draw_general_info(self, win: Any) -> None:
            assert Color is not None
            assert Color is not None
            fetcher = self.manager.fetcher
            data = self.manager.data
            assert data is not None

            win.addstr('Hostname: ', Color.CAPTION)
            win.addstr(data.hostname, Color.HOSTNAME)
            if (self.manager.alias):
                win.addstr(' ({})'.format(self.manager.alias), Color.HOSTNAME)
            win.addstr('\n')

            win.addstr('Network: ', Color.CAPTION)
            win.addstr(data.network, Color.NETWORK)
            win.addstr(' (v', Color.VERSION)
            win.addstr(data.version, Color.VERSION)
            win.addstr(')', Color.VERSION)
            win.addstr('\n')

            win.addstr('URL: ', Color.CAPTION)
            win.addstr(fetcher.url, Color.URL)
            win.addstr('\n')

            win.addstr('Last update: ', Color.CAPTION)
            if self.manager.freeze_data:
                attr = Color.LAST_UPDATE_FROZEN
            elif fetcher.error_count > 0:
                attr = Color.LAST_UPDATE_ERROR
            elif not data.enabled:
                attr = Color.LAST_UPDATE_DISABLED
            else:
                attr = Color.LAST_UPDATE

            if fetcher.last_update:
                last_update = datetime.datetime.fromtimestamp(fetcher.last_update)
                win.addstr(last_update.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"), attr)
            else:
                win.addstr('Unknown', attr)

            if self.manager.freeze_data:
                win.addstr(' (frozen)', Color.FETCH_FROZEN)
            elif fetcher.error_count > 0:
                win.addstr(' (fetch failed: {})'.format(fetcher.error_count), Color.FETCH_ERROR)
            elif not data.enabled:
                win.addstr(' (profiler is not running)', Color.PROFILER_DISABLED)
            win.addstr('\n')

            win.addstr('max_depth={} '.format(self.max_depth), Color.CAPTION)
            win.addstr('group_cpu_percent={} '.format(self.group_cpu_percent), Color.CAPTION)
            win.addstr('\n')

        def draw_no_data(self, win: Any) -> None:
            assert Color is not None
            fetcher = self.manager.fetcher
            win.addstr('URL: ', Color.CAPTION)
            win.addstr(fetcher.url, Color.URL)
            win.addstr('\n')
            win.addstr('Waiting for data...\n', Color.CAPTION)
            if fetcher.error_count > 0:
                win.addstr('\n')
                win.addstr('Fetch failed: ', Color.FETCH_ERROR_CAPTION)
                win.addstr('({}) {}\n'.format(fetcher.error_count, fetcher.error), Color.FETCH_ERROR)

        def render(self) -> None:
            assert Color is not None

            if self.manager.data is None:
                self.draw_no_data(self.win)
                return

            self.draw_general_info(self.win)

            data = self.manager.data
            assert data is not None

            if data.error:
                self.win.addstr('>> PROFILER ERROR: {}'.format(data.error), Color.PROFILER_ERROR)
            self.win.addstr('\n')

            height, width = self.win.getmaxyx()

            proc_list: list[ProcItem] = data.proc_list
            groups: ProcGroup = group_by_parent(proc_list)
            if self.group_cpu_percent:
                groups = group_cpu_percent(groups)
            cpu_percent = sum(proc.percent_cpu for proc in groups[tuple()])
            self.draw_cpu(self.win, cpu_percent, width=width // 2)

            fmt1 = '{:4s} {:8s} '
            title = fmt1.format('CPU%', 'TIME+')
            self.win.addstr(title, Color.TITLE)
            source_width = width - len(title)

            fmt2 = '{{:{}s}}'.format(source_width)
            self.win.addstr(fmt2.format('Source'), Color.TITLE)

            y, _ = self.win.getyx()
            max_rows = height - y - 1

            printer = TreePrinter(self.win, groups, self.max_depth, max_rows, source_width)
            printer.print_tree()

    class ControlWindow(Window):
        """Control window."""

        def __init__(self, manager: 'ScreenManager', win: Any) -> None:
            super().__init__(manager, win)

            self._logs: list[tuple[str, int]] = []

            fetcher: 'ProfileAPIClient' = self.manager.fetcher
            self.cmd_map: dict[str, Any] = {
                'start': fetcher.send_start_cmd,
                'stop': fetcher.send_stop_cmd,
                'reset': fetcher.send_reset_cmd,
            }

        def on_keypress(self, key: int) -> None:
            if key == ord('q'):
                self.manager.goto('main')

            elif key == ord('c'):
                self._logs = []
                self.manager.redraw()

            elif key == ord('w'):
                loop = self.manager.loop
                loop.create_task(self.send_cmd('start'))

            elif key == ord('o'):
                loop = self.manager.loop
                loop.create_task(self.send_cmd('stop'))

            elif key == ord('r'):
                loop = self.manager.loop
                loop.create_task(self.send_cmd('reset'))

        def log(self, msg: str, attr: int = 0) -> None:
            """Util to add log lines and redraw screen."""
            self._logs.append((msg, attr))
            self.manager.redraw()

        async def send_cmd(self, cmd: str) -> None:
            """Send a cmd to the profiler and logs the results."""
            assert Color is not None
            now = datetime.datetime.now()
            now_str = now.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
            self.log(now_str, Color.CMD_DATETIME)

            cmd_fn = self.cmd_map.get(cmd, None)
            self.log('> sending {} command...'.format(cmd), Color.CMD_CMDLINE)
            if cmd_fn is None:
                self.log('command not found: {}'.format(cmd))
                return
            try:
                ret = await cmd_fn()
                self.log(str(ret))
            except Exception as e:
                self.log('error: {}'.format(e))
            finally:
                self.log('')

        def print_cmd(self, cmd: str, description: str) -> None:
            """Util to print a cmd."""
            assert Color is not None
            self.win.addstr(cmd, Color.HELP_BOLD)
            self.win.addstr(': ', Color.HELP_BOLD)
            self.win.addstr(description)
            self.win.addstr('\n')

        def render(self) -> None:
            assert Color is not None
            self.win.addstr('profiler control\n', Color.HELP_BOLD)
            self.win.addstr('\n')
            self.print_cmd('c', 'clear log')
            self.print_cmd('w', 'send a start command')
            self.print_cmd('o', 'send a stop command')
            self.print_cmd('r', 'send a reset command')
            self.print_cmd('q', 'go back to main window')
            self.win.addstr('\n')

            height, width = self.win.getmaxyx()
            y, _ = self.win.getyx()

            self.win.addstr('─' * width)
            txt = ' OUTPUT '
            self.win.move(y, (width - len(txt)) // 2)
            self.win.addstr(txt)
            self.win.move(y + 1, 0)

            y, _ = self.win.getyx()
            max_rows = height - y - 1
            for msg, attr in self._logs[-max_rows:]:
                self.win.addstr(msg, attr)
                self.win.addstr('\n')

    class ScreenManager:
        """Manage the screen."""

        def __init__(self, loop: AbstractEventLoop, fetcher: 'ProfileAPIClient', *,
                     update_interval: int = 2, alias: Optional[str] = None) -> None:
            """Initialize the screen and immediately draw an initial screen."""
            self.stdscr = curses.initscr()
            curses.noecho()
            curses.cbreak()
            curses.curs_set(0)
            self.stdscr.keypad(True)
            self.stdscr.nodelay(True)
            self.register_colors()

            self.alias = alias

            self._redraw: bool = False

            self.freeze_data: bool = False

            self.loop: AbstractEventLoop = loop
            self.loop.add_reader(sys.stdin, self.getch)

            self.fetcher: 'ProfileAPIClient' = fetcher

            self.screen_list: dict[str, Window] = {
                'help': HelpWindow(self, self.stdscr),
                'main': MainWindow(self, self.stdscr),
                'control': ControlWindow(self, self.stdscr),
            }
            self.screen = self.screen_list['main']

            # Capture Ctrl+C.
            signal.signal(signal.SIGINT, self.signal_sigint_handler)

            # Capture resize if signal is available.
            resize_signal = getattr(signal, 'SIGWINCH', None)
            if resize_signal:
                signal.signal(resize_signal, self.signal_resize_handler)

            # Fetch task.
            self.data: Optional[ProfileData] = None
            self.fetcher.on_fetch_success = self.on_data_update
            self.fetcher.on_fetch_error = self.redraw
            self.fetcher.start()

            # Finally, draw for the first time.
            self.redraw()

        def signal_sigint_handler(self, sig, frame):
            """Called when signal SIGINT is received."""
            self.quit()

        def signal_resize_handler(self, sig, frame):
            """Called when the window is resized."""
            import fcntl
            import struct
            import termios
            try:
                h, w = struct.unpack('hh', fcntl.ioctl(1, termios.TIOCGWINSZ, '1234'))
            except Exception:
                w = curses.tigetnum('cols')
                h = curses.tigetnum('lines')
            curses.resizeterm(h, w)
            self.redraw()

        def register_colors(self) -> None:
            """Register colors used by the windows."""
            global Color
            curses.start_color()
            Color = DefaultColor()

        def on_data_update(self, data: ProfileData) -> None:
            """Called when new data arrives from the profiler."""
            if self.freeze_data:
                return
            self.data = data
            self.screen.on_data_update()
            self.redraw()

        def goto(self, name: str) -> None:
            """Go to the `name` screen."""
            self.screen = self.screen_list[name]
            self.redraw()

        def redraw(self) -> None:
            """Redraw screen."""
            if self._redraw:
                return
            self._redraw = True
            self.loop.call_later(0, self.render)

        def getch(self) -> None:
            """Called by asyncio when a key is pressed."""
            key = self.stdscr.getch()
            self.screen.on_keypress(key)

        def render(self) -> None:
            """Render current screen."""
            self.stdscr.clear()
            try:
                self.screen.render()
            except Exception as e:
                self.quit()
                raise e
            self.stdscr.refresh()
            self._redraw = False

        def quit(self) -> None:
            """Quit."""
            curses.nocbreak()
            self.stdscr.keypad(False)
            curses.echo()
            curses.endwin()
            self.loop.stop()

    class ProfileAPIClient:
        """Client to communicate with the API of the full-node."""
        def __init__(self, loop: AbstractEventLoop, base_url: str, *, update_interval: int = 2) -> None:
            self.loop = loop
            self.url = urllib.parse.urljoin(base_url, '/v1a/top/')
            self.session = ClientSession()

            self.on_fetch_success: Optional[Callable[[ProfileData], None]] = None
            self.on_fetch_error: Optional[Callable[[], None]] = None

            self.last_update: Optional[float] = None
            self.error: str = ''
            self.error_count: int = 0

            self.latest_data: Optional[ProfileData] = None

            self.update_interval = update_interval
            self.task = None

        def start(self):
            self.task = self.loop.create_task(self.run())

        async def send_start_cmd(self):
            async with self.session.post(self.url, data='start') as resp:
                data = await resp.json()
                return data

        async def send_stop_cmd(self):
            async with self.session.post(self.url, data='stop') as resp:
                data = await resp.json()
                return data

        async def send_reset_cmd(self):
            async with self.session.post(self.url, data='reset') as resp:
                data = await resp.json()
                return data

        async def run(self) -> Any:
            while True:
                try:
                    data_dict: dict[str, Any] = await self.fetch()
                    data = ProfileData.create_from_api(data_dict)
                    self.last_update = time.time()
                    self.error = ''
                    self.error_count = 0
                    self.latest_data = data
                    if self.on_fetch_success:
                        self.on_fetch_success(self.latest_data)
                except Exception as e:
                    self.error = str(e)
                    self.error_count += 1
                    if self.on_fetch_error:
                        self.on_fetch_error()
                await asyncio.sleep(self.update_interval)

        async def fetch(self):
            async with self.session.get(self.url) as resp:
                data = await resp.json()
                return data

    class DefaultColor:
        def __init__(self) -> None:
            self._color_map: dict[tuple[int, int], int] = {}

            A_NONE = 0
            A_BOLD = curses.A_BOLD
            COLOR_CYAN = curses.COLOR_CYAN
            COLOR_BLACK = curses.COLOR_BLACK
            COLOR_RED = curses.COLOR_RED
            COLOR_GREEN = curses.COLOR_GREEN
            COLOR_WHITE = curses.COLOR_WHITE
            COLOR_MAGENTA = curses.COLOR_MAGENTA

            _ = self._register

            self.CAPTION: int = _(A_NONE, COLOR_CYAN, COLOR_BLACK)
            self.URL: int = _(A_NONE, COLOR_CYAN, COLOR_BLACK)
            self.HOSTNAME: int = _(A_BOLD, COLOR_WHITE, COLOR_BLACK)
            self.NETWORK: int = _(A_BOLD, COLOR_CYAN, COLOR_BLACK)
            self.VERSION: int = _(A_BOLD, COLOR_CYAN, COLOR_BLACK)
            self.CPU_LABEL: int = _(A_NONE, COLOR_CYAN, COLOR_BLACK)
            self.CPU_BRACKET: int = _(A_BOLD, COLOR_WHITE, COLOR_BLACK)
            self.CPU_NORMAL: int = _(A_NONE, COLOR_GREEN, COLOR_BLACK)
            self.CPU_PERCENT: int = _(A_BOLD, COLOR_BLACK, COLOR_BLACK)
            self.LAST_UPDATE: int = _(A_BOLD, COLOR_GREEN, COLOR_BLACK)
            self.LAST_UPDATE_ERROR: int = _(A_BOLD, COLOR_WHITE, COLOR_RED)
            self.LAST_UPDATE_FROZEN: int = _(A_BOLD, COLOR_WHITE, COLOR_CYAN)
            self.LAST_UPDATE_DISABLED: int = _(A_BOLD, COLOR_WHITE, COLOR_MAGENTA)
            self.FETCH_ERROR_CAPTION: int = _(0, COLOR_RED, COLOR_BLACK)
            self.FETCH_ERROR: int = _(A_BOLD, COLOR_RED, COLOR_BLACK)
            self.FETCH_FROZEN: int = _(A_BOLD, COLOR_CYAN, COLOR_BLACK)
            self.PROFILER_DISABLED: int = _(A_BOLD, COLOR_MAGENTA, COLOR_BLACK)
            self.PROFILER_ERROR: int = _(A_BOLD, COLOR_WHITE, COLOR_RED)
            self.TITLE: int = _(A_NONE, COLOR_BLACK, COLOR_GREEN)
            self.TREE_PARTS: int = _(A_NONE, COLOR_CYAN, COLOR_BLACK)
            self.SOURCE_BASENAME: int = _(A_BOLD, COLOR_GREEN, COLOR_BLACK)
            self.HELP_BOLD: int = _(A_BOLD, COLOR_CYAN, COLOR_BLACK)
            self.CMD_CMDLINE: int = _(A_BOLD, COLOR_CYAN, COLOR_BLACK)
            self.CMD_DATETIME: int = _(A_BOLD, COLOR_BLACK, COLOR_BLACK)

        def _register(self, attr: int, fore: int, back: int) -> int:
            key = (fore, back)
            if key not in self._color_map:
                code = len(self._color_map) + 1
                self._color_map[key] = code
                curses.init_pair(code, fore, back)
            else:
                code = self._color_map[key]

            return attr | curses.color_pair(code)

    def main() -> None:
        from hathor_cli.util import create_parser
        parser = create_parser()
        parser.add_argument('url', help='URL of the full-node API')
        parser.add_argument('-g', action='store_true', help='Group small CPU percent')
        parser.add_argument('--alias', help='Alias to the server')
        args = parser.parse_args(sys.argv[1:])

        # data = fetch_data(args.url)
        # print_screen(data, print_fn=print, group_small_cpu_percent=True)

        loop = asyncio.get_event_loop()
        fetcher = ProfileAPIClient(loop, args.url)
        ScreenManager(loop, fetcher, alias=args.alias)
        loop.run_forever()
