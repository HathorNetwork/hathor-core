# Copyright 2023 Hathor Labs
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

import inspect
from typing import Callable, Optional

from pydantic import ValidationError
from twisted.protocols.basic import LineReceiver

from hathor.sysctl.exception import (
    SysctlEntryNotFound,
    SysctlException,
    SysctlReadOnlyEntry,
    SysctlRunnerException,
    SysctlWriteOnlyEntry,
)
from hathor.sysctl.runner import SysctlRunner


class SysctlProtocol(LineReceiver):
    delimiter = b'\n'

    def __init__(self, runner: SysctlRunner) -> None:
        self.runner = runner

    def lineReceived(self, raw: bytes) -> None:
        try:
            line = raw.decode('utf-8').strip()
        except UnicodeDecodeError:
            self.sendError('command is not utf-8 valid')

        if line.startswith('!help'):
            _, _, path = line.partition(' ')
            self.help(path)
            return
        elif line.startswith('!backup'):
            self.backup()
            return

        try:
            feedback = self.runner.run(line)
            if feedback:
                self.sendLine(feedback)
        except SysctlEntryNotFound:
            path, _, _ = self.runner.get_line_parts(line)
            self.sendError(f'{path} not found')
        except SysctlReadOnlyEntry:
            path, _, _ = self.runner.get_line_parts(line)
            self.sendError(f'cannot write to {path}')
        except SysctlWriteOnlyEntry:
            path, _, _ = self.runner.get_line_parts(line)
            self.sendError(f'cannot read from {path}')
        except SysctlException as e:
            self.sendError(str(e))
        except ValidationError as e:
            self.sendError(str(e))
        except SysctlRunnerException as e:
            self.sendError(str(e))

    def sendError(self, msg: str) -> None:
        """Send an error message to the client. Used when a command fails."""
        self.sendLine(f'[error] {msg}'.encode('utf-8'))

    def backup(self) -> None:
        """Run a `backup` command, sending all parameters to the client."""
        for key, value in self.runner.root.get_all():
            output = f'{key}={self.runner.serialize(value)}'
            self.sendLine(output.encode('utf-8'))

    def help(self, path: str) -> None:
        """Show all available commands."""
        if path == '':
            self._send_all_commands()
            return
        try:
            cmd = self.runner.root.get_command(path)
        except SysctlEntryNotFound:
            self.sendError(f'{path} not found')
            return

        output: list[str] = []
        output.extend(self._get_method_help('getter', cmd.getter))
        output.append('')
        output.extend(self._get_method_help('setter', cmd.setter))
        self.sendLine('\n'.join(output).encode('utf-8'))

    def _send_all_commands(self) -> None:
        all_paths = list(self.runner.root.get_all_paths())
        for path in sorted(all_paths):
            self.sendLine(path.encode('utf-8'))

    def _get_all_commands(self) -> list[str]:
        """Get a list of all commands availale in the sysctl."""
        all_paths = list(self.runner.root.get_all_paths())
        output: list[str] = []
        for path in sorted(all_paths):
            output.append(path)
        return output

    def _get_method_help(self, method_name: str, method: Optional[Callable]) -> list[str]:
        """Return a list of strings with the help for `method`."""
        if method is None:
            return [f'{method_name}: not available']

        output: list[str] = []
        doc: str = inspect.getdoc(method) or '(no help found)'
        signature = inspect.signature(method)
        output.append(f'{method_name}{signature}:')
        for line in doc.splitlines():
            output.append(f'    {line.strip()}')
        return output
