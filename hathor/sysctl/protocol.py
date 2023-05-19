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
import json
from typing import TYPE_CHECKING, Any, Callable, List, Optional

from pydantic import ValidationError
from twisted.protocols.basic import LineReceiver

from hathor.sysctl.exception import SysctlEntryNotFound, SysctlException, SysctlReadOnlyEntry, SysctlWriteOnlyEntry

if TYPE_CHECKING:
    from hathor.sysctl.sysctl import Sysctl


class SysctlProtocol(LineReceiver):
    delimiter = b'\n'

    def __init__(self, root: 'Sysctl') -> None:
        self.root = root

    def lineReceived(self, raw: bytes) -> None:
        try:
            line = raw.decode('utf-8').strip()
        except UnicodeDecodeError:
            self.sendError('command is not utf-8 valid')
        if line.startswith('!help'):
            _, _, path = line.partition(' ')
            self.help(path)
            return
        elif line == '!backup':
            self.backup()
            return
        head, separator, tail = line.partition('=')
        head = head.strip()
        tail = tail.strip()
        if separator == '=':
            self.set(head, tail)
        else:
            self.get(head)

    def sendError(self, msg: str) -> None:
        """Send an error message to the client. Used when a command fails."""
        self.sendLine(f'[error] {msg}'.encode('utf-8'))

    def set(self, path: str, value_str: str) -> None:
        """Run a `set` command in sysctl."""
        try:
            value = self._deserialize(value_str)
        except json.JSONDecodeError:
            self.sendError('value: wrong format')
            return

        try:
            self.root.set(path, value)
        except SysctlEntryNotFound:
            self.sendError(f'{path} not found')
        except SysctlReadOnlyEntry:
            self.sendError(f'cannot write to {path}')
        except SysctlException as e:
            self.sendError(str(e))
        except ValidationError as e:
            self.sendError(str(e))
        except TypeError as e:
            self.sendError(str(e))

    def get(self, path: str) -> None:
        """Run a `get` command in sysctl."""
        try:
            value = self.root.get(path)
        except SysctlEntryNotFound:
            self.sendError(f'{path} not found')
        except SysctlWriteOnlyEntry:
            self.sendError(f'cannot read from {path}')
        else:
            output = self._serialize(value)
            self.sendLine(output.encode('utf-8'))

    def backup(self) -> None:
        """Run a `backup` command, sending all parameters to the client."""
        for key, value in self.root.get_all():
            output = f'{key}={self._serialize(value)}'
            self.sendLine(output.encode('utf-8'))

    def help(self, path: str) -> None:
        """Show all available commands."""
        if path == '':
            self._send_all_commands()
            return
        try:
            cmd = self.root.get_command(path)
        except SysctlEntryNotFound:
            self.sendError(f'{path} not found')
            return

        output: List[str] = []
        output.extend(self._get_method_help('getter', cmd.getter))
        output.append('')
        output.extend(self._get_method_help('setter', cmd.setter))
        self.sendLine('\n'.join(output).encode('utf-8'))

    def _send_all_commands(self) -> None:
        all_paths = list(self.root.get_all_paths())
        for path in sorted(all_paths):
            self.sendLine(path.encode('utf-8'))

    def _serialize(self, value: Any) -> str:
        """Serialize the return of a sysctl getter."""
        output: str
        if isinstance(value, tuple):
            parts = (json.dumps(x) for x in value)
            output = ', '.join(parts)
        else:
            output = json.dumps(value)
        return output

    def _deserialize(self, value_str: str) -> Any:
        """Deserialize a value sent by the client."""
        if len(value_str) == 0:
            return ()
        parts = [x.strip() for x in value_str.split(',')]
        if len(parts) > 1:
            return tuple(json.loads(x) for x in parts)
        return json.loads(value_str)

    def _get_method_help(self, method_name: str, method: Optional[Callable]) -> List[str]:
        """Return a list of strings with the help for `method`."""
        if method is None:
            return [f'{method_name}: not available']

        output: List[str] = []
        doc: str = inspect.getdoc(method) or '(no help found)'
        signature = inspect.signature(method)
        output.append(f'{method_name}{signature}:')
        for line in doc.splitlines():
            output.append(f'    {line.strip()}')
        return output
