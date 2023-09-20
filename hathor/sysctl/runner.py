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

import json
import re
from typing import TYPE_CHECKING, Any

from hathor.sysctl.exception import SysctlRunnerException

if TYPE_CHECKING:
    from hathor.sysctl.sysctl import Sysctl

# - It starts with an opening square bracket [.
# - It ends with a closing square bracket ].
# - The elements are separated by commas and can be followed by optional whitespace.
# - There can be zero or more elements in the array (an empty array is allowed).
array_pattern = r'^\s*\[\s*(?:[^\[\],]+(?:\s*,\s*[^\[\],]+)*)?\s*\]\s*$'


class SysctlRunner:
    """ Encapsulates the Sysctl to decouple it from the SyctlProtocol.
    """

    def __init__(self, root: 'Sysctl') -> None:
        self.root = root

    def run(self, line: str) -> bytes:
        """Receives a string line, parses, interprets, acts over the Sysctl,
        and returns an UTF-8 encoding data as feedback.
        """
        if not line:
            raise SysctlRunnerException('line cannot be empty or None')

        head, separator, tail = self.get_line_parts(line)
        if separator == '=':
            return self._set(head, tail)
        else:
            return self._get(head)

    def _set(self, path: str, value_str: str) -> bytes:
        """Run a `set` command in sysctl, and return and empty feedback."""
        try:
            value = self.deserialize(value_str)
        except json.JSONDecodeError:
            raise SysctlRunnerException('value: wrong format')

        self.root.set(path, value)
        return b''

    def _get(self, path: str) -> bytes:
        """Run a `get` command in sysctl."""
        value = self.root.get(path)
        return self.serialize(value).encode('utf-8')

    def get_line_parts(self, line: str) -> tuple[str, ...]:
        """Get line parts and return a tuple with head, separator, tail."""
        head, separator, tail = line.partition('=')
        head = head.strip()
        tail = tail.strip()
        return (head, separator, tail)

    def serialize(self, value: Any) -> str:
        """Serialize the return of a sysctl getter."""
        if isinstance(value, tuple):
            parts = (json.dumps(x) for x in value)
            return ', '.join(parts)
        else:
            return json.dumps(value)

    def deserialize(self, value_str: str) -> Any:
        """Deserialize a value sent by the client."""
        if len(value_str) == 0:
            return ()

        if re.match(array_pattern, value_str):
            return list(json.loads(value_str))

        parts = [x.strip() for x in value_str.split(',')]
        if len(parts) > 1:
            return tuple(json.loads(x) for x in parts)
        return json.loads(value_str)
