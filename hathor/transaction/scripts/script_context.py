#  Copyright 2023 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from hathor.transaction.scripts.execute import ScriptExtras, Stack


class ScriptContext:
    """A context to be manipulated during script execution. A separate instance must be used for each script."""
    __slots__ = ('stack', 'logs', 'extras')

    def __init__(self, *, stack: Stack, logs: list[str], extras: ScriptExtras) -> None:
        self.stack = stack
        self.logs = logs
        self.extras = extras
