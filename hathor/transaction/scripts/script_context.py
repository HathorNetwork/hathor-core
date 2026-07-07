# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor.transaction.scripts.execute import ScriptExtras, Stack


class ScriptContext:
    """A context to be manipulated during script execution. A separate instance must be used for each script."""
    __slots__ = ('stack', 'logs', 'extras')

    def __init__(self, *, stack: Stack, logs: list[str], extras: ScriptExtras) -> None:
        self.stack = stack
        self.logs = logs
        self.extras = extras
