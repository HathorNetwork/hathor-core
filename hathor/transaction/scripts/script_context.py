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

import hashlib

from typing_extensions import assert_never

from hathor.conf.settings import HathorSettings
from hathor.transaction import Transaction
from hathor.transaction.exceptions import ScriptError
from hathor.transaction.scripts.execute import ScriptExtras, Stack
from hathor.transaction.scripts.sighash import SighashAll, SighashBitmask, SighashType


class ScriptContext:
    """A context to be manipulated during script execution. A separate instance must be used for each script."""
    __slots__ = ('stack', 'logs', 'extras', '_settings', '_sighash')

    def __init__(self, *, stack: Stack, logs: list[str], extras: ScriptExtras, settings: HathorSettings) -> None:
        self.stack = stack
        self.logs = logs
        self.extras = extras
        self._settings = settings
        self._sighash: SighashType = SighashAll()

    def set_sighash(self, sighash: SighashType) -> None:
        """
        Set a Sighash type in this context.
        It can only be set once, that is, a script cannot use more than one sighash type.
        """
        if type(self._sighash) is not SighashAll:
            raise ScriptError('Cannot modify sighash after it is already set.')

        self._sighash = sighash

    def get_tx_sighash_data(self, tx: Transaction) -> bytes:
        """
        Return the sighash data for a tx, depending on the sighash type set in this context.
        Must be used when verifying signatures during script execution.
        """
        match self._sighash:
            case SighashAll():
                return tx.get_sighash_all_data()
            case SighashBitmask():
                data = tx.get_custom_sighash_data(self._sighash)
                return hashlib.sha256(data).digest()
            case _:
                assert_never(self._sighash)

    def get_selected_outputs(self) -> set[int]:
        """Get a set with all output indexes selected (that is, signed) in this context."""
        match self._sighash:
            case SighashAll():
                return set(range(self._settings.MAX_NUM_OUTPUTS))
            case SighashBitmask():
                return set(self._sighash.get_output_indexes())
            case _:
                assert_never(self._sighash)
