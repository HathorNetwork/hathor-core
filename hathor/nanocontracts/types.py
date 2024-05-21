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

from enum import Enum
from typing import Callable, Generic, NamedTuple, TypeVar

from hathor.nanocontracts.exception import NCInvalidContext
from hathor.transaction import BaseTransaction
from hathor.types import Address

T = TypeVar('T')


class SignedData(Generic[T]):
    """A wrapper class to sign data.

    T must be serializable.
    """
    def __init__(self, data: T, script_input: bytes) -> None:
        self.data = data
        self.script_input = script_input

    def __eq__(self, other):
        if self.data != other.data:
            return False
        if self.script_input != other.script_input:
            return False
        return True

    def get_data_bytes(self) -> bytes:
        """Return the serialized data."""
        from hathor.nanocontracts.serializers import Serializer
        serializer = Serializer()
        return serializer.from_type(type(self.data), self.data)

    def get_sighash_all_data(self) -> bytes:
        """Workaround to be able to pass `self` for ScriptExtras. See the method `checksig`."""
        return self.get_data_bytes()

    def checksig(self, script: bytes) -> bool:
        """Check if `self.script_input` satisfies the provided script."""
        from hathor.transaction.exceptions import ScriptError
        from hathor.transaction.scripts import ScriptExtras
        from hathor.transaction.scripts.execute import execute_eval
        full_data = self.script_input + script
        log: list[str] = []
        extras = ScriptExtras(tx=self, txin=None, spent_tx=None)  # type: ignore
        try:
            execute_eval(full_data, log, extras)
        except ScriptError:
            return False
        else:
            return True


def public(fn: Callable) -> Callable:
    """Decorator to mark a blueprint method as public."""
    setattr(fn, '_is_nc_public', True)
    return fn


class NCActionType(Enum):
    """Types of interactions a transaction might have with a contract."""
    DEPOSIT = 'deposit'
    WITHDRAWAL = 'withdrawal'


class NCAction(NamedTuple):
    type: NCActionType
    token_uid: bytes
    amount: int


class Context:
    """Context passed to a method call. An empty list of actions means the
    method is being called with no deposits and withdrawals.

    Deposits and withdrawals are grouped by token. Note that it is impossible
    to have both a deposit and a withdrawal for the same token.
    """
    def __init__(self, actions: list[NCAction], tx: BaseTransaction, address: Address, timestamp: int) -> None:
        # Dict of action where the key is the token_uid.
        # If empty, it is a method call without deposits and withdrawals.
        self.actions: dict[bytes, NCAction] = {}
        for action in actions:
            if action.token_uid in self.actions:
                raise NCInvalidContext('Two or more actions with the same token uid')
            self.actions[action.token_uid] = action

        # Transaction calling the method.
        self.tx = tx

        # Address calling the method.
        self.address = address

        # Timestamp of the first block confirming tx.
        self.timestamp = timestamp
