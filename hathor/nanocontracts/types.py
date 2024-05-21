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

from __future__ import annotations

from enum import Enum, unique
from typing import Callable, Generic, NamedTuple, NewType, TypeVar

from hathor.transaction.util import bytes_to_int, int_to_bytes

# Types to be used by blueprints.
VertexId = NewType('VertexId', bytes)
Amount = NewType('Amount', int)
Address = NewType('Address', bytes)
TxOutputScript = NewType('TxOutputScript', bytes)
TokenUid = NewType('TokenUid', bytes)
Timestamp = NewType('Timestamp', int)
ContractId = NewType('ContractId', VertexId)
BlueprintId = NewType('BlueprintId', VertexId)
VarInt = NewType('VarInt', int)

T = TypeVar('T')


def blueprint_id_from_bytes(data: bytes) -> BlueprintId:
    """Create a BlueprintId from a bytes object."""
    return BlueprintId(VertexId(data))


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
    assert not hasattr(fn, '_nc_method_type')
    setattr(fn, '_nc_method_type', 'public')
    return fn


def view(fn: Callable) -> Callable:
    """Decorator to mark a blueprint method as view (read-only)."""
    assert not hasattr(fn, '_nc_method_type')
    setattr(fn, '_nc_method_type', 'view')
    return fn


@unique
class NCActionType(Enum):
    """Types of interactions a transaction might have with a contract."""
    DEPOSIT = 1
    WITHDRAWAL = 2

    def __str__(self) -> str:
        return self.name.lower()

    def to_bytes(self) -> bytes:
        return int_to_bytes(number=self.value, size=1)

    @staticmethod
    def from_bytes(data: bytes) -> NCActionType:
        return NCActionType(bytes_to_int(data))


class NCAction(NamedTuple):
    type: NCActionType
    token_uid: TokenUid
    amount: int
