# Copyright 2021 Hathor Labs
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

from abc import ABC, abstractmethod
from enum import IntEnum, unique
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage


@unique
class MigrationState(IntEnum):
    NOT_STARTED = 0
    STARTED = 1
    # XXX: we might have to introduce multiple states in the future, so I'm leaving some room before COMPLETED, this
    #      way new states can be sorted in a way that makes sense
    COMPLETED = 100
    ERROR = -1

    def to_db_bytes(self) -> bytes:
        import struct
        return struct.pack('!b', self.value)

    @classmethod
    def from_db_bytes(cls, data: bytes) -> 'MigrationState':
        import struct
        val, = struct.unpack('!b', data)
        return cls(val)


# XXX: make sure that no migration state has a value outside of a certain range, because of how they are stored
for _migration_state in MigrationState:
    _value = _migration_state.value
    if _value not in range(-128, 128):
        raise TypeError(f'MigrationState requires a value in [-128, 128), {_migration_state} has value {_value}')


class BaseMigration(ABC):
    @abstractmethod
    def skip_empty_db(self) -> bool:
        """Whether this migration should skip running on an empty database.

        By default returns `True`, which means it will be automatically marked as COMPLETED on an empty database.
        """
        raise NotImplementedError

    @abstractmethod
    def get_db_name(self) -> str:
        """Used to store the migration state on the database."""
        raise NotImplementedError

    @abstractmethod
    def run(self, storage: 'TransactionStorage') -> None:
        """Actual implementation of the migration."""
        raise NotImplementedError
