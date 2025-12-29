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

from hathorlib.utils import bytes_to_int, int_to_bytes


@unique
class NCActionType(Enum):
    """Types of interactions a transaction might have with a contract."""
    DEPOSIT = 1
    WITHDRAWAL = 2
    GRANT_AUTHORITY = 3
    ACQUIRE_AUTHORITY = 4

    def __str__(self) -> str:
        return self.name.lower()

    def to_bytes(self) -> bytes:
        return int_to_bytes(number=self.value, size=1)

    @staticmethod
    def from_bytes(data: bytes) -> NCActionType:
        return NCActionType(bytes_to_int(data))
