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

from dataclasses import dataclass
from enum import IntEnum


class TokenVersion(IntEnum):
    NATIVE = 0
    DEPOSIT = 1
    FEE = 2


@dataclass(slots=True, frozen=True, kw_only=True)
class TokenDescription:
    token_id: bytes
    token_name: str
    token_symbol: str
    token_version: TokenVersion

    def __post_init__(self) -> None:
        assert isinstance(self.token_version, TokenVersion)
