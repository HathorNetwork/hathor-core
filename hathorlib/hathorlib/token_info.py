# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
