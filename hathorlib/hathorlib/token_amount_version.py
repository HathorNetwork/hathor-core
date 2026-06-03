#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from __future__ import annotations

from enum import IntEnum, unique
from typing import TYPE_CHECKING

from typing_extensions import assert_never

if TYPE_CHECKING:
    from hathorlib.conf.settings import HathorSettings


@unique
class TokenAmountVersion(IntEnum):
    """
    The version under which a vertex's token amounts must be interpreted, according to the version's decimal places.

    The integer value is the raw version as encoded in the vertex, so it is part of the
    serialization contract and must remain stable.
    """

    V1 = 1
    V2 = 2

    def get_decimal_places(self, settings: HathorSettings) -> int:
        """Return the number of decimal places this version maps to, according to settings."""
        match self:
            case TokenAmountVersion.V1:
                return settings.TOKEN_AMOUNT_V1_DECIMAL_PLACES
            case TokenAmountVersion.V2:
                return settings.TOKEN_AMOUNT_V2_DECIMAL_PLACES
            case _:
                assert_never(self)
