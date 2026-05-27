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
class VertexDecimalVersion(IntEnum):
    """
    The decimal-places version under which a vertex's token amounts must be interpreted.

    The integer value is the raw version as encoded in the vertex, so it is part of the
    serialization contract and must remain stable.
    """

    V1 = 1
    V2 = 2

    def get_decimal_places(self, settings: HathorSettings) -> int:
        """Return the number of decimal places this version maps to, according to settings."""
        decimal_places = settings.VERTEX_DECIMAL_PLACES.get(self)
        if decimal_places is None:
            raise ValueError(f'unsupported decimal places version {self.name}')
        return decimal_places

    def normalize_token_value(self, *, settings: HathorSettings, value: int) -> int:
        """
        Normalize a token value (amount) according to a decimal places version.

        Currently, it has hardcoded support for V1 with 2 decimal places and V2 with 18 decimal places.
        V2 values are returned as-is, and V1 values are scaled up with a factor of 10**16.
        """
        v1_decimal_places = VertexDecimalVersion.V1.get_decimal_places(settings)
        v2_decimal_places = VertexDecimalVersion.V2.get_decimal_places(settings)

        # Hardcoding these here as this is most likely a one-time update, and we need to
        # be very deliberate about how to normalize values if we ever change it again.
        assert v1_decimal_places == 2
        assert v2_decimal_places == 18

        match self:
            case VertexDecimalVersion.V1:
                v1_v2_normalization_factor = 10 ** (v2_decimal_places - v1_decimal_places)
                return value * v1_v2_normalization_factor
            case VertexDecimalVersion.V2:
                return value
            case _:
                assert_never(self)
