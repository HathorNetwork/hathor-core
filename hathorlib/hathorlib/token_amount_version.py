# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from enum import IntEnum, unique


@unique
class TokenAmountVersion(IntEnum):
    """
    The version under which a vertex's token amounts must be interpreted, according to the version's decimal places.

    The integer value is the raw version as encoded in the vertex, so it is part of the
    serialization contract and must remain stable.
    """

    V1 = 1
    V2 = 2
