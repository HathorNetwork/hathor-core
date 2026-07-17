# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from enum import Enum, unique


@unique
class VertexHeaderId(Enum):
    NANO_HEADER = b'\x10'
    FEE_HEADER = b'\x11'
    SHIELDED_OUTPUTS_HEADER = b'\x12'
    UNSHIELD_BALANCE_HEADER = b'\x13'
