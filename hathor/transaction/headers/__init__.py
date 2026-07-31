# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import TypeAlias

from hathor.transaction.headers.fee_header import FeeHeader
from hathor.transaction.headers.nano_header import NanoHeader
from hathor.transaction.headers.types import VertexHeaderId
from hathorlib.headers.base import VertexBaseHeader as _HathorlibVertexBaseHeader
from hathorlib.headers.mint_melt_header import MeltHeader, MintHeader, MintMeltEntry
from hathorlib.headers.shielded_outputs_header import ShieldedOutputsHeader
from hathorlib.headers.unshield_balance_header import UnshieldBalanceHeader

# Widened to hathorlib's header base so hathorlib's shielded headers are admitted
# alongside hathor-core's headers (a broader type for the cross-lib header classes).
AnyVertexHeader: TypeAlias = NanoHeader | FeeHeader | _HathorlibVertexBaseHeader

__all__ = [
    'VertexHeaderId',
    'NanoHeader',
    'FeeHeader',
    'ShieldedOutputsHeader',
    'UnshieldBalanceHeader',
    'MintHeader',
    'MeltHeader',
    'MintMeltEntry',
    'AnyVertexHeader',
]
