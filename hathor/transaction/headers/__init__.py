# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import TypeAlias

from hathor.transaction.headers.fee_header import FeeHeader
from hathor.transaction.headers.nano_header import NanoHeader
from hathor.transaction.headers.types import VertexHeaderId
from hathorlib.headers.base import VertexBaseHeader as _HathorlibVertexBaseHeader
from hathorlib.headers.shielded_outputs_header import ShieldedOutputsHeader
from hathorlib.headers.unshield_balance_header import UnshieldBalanceHeader

# Widened to hathorlib's header base so hathorlib's shielded headers are admitted
# alongside hathor-core's headers (a broader type for the cross-lib header classes).
AnyVertexHeader: TypeAlias = NanoHeader | FeeHeader | _HathorlibVertexBaseHeader

# NOTE: MintHeader/MeltHeader (header IDs 0x14/0x15) are deferred to a separate
# later PR. They are a post-plan extension to the original 8-PR shielded-tx split
# (see docs/plans/shielded-pr-split.md "Post-plan extensions"). The
# hathor.transaction.headers.mint_melt_header module and its exports — MintHeader,
# MeltHeader, MintMeltEntry — will be added here when that PR lands.

__all__ = [
    'VertexHeaderId',
    'NanoHeader',
    'FeeHeader',
    'ShieldedOutputsHeader',
    'UnshieldBalanceHeader',
    'AnyVertexHeader',
]
