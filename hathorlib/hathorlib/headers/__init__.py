# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathorlib.headers.base import VertexBaseHeader
from hathorlib.headers.fee_header import FeeEntry, FeeHeader, FeeHeaderEntry
# NOTE: MintHeader/MeltHeader (header IDs 0x14/0x15) are deferred to a separate
# later PR. They are a post-plan extension to the original 8-PR shielded-tx split
# (see docs/plans/shielded-pr-split.md "Post-plan extensions"). The
# hathorlib.headers.mint_melt_header module and its exports — MintHeader,
# MeltHeader, MintMeltEntry, MAX_MINT_MELT_ENTRIES, serialize_entries,
# deserialize_entries — will be added here when that PR lands.
from hathorlib.headers.nano_header import NC_INITIALIZE_METHOD, NanoHeader
from hathorlib.headers.shielded_outputs_header import ShieldedOutputsHeader
from hathorlib.headers.types import VertexHeaderId
from hathorlib.headers.unshield_balance_header import UnshieldBalanceHeader

__all__ = [
    'VertexBaseHeader',
    'VertexHeaderId',
    'NanoHeader',
    'FeeHeader',
    'FeeHeaderEntry',
    'FeeEntry',
    'NC_INITIALIZE_METHOD',
    'ShieldedOutputsHeader',
    'UnshieldBalanceHeader',
]
