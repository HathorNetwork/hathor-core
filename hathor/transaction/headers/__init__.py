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

from hathor.transaction.headers.base import VertexBaseHeader
from hathor.transaction.headers.fee_header import FeeHeader
from hathor.transaction.headers.nano_header import NanoHeader
from hathor.transaction.headers.types import VertexHeaderId
from hathorlib.headers.base import VertexBaseHeader as _HathorlibVertexBaseHeader
from hathorlib.headers.shielded_outputs_header import ShieldedOutputsHeader
from hathorlib.headers.unshield_balance_header import UnshieldBalanceHeader

# Widened to hathorlib's header base so hathorlib's shielded headers are admitted
# alongside hathor-core's headers (a broader type for the cross-lib header classes).
AnyVertexHeader = VertexBaseHeader | _HathorlibVertexBaseHeader

# NOTE: MintHeader/MeltHeader (header IDs 0x14/0x15) are deferred to a separate
# later PR. They are a post-plan extension to the original 8-PR shielded-tx split
# (see docs/plans/shielded-pr-split.md "Post-plan extensions"). The
# hathor.transaction.headers.mint_melt_header module and its exports — MintHeader,
# MeltHeader, MintMeltEntry — will be added here when that PR lands.

__all__ = [
    'VertexBaseHeader',
    'VertexHeaderId',
    'NanoHeader',
    'FeeHeader',
    'ShieldedOutputsHeader',
    'UnshieldBalanceHeader',
    'AnyVertexHeader',
]
