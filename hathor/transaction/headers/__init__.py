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
