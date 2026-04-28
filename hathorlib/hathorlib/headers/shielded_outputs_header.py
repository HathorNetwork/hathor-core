# Copyright 2024 Hathor Labs
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

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from hathorlib.headers.base import VertexBaseHeader
from hathorlib.transaction.shielded_tx_output import ShieldedOutput

if TYPE_CHECKING:
    from hathorlib.transaction import Transaction


@dataclass(frozen=True)
class ShieldedOutputsHeader(VertexBaseHeader):
    """List of shielded outputs attached to a transaction.

    Wire-format (de)serialization lives in
    ``hathorlib.vertex_parser._shielded_outputs_header``; the inherited
    ``serialize``/``deserialize``/``get_sighash_bytes`` methods route
    through the central dispatcher in ``hathorlib.vertex_parser._headers``.
    """

    tx: Transaction
    shielded_outputs: list[ShieldedOutput] = field(default_factory=list)
