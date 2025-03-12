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

from typing import TYPE_CHECKING, Optional

from structlog import get_logger

from hathor.transaction import Transaction, TxInput, TxOutput, TxVersion
from hathor.transaction.headers import NanoHeader, VertexHeaderId
from hathor.transaction.util import VerboseCallback

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage  # noqa: F401

logger = get_logger()


class DeprecatedNanoContract(Transaction):
    """NanoContract vertex to be placed on the DAG of transactions."""

    def __init__(self,
                 nonce: int = 0,
                 timestamp: Optional[int] = None,
                 version: TxVersion = TxVersion.NANO_CONTRACT,
                 weight: float = 0,
                 inputs: Optional[list[TxInput]] = None,
                 outputs: Optional[list[TxOutput]] = None,
                 parents: Optional[list[bytes]] = None,
                 tokens: Optional[list[bytes]] = None,
                 hash: Optional[bytes] = None,
                 storage: Optional['TransactionStorage'] = None) -> None:
        super().__init__(nonce=nonce, timestamp=timestamp, version=version, weight=weight, inputs=inputs,
                         outputs=outputs or [], tokens=tokens, parents=parents or [], hash=hash, storage=storage)

    ################################
    # Methods for Transaction
    ################################

    def get_funds_fields_from_struct(self, buf: bytes, *, verbose: VerboseCallback = None) -> bytes:
        buf = super().get_funds_fields_from_struct(buf, verbose=verbose)
        nano_header, buf = NanoHeader.deserialize(self, VertexHeaderId.NANO_HEADER.value + buf, verbose=verbose)
        self.headers.append(nano_header)
        return buf

    def get_funds_struct(self) -> bytes:
        struct_bytes = super().get_funds_struct()
        nano_header_bytes = self.get_nano_header().serialize()
        struct_bytes += nano_header_bytes[1:]
        return struct_bytes

    def get_headers_hash(self) -> bytes:
        return b''

    def get_headers_struct(self) -> bytes:
        return b''
