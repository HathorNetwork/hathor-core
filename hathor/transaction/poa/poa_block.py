#  Copyright 2024 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from hathor.consensus import poa
from hathor.transaction import Block, TxVersion
from hathor.transaction.storage import TransactionStorage
from hathor.transaction.util import VerboseCallback, int_to_bytes, unpack, unpack_len

# Size limit in bytes for signature field
_MAX_POA_SIGNATURE_LEN: int = 100


class PoaBlock(Block):
    """A Proof-of-Authority block."""

    def __init__(
        self,
        timestamp: int | None = None,
        signal_bits: int = 0,
        weight: float = 0,
        parents: list[bytes] | None = None,
        hash: bytes | None = None,
        data: bytes = b'',
        storage: TransactionStorage | None = None,
        signer_id: bytes = b'',
        signature: bytes = b'',
    ) -> None:
        super().__init__(
            nonce=0,
            timestamp=timestamp,
            signal_bits=signal_bits,
            version=TxVersion.POA_BLOCK,
            weight=weight,
            outputs=[],
            parents=parents or [],
            hash=hash,
            data=data,
            storage=storage
        )
        self.signer_id = signer_id
        self.signature = signature

    def get_graph_fields_from_struct(self, buf: bytes, *, verbose: VerboseCallback = None) -> bytes:
        buf = super().get_graph_fields_from_struct(buf, verbose=verbose)

        self.signer_id, buf = unpack_len(poa.SIGNER_ID_LEN, buf)
        if verbose:
            verbose('signer_id', self.signer_id.hex())

        (signature_len,), buf = unpack('!B', buf)
        if verbose:
            verbose('signature_len', signature_len)

        if signature_len > _MAX_POA_SIGNATURE_LEN:
            raise ValueError(f'invalid signature length: {signature_len}')

        self.signature, buf = unpack_len(signature_len, buf)
        if verbose:
            verbose('signature', self.signature.hex())

        return buf

    def get_graph_struct(self) -> bytes:
        assert len(self.signer_id) == poa.SIGNER_ID_LEN
        struct_bytes_without_poa = super().get_graph_struct()
        signature_len = int_to_bytes(len(self.signature), 1)
        return struct_bytes_without_poa + self.signer_id + signature_len + self.signature