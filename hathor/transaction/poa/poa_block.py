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

from typing import Any

from typing_extensions import override

from hathor.conf.settings import HathorSettings
from hathor.consensus import poa
from hathor.consensus.consensus_settings import PoaSettings
from hathor.serialization import Serializer
from hathor.transaction import Block, TxOutput, TxVersion
from hathor.transaction.storage import TransactionStorage


class PoaBlock(Block):
    """A Proof-of-Authority block."""

    def __init__(
        self,
        timestamp: int | None = None,
        signal_bits: int = 0,
        weight: float = 0,
        outputs: list[TxOutput] | None = None,
        parents: list[bytes] | None = None,
        hash: bytes | None = None,
        data: bytes = b'',
        storage: TransactionStorage | None = None,
        signer_id: bytes = b'',
        signature: bytes = b'',
        settings: HathorSettings | None = None,
    ) -> None:
        assert not outputs, 'PoaBlocks must not have outputs'
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
            storage=storage,
            settings=settings,
        )
        self.signer_id = signer_id
        self.signature = signature

    @override
    def get_graph_struct(self) -> bytes:
        from hathor.transaction.vertex_parser._block import serialize_poa_block_graph_fields
        assert len(self.signer_id) == poa.SIGNER_ID_LEN
        serializer = Serializer.build_bytes_serializer()
        serialize_poa_block_graph_fields(serializer, self)
        return bytes(serializer.finalize())

    @override
    def to_json(self, decode_script: bool = False, include_metadata: bool = False) -> dict[str, Any]:
        poa_settings = self._settings.CONSENSUS_ALGORITHM
        assert isinstance(poa_settings, PoaSettings)
        json = super().to_json(decode_script=decode_script, include_metadata=include_metadata)
        signature_validation = poa.verify_poa_signature(poa_settings, self)

        if isinstance(signature_validation, poa.ValidSignature):
            json['signer'] = signature_validation.public_key.hex()

        json['signer_id'] = self.signer_id.hex()
        return json
