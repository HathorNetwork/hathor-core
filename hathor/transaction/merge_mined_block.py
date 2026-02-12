# Copyright 2021 Hathor Labs
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

from typing import TYPE_CHECKING, Any, Optional

from typing_extensions import Self, override

from hathor.transaction.aux_pow import BitcoinAuxPow
from hathor.transaction.base_transaction import TxOutput, TxVersion
from hathor.transaction.block import Block
from hathor.transaction.util import VerboseCallback

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.transaction.storage import TransactionStorage  # noqa: F401


class MergeMinedBlock(Block):
    def __init__(
        self,
        nonce: int = 0,
        timestamp: Optional[int] = None,
        signal_bits: int = 0,
        version: TxVersion = TxVersion.MERGE_MINED_BLOCK,
        weight: float = 0,
        outputs: Optional[list[TxOutput]] = None,
        parents: Optional[list[bytes]] = None,
        hash: Optional[bytes] = None,
        data: bytes = b'',
        aux_pow: Optional[BitcoinAuxPow] = None,
        storage: Optional['TransactionStorage'] = None,
        settings: HathorSettings | None = None,
    ) -> None:
        super().__init__(
            nonce=nonce,
            timestamp=timestamp,
            signal_bits=signal_bits,
            version=version,
            weight=weight,
            data=data,
            outputs=outputs or [],
            parents=parents or [],
            hash=hash,
            storage=storage,
            settings=settings
        )
        self.aux_pow = aux_pow

    @classmethod
    @override
    def create_from_struct(cls, struct_bytes: bytes, storage: Optional['TransactionStorage'] = None,
                           *, verbose: VerboseCallback = None) -> Self:
        from hathor.serialization import Deserializer
        from hathor.transaction.vertex_parser._block import deserialize_block_funds, deserialize_block_graph_fields
        block = cls(storage=storage)
        deserializer = Deserializer.build_bytes_deserializer(struct_bytes)
        deserialize_block_funds(deserializer, block, verbose=verbose)
        deserialize_block_graph_fields(deserializer, block, verbose=verbose)
        block.aux_pow = BitcoinAuxPow.from_bytes(bytes(deserializer.read_all()))
        deserializer.finalize()
        block.hash = block.calculate_hash()
        block.storage = storage
        return block

    @override
    def get_struct_nonce(self) -> bytes:
        if not self.aux_pow:
            return bytes(BitcoinAuxPow.dummy())
        return bytes(self.aux_pow)

    def _get_formatted_fields_dict(self, short: bool = True) -> dict[str, str]:
        from hathor.util import abbrev
        d = super()._get_formatted_fields_dict(short)
        del d['nonce']
        if self.aux_pow is not None:
            d.update(aux_pow=abbrev(bytes(self.aux_pow).hex().encode('ascii'), 128).decode('ascii'))
        return d

    def calculate_hash(self) -> bytes:
        assert self.aux_pow is not None
        return self.aux_pow.calculate_hash(self.get_mining_base_hash())

    def to_json(self, decode_script: bool = False, include_metadata: bool = False) -> dict[str, Any]:
        json = super().to_json(decode_script=decode_script, include_metadata=include_metadata)
        del json['nonce']
        json['aux_pow'] = bytes(self.aux_pow).hex() if self.aux_pow else None
        return json
