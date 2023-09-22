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

from typing import TYPE_CHECKING, Any, Optional

from hathor.transaction.aux_pow import BitcoinAuxPow
from hathor.transaction.base_transaction import TxOutput, TxVersion
from hathor.transaction.block import Block
from hathor.transaction.util import VerboseCallback
from hathor.verification import block_verification

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage  # noqa: F401


class MergeMinedBlock(Block):
    def __init__(self,
                 nonce: int = 0,
                 timestamp: Optional[int] = None,
                 signal_bits: int = 0,
                 version: int = TxVersion.MERGE_MINED_BLOCK,
                 weight: float = 0,
                 outputs: Optional[list[TxOutput]] = None,
                 parents: Optional[list[bytes]] = None,
                 hash: Optional[bytes] = None,
                 data: bytes = b'',
                 aux_pow: Optional[BitcoinAuxPow] = None,
                 storage: Optional['TransactionStorage'] = None) -> None:
        super().__init__(nonce=nonce, timestamp=timestamp, signal_bits=signal_bits, version=version, weight=weight,
                         data=data, outputs=outputs or [], parents=parents or [], hash=hash, storage=storage)
        self.aux_pow = aux_pow

    def _get_formatted_fields_dict(self, short: bool = True) -> dict[str, str]:
        from hathor.util import abbrev
        d = super()._get_formatted_fields_dict(short)
        del d['nonce']
        if self.aux_pow is not None:
            d.update(aux_pow=abbrev(bytes(self.aux_pow).hex().encode('ascii'), 128).decode('ascii'))
        return d

    @classmethod
    def create_from_struct(cls, struct_bytes: bytes, storage: Optional['TransactionStorage'] = None,
                           *, verbose: VerboseCallback = None) -> 'MergeMinedBlock':
        blc = cls()
        buf = blc.get_fields_from_struct(struct_bytes, verbose=verbose)
        blc.aux_pow = BitcoinAuxPow.from_bytes(buf)
        blc.hash = blc.calculate_hash()
        blc.storage = storage
        return blc

    def calculate_hash(self) -> bytes:
        assert self.aux_pow is not None
        return self.aux_pow.calculate_hash(self.get_base_hash())

    def get_struct_nonce(self) -> bytes:
        if not self.aux_pow:
            # FIXME: this happens sometimes, why?
            dummy_bytes = bytes(BitcoinAuxPow.dummy())
            return dummy_bytes
        return bytes(self.aux_pow)

    def to_json(self, decode_script: bool = False, include_metadata: bool = False) -> dict[str, Any]:
        json = super().to_json(decode_script=decode_script, include_metadata=include_metadata)
        del json['nonce']
        json['aux_pow'] = bytes(self.aux_pow).hex() if self.aux_pow else None
        return json

    def verify_without_storage(self) -> None:
        self.verify_aux_pow()
        block_verification.verify_without_storage(self, settings=self._settings)

    def verify_aux_pow(self) -> None:
        """ Verify auxiliary proof-of-work (for merged mining).
        """
        assert self.aux_pow is not None
        self.aux_pow.verify(self.get_base_hash())
