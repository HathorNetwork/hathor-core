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

from typing_extensions import override

from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.feature_activation.feature_service import FeatureService
from hathor.transaction.aux_pow import BitcoinAuxPow
from hathor.transaction.base_transaction import BaseTransaction, TxOutput, TxVersion
from hathor.transaction.block import Block
from hathor.transaction.util import VerboseCallback
from hathor.types import VertexId
from hathor.util import not_none

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage  # noqa: F401
    from hathor.verification.verification_model import VerificationModel


class MergeMinedBlock(Block):
    def __init__(self,
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

    @override
    def get_verification_model(
        self,
        *,
        daa: DifficultyAdjustmentAlgorithm,
        feature_service: FeatureService | None = None,
        skip_weight_verification: bool = False,
        pre_fetched_deps: dict[VertexId, 'BaseTransaction'] | None = None,
        only_basic: bool = False
    ) -> 'VerificationModel':
        from hathor.verification.verification_dependencies import BasicBlockDependencies, BlockDependencies
        from hathor.verification.verification_model import VerificationMergeMinedBlock
        basic_deps = BasicBlockDependencies.create(
            self,
            daa=daa,
            skip_weight_verification=skip_weight_verification,
            pre_fetched_deps=pre_fetched_deps
        )

        if only_basic:
            deps = None
        else:
            deps = BlockDependencies.create(
                self,
                feature_service=not_none(feature_service),
                pre_fetched_deps=pre_fetched_deps
            )

        return VerificationMergeMinedBlock(
            vertex=self.clone(include_storage=False, include_metadata=False),
            basic_deps=basic_deps,
            deps=deps,
        )
