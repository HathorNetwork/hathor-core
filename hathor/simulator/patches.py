#  Copyright 2023 Hathor Labs
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

from typing import Optional

from structlog import get_logger

from hathor.mining.cpu_mining_service import CpuMiningService
from hathor.transaction import BaseTransaction
from hathor.verification.block_verifier import BlockVerifier
from hathor.verification.merge_mined_block_verifier import MergeMinedBlockVerifier
from hathor.verification.token_creation_transaction_verifier import TokenCreationTransactionVerifier
from hathor.verification.transaction_verifier import TransactionVerifier

logger = get_logger()


def _verify_pow(vertex: BaseTransaction) -> None:
    assert vertex.hash is not None
    logger.new().debug('Skipping VertexVerifier.verify_pow() for simulator')


class SimulatorBlockVerifier(BlockVerifier):
    @classmethod
    def verify_pow(cls, vertex: BaseTransaction, *, override_weight: Optional[float] = None) -> None:
        _verify_pow(vertex)


class SimulatorMergeMinedBlockVerifier(MergeMinedBlockVerifier):
    @classmethod
    def verify_pow(cls, vertex: BaseTransaction, *, override_weight: Optional[float] = None) -> None:
        _verify_pow(vertex)


class SimulatorTransactionVerifier(TransactionVerifier):
    @classmethod
    def verify_pow(cls, vertex: BaseTransaction, *, override_weight: Optional[float] = None) -> None:
        _verify_pow(vertex)


class SimulatorTokenCreationTransactionVerifier(TokenCreationTransactionVerifier):
    @classmethod
    def verify_pow(cls, vertex: BaseTransaction, *, override_weight: Optional[float] = None) -> None:
        _verify_pow(vertex)


class SimulatorCpuMiningService(CpuMiningService):
    def resolve(self, vertex: BaseTransaction, *, update_time: bool = False) -> bool:
        vertex.update_hash()
        logger.new().debug('Skipping CpuMiningService.resolve() for simulator')
        return True
