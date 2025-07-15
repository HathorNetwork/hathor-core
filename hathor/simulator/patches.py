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
from typing_extensions import override

from hathor.mining.cpu_mining_service import CpuMiningService
from hathor.transaction import BaseTransaction
from hathor.verification.vertex_verifier import VertexVerifier

logger = get_logger()


class SimulatorVertexVerifier(VertexVerifier):
    @classmethod
    def verify_pow(cls, vertex: BaseTransaction, *, override_weight: Optional[float] = None) -> None:
        logger.new().debug('Skipping VertexVerifier.verify_pow() for simulator')


class SimulatorCpuMiningService(CpuMiningService):
    @override
    def resolve(
        self,
        vertex: BaseTransaction,
        *,
        update_time: bool = False,
    ) -> bool:
        vertex.update_hash()
        logger.new().debug('Skipping CpuMiningService.resolve() for simulator')
        return True
