# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
