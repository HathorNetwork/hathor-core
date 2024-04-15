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

from hathor.transaction import BaseTransaction
from hathor.verification.verification_service import VerificationService


class ParallelVerifier:
    __slots__ = ('_verification_service',)

    def __init__(self, *, verification_service: VerificationService) -> None:
        self._verification_service = verification_service

    async def validate_full(self, vertex: BaseTransaction, *, reject_locked_reward: bool) -> bool:
        return await self._verification_service.validate_full_async(vertex, reject_locked_reward=reject_locked_reward)
