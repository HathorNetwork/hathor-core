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

import time
from typing import Callable, Optional

from hathor.transaction import BaseTransaction
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.types import VertexId

MAX_NONCE = 2**32


class CpuMiningService:
    def resolve(self, vertex: BaseTransaction, *, update_time: bool = False) -> bool:
        """Run a CPU mining looking for the nonce that solves the proof-of-work

        The `vertex.weight` must be set before calling this method.

        :param update_time: update timestamp every 2 seconds
        :return: True if a solution was found
        :rtype: bool
        """
        hash_bytes = self.start_mining(vertex, update_time=update_time)

        if hash_bytes:
            vertex.hash = hash_bytes
            metadata = getattr(vertex, '_metadata', None)
            if metadata is not None and metadata.hash is not None:
                metadata.hash = hash_bytes

            if isinstance(vertex, TokenCreationTransaction):
                vertex.tokens = [vertex.hash]

            return True
        else:
            return False

    @staticmethod
    def start_mining(
        vertex: BaseTransaction,
        *,
        start: int = 0,
        end: int = MAX_NONCE,
        sleep_seconds: float = 0.0,
        update_time: bool = True,
        should_stop: Callable[[], bool] = lambda: False
    ) -> Optional[VertexId]:
        """Starts mining until it solves the problem, i.e., finds the nonce that satisfies the conditions

        :param start: beginning of the search interval
        :param end: end of the search interval
        :param sleep_seconds: the number of seconds it will sleep after each attempt
        :param update_time: update timestamp every 2 seconds
        :return The hash of the solved PoW or None when it is not found
        """
        pow_part1 = vertex.calculate_hash1()
        target = vertex.get_target()
        vertex.nonce = start
        last_time = time.time()
        while vertex.nonce < end:
            if update_time:
                now = time.time()
                if now - last_time > 2:
                    if should_stop():
                        return None
                    vertex.timestamp = int(now)
                    pow_part1 = vertex.calculate_hash1()
                    last_time = now
                    vertex.nonce = start

            result = vertex.calculate_hash2(pow_part1.copy())
            if int(result.hex(), vertex.HEX_BASE) < target:
                return result
            vertex.nonce += 1
            if sleep_seconds > 0:
                time.sleep(sleep_seconds)
                if should_stop():
                    return None
        return None
