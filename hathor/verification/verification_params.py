#  Copyright 2025 Hathor Labs
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

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True, frozen=True, kw_only=True)
class VerificationParams:
    """Contains every parameter/setting to run a single verification."""

    enable_checkdatasig_count: bool
    reject_locked_reward: bool = True
    skip_block_weight_verification: bool = False

    @classmethod
    def default_for_mempool(cls) -> VerificationParams:
        """This is the appropriate parameters for veriyfing mempool transactions, realtime blocks and API pushes.

        Other cases should instantiate `VerificationParams` manually with the appropriate parameter values.
        """
        return cls(
            enable_checkdatasig_count=True,
        )
