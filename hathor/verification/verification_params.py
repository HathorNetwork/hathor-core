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

from hathor.feature_activation.utils import Features
from hathor.transaction import Block


@dataclass(slots=True, frozen=True, kw_only=True)
class VerificationParams:
    """Contains every parameter/setting to run a single verification."""

    nc_block_root_id: bytes | None
    reject_locked_reward: bool = True
    skip_block_weight_verification: bool = False
    features: Features

    reject_too_old_vertices: bool = False
    harden_token_restrictions: bool = False
    harden_nano_restrictions: bool = False
    reject_conflicts_with_confirmed_txs: bool = False

    @classmethod
    def default_for_mempool(cls, *, best_block: Block, features: Features) -> VerificationParams:
        """This is the appropriate parameters for verifying mempool transactions, realtime blocks and API pushes.

        Callers MUST compute features via Features.from_vertex() to ensure
        feature activation state (including shielded_transactions) is correct.

        Other cases should instantiate `VerificationParams` manually with the appropriate parameter values.
        """
        best_block_meta = best_block.get_metadata()
        if best_block_meta.nc_block_root_id is None:
            assert best_block.is_genesis

        return cls(
            nc_block_root_id=best_block_meta.nc_block_root_id,
            features=features,
            reject_too_old_vertices=True,
            harden_token_restrictions=True,
            harden_nano_restrictions=True,
            reject_conflicts_with_confirmed_txs=True,
        )
