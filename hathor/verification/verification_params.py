# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
    def for_mempool(cls, *, best_block: Block, features: Features) -> VerificationParams:
        """This is the appropriate parameters for verifying mempool transactions, realtime blocks and API pushes.

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
