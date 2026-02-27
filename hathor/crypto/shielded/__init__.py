"""Shielded transaction cryptographic primitives.

This package wraps the native Rust hathor-ct-crypto library,
providing Pedersen commitments, Bulletproof range proofs,
surjection proofs, and homomorphic balance verification.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hathor.crypto.shielded._bindings import AVAILABLE as SHIELDED_CRYPTO_AVAILABLE

if TYPE_CHECKING:
    from hathor.conf.settings import FeatureSetting
from hathor.crypto.shielded.asset_tag import create_asset_commitment, derive_asset_tag, derive_tag, htr_asset_tag
from hathor.crypto.shielded.balance import compute_balancing_blinding_factor, verify_balance
from hathor.crypto.shielded.commitment import (
    create_commitment,
    create_trivial_commitment,
    validate_commitment,
    validate_generator,
    verify_commitments_sum,
)
from hathor.crypto.shielded.range_proof import create_range_proof, rewind_range_proof, verify_range_proof
from hathor.crypto.shielded.surjection import create_surjection_proof, verify_surjection_proof


def validate_shielded_crypto_available(feature_setting: FeatureSetting) -> None:
    """Validate that the native crypto library is available when the shielded feature is not disabled.

    Should be called at node startup to fail fast with a clear error message.
    """
    from hathor.conf.settings import FeatureSetting as _FeatureSetting
    if feature_setting != _FeatureSetting.DISABLED and not SHIELDED_CRYPTO_AVAILABLE:
        raise RuntimeError(
            'hathor_ct_crypto native library is not available, but '
            f'ENABLE_SHIELDED_TRANSACTIONS={feature_setting.value}. '
            'Either compile the library (maturin develop) or set '
            'ENABLE_SHIELDED_TRANSACTIONS=disabled.'
        )


__all__ = [
    'SHIELDED_CRYPTO_AVAILABLE',
    'validate_shielded_crypto_available',
    'create_asset_commitment',
    'create_commitment',
    'create_range_proof',
    'create_surjection_proof',
    'rewind_range_proof',
    'create_trivial_commitment',
    'compute_balancing_blinding_factor',
    'derive_asset_tag',
    'derive_tag',
    'htr_asset_tag',
    'validate_commitment',
    'validate_generator',
    'verify_balance',
    'verify_commitments_sum',
    'verify_range_proof',
    'verify_surjection_proof',
]
