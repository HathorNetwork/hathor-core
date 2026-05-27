"""Shielded transaction cryptographic primitives.

The cryptographic primitives themselves (Pedersen commitments, range proofs,
surjection proofs, homomorphic balance) live in the native ``hathor_ct_crypto``
Rust module and are imported directly from there. Only the helpers that carry
Python-side logic remain in this package.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hathor.crypto.shielded._bindings import AVAILABLE as SHIELDED_CRYPTO_AVAILABLE

if TYPE_CHECKING:
    from hathor.conf.settings import FeatureSetting

from hathor.crypto.shielded.asset_tag import normalize_token_uid
from hathor.crypto.shielded.balance import verify_balance


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
    'normalize_token_uid',
    'verify_balance',
]
