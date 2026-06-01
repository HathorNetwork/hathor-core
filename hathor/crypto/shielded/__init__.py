"""Shielded transaction cryptographic primitives.

The cryptographic primitives themselves (Pedersen commitments, range proofs,
surjection proofs, homomorphic balance) live in the native ``hathor_ct_crypto``
Rust module and are imported directly from there. Only the helpers that carry
Python-side logic remain in this package.
"""

from __future__ import annotations

from hathor.crypto.shielded.asset_tag import normalize_token_uid

__all__ = [
    'normalize_token_uid',
]
