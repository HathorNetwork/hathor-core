# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Shielded transaction cryptographic primitives.

The cryptographic primitives themselves (Pedersen commitments, range proofs,
surjection proofs, homomorphic balance) live in the native ``hathor_ct_crypto``
Rust module. Only Python-side helpers remain in this package.
"""

from __future__ import annotations

from hathor.crypto.shielded.asset_tag import normalize_token_uid

__all__ = [
    'normalize_token_uid',
]
