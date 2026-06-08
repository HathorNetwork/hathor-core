"""Shielded transaction cryptographic primitives.

The cryptographic primitives themselves (Pedersen commitments, range proofs,
surjection proofs, homomorphic balance) live in the native ``hathor_ct_crypto``
Rust module. Only Python-side helpers remain in this package.
"""

from __future__ import annotations

from hathor.crypto.shielded.asset_tag import normalize_token_uid

# Runtime gate for the wallet's shielded discovery path.
#
# Held at False because the native Rust crate (htr-rs/crates/hathor-ct-crypto)
# is currently an empty stub — its functions don't exist, so any actual call
# would AttributeError. With this constant at False, the wallet's existing
# guard (`if not SHIELDED_CRYPTO_AVAILABLE: return False`) keeps the discovery
# loop structurally dormant, even if an operator enables
# ENABLE_SHIELDED_TRANSACTIONS. The constant only flips to True when PR-8
# ships the real Rust implementation — not when PR-5 merges.
#
# PR-5 cleanup (post-Jan's _bindings removal): this constant is gone on master.
# When PR-6 rebases post-PR-5, drop this line AND remove the `if not
# SHIELDED_CRYPTO_AVAILABLE: return False` block in hathor/wallet/base_wallet.py.
SHIELDED_CRYPTO_AVAILABLE: bool = False

__all__ = [
    'normalize_token_uid',
    'SHIELDED_CRYPTO_AVAILABLE',
]
