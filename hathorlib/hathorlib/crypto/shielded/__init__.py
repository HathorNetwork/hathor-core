"""Shielded transaction cryptographic primitives.

This package wraps the native Rust crypto exposed by ``htr_lib.shielded``,
providing Pedersen commitments, Bulletproof range proofs,
surjection proofs, and homomorphic balance verification.
"""

from __future__ import annotations

from hathorlib.crypto.shielded.asset_tag import (
    create_asset_commitment,
    derive_asset_tag,
    derive_tag,
    htr_asset_tag,
    normalize_token_uid,
)
from hathorlib.crypto.shielded.balance import compute_balancing_blinding_factor, verify_balance
from hathorlib.crypto.shielded.commitment import (
    create_commitment,
    create_trivial_commitment,
    validate_commitment,
    validate_generator,
    verify_commitments_sum,
)
from hathorlib.crypto.shielded.ecdh import (
    derive_ecdh_shared_secret,
    derive_rewind_nonce,
    extract_key_bytes,
    generate_ephemeral_keypair,
)
from hathorlib.crypto.shielded.range_proof import create_range_proof, rewind_range_proof, verify_range_proof
from hathorlib.crypto.shielded.recover import recover_shielded_secrets
from hathorlib.crypto.shielded.surjection import create_surjection_proof, verify_surjection_proof

__all__ = [
    'recover_shielded_secrets',
    'create_asset_commitment',
    'create_commitment',
    'create_range_proof',
    'create_surjection_proof',
    'rewind_range_proof',
    'create_trivial_commitment',
    'compute_balancing_blinding_factor',
    'derive_asset_tag',
    'derive_ecdh_shared_secret',
    'derive_rewind_nonce',
    'derive_tag',
    'extract_key_bytes',
    'generate_ephemeral_keypair',
    'htr_asset_tag',
    'normalize_token_uid',
    'validate_commitment',
    'validate_generator',
    'verify_balance',
    'verify_commitments_sum',
    'verify_range_proof',
    'verify_surjection_proof',
]
