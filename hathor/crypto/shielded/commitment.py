"""Pedersen commitment helpers wrapping the native Rust library."""

from hathor.crypto.shielded._bindings import _lib

COMMITMENT_SIZE: int = 33


def create_commitment(amount: int, blinding: bytes, generator: bytes) -> bytes:
    """Create a Pedersen commitment: C = amount * H + blinding * G."""
    if _lib is None:
        raise RuntimeError('hathor_ct_crypto native library is not available')
    return _lib.create_commitment(amount, blinding, generator)


def create_trivial_commitment(amount: int, generator: bytes) -> bytes:
    """Create a trivial (zero-blinding) Pedersen commitment: C = amount * H."""
    if _lib is None:
        raise RuntimeError('hathor_ct_crypto native library is not available')
    return _lib.create_trivial_commitment(amount, generator)


def verify_commitments_sum(positive: list[bytes], negative: list[bytes]) -> bool:
    """Verify that sum(positive) == sum(negative)."""
    if _lib is None:
        raise RuntimeError('hathor_ct_crypto native library is not available')
    return _lib.verify_commitments_sum(positive, negative)


def validate_commitment(data: bytes) -> bool:
    """Validate that bytes represent a valid Pedersen commitment (curve point)."""
    if _lib is None:
        raise RuntimeError('hathor_ct_crypto native library is not available')
    return _lib.validate_commitment(data)


def validate_generator(data: bytes) -> bool:
    """Validate that bytes represent a valid generator (curve point)."""
    if _lib is None:
        raise RuntimeError('hathor_ct_crypto native library is not available')
    return _lib.validate_generator(data)
