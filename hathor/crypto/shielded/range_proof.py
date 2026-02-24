"""Bulletproof range proof helpers wrapping the native Rust library."""

from hathor.crypto.shielded._bindings import _lib


def create_range_proof(
    amount: int,
    blinding: bytes,
    commitment: bytes,
    generator: bytes,
    message: bytes | None = None,
    nonce: bytes | None = None,
) -> bytes:
    """Create a Bulletproof range proof proving amount is in [0, 2^64).

    If `nonce` is provided (32 bytes), it is used as the nonce key, enabling
    `rewind_range_proof` to recover the committed values. If None, a random nonce is used.
    """
    if _lib is None:
        raise RuntimeError('hathor_ct_crypto native library is not available')
    return _lib.create_range_proof(amount, blinding, commitment, generator, message, nonce)


def verify_range_proof(proof: bytes, commitment: bytes, generator: bytes) -> bool:
    """Verify a Bulletproof range proof."""
    if _lib is None:
        raise RuntimeError('hathor_ct_crypto native library is not available')
    return _lib.verify_range_proof(proof, commitment, generator)


def rewind_range_proof(
    proof: bytes,
    commitment: bytes,
    nonce: bytes,
    generator: bytes,
) -> tuple[int, bytes, bytes]:
    """Rewind a Bulletproof range proof to recover committed value, blinding factor, and message.

    Requires the same nonce key that was used when creating the proof.
    Returns (value, blinding_factor, message).
    """
    if _lib is None:
        raise RuntimeError('hathor_ct_crypto native library is not available')
    return _lib.rewind_range_proof(proof, commitment, nonce, generator)
