"""NUMS asset tag derivation wrapping the native Rust library."""

from hathor.crypto.shielded._bindings import _lib


def derive_asset_tag(token_uid: bytes) -> bytes:
    """Derive a deterministic NUMS generator (33 bytes) for a token UID."""
    if _lib is None:
        raise RuntimeError('hathor_ct_crypto native library is not available')
    return _lib.derive_asset_tag(token_uid)


def htr_asset_tag() -> bytes:
    """Return the HTR asset tag (token_uid = all zeros, 33 bytes)."""
    if _lib is None:
        raise RuntimeError('hathor_ct_crypto native library is not available')
    return _lib.htr_asset_tag()


def derive_tag(token_uid: bytes) -> bytes:
    """Derive a raw Tag (32 bytes) from token UID for surjection proofs."""
    if _lib is None:
        raise RuntimeError('hathor_ct_crypto native library is not available')
    return _lib.derive_tag(token_uid)


def create_asset_commitment(tag_bytes: bytes, r_asset: bytes) -> bytes:
    """Create a blinded asset commitment (Generator, 33 bytes) from a raw Tag and blinding factor."""
    if _lib is None:
        raise RuntimeError('hathor_ct_crypto native library is not available')
    return _lib.create_asset_commitment(tag_bytes, r_asset)
