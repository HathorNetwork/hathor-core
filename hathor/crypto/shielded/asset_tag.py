"""NUMS asset tag derivation wrapping the native Rust library."""

from hathor.crypto.shielded._bindings import _lib

_CRYPTO_TOKEN_UID_SIZE = 32


def _normalize_token_uid(token_uid: bytes) -> bytes:
    """Normalize a token UID to 32 bytes for the crypto library.

    Hathor uses b'\\x00' (1 byte) for HTR and 32-byte hashes for custom tokens.
    The crypto library always expects 32-byte token UIDs.
    """
    if len(token_uid) == _CRYPTO_TOKEN_UID_SIZE:
        return token_uid
    if len(token_uid) == 1:
        return token_uid.ljust(_CRYPTO_TOKEN_UID_SIZE, b'\x00')
    raise ValueError(
        f'invalid token UID length: expected 1 or {_CRYPTO_TOKEN_UID_SIZE} bytes, got {len(token_uid)}'
    )


def derive_asset_tag(token_uid: bytes) -> bytes:
    """Derive a deterministic NUMS generator (33 bytes) for a token UID.

    Accepts both 1-byte (HTR) and 32-byte token UIDs.
    """
    if _lib is None:
        raise RuntimeError('hathor_ct_crypto native library is not available')
    return _lib.derive_asset_tag(_normalize_token_uid(token_uid))


def htr_asset_tag() -> bytes:
    """Return the HTR asset tag (token_uid = all zeros, 33 bytes)."""
    if _lib is None:
        raise RuntimeError('hathor_ct_crypto native library is not available')
    return _lib.htr_asset_tag()


def derive_tag(token_uid: bytes) -> bytes:
    """Derive a raw Tag (32 bytes) from token UID for surjection proofs.

    Accepts both 1-byte (HTR) and 32-byte token UIDs.
    """
    if _lib is None:
        raise RuntimeError('hathor_ct_crypto native library is not available')
    return _lib.derive_tag(_normalize_token_uid(token_uid))


def create_asset_commitment(tag_bytes: bytes, r_asset: bytes) -> bytes:
    """Create a blinded asset commitment (Generator, 33 bytes) from a raw Tag and blinding factor."""
    if _lib is None:
        raise RuntimeError('hathor_ct_crypto native library is not available')
    return _lib.create_asset_commitment(tag_bytes, r_asset)
