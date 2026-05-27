"""Token UID normalization for the shielded crypto library."""

_CRYPTO_TOKEN_UID_SIZE = 32


def normalize_token_uid(token_uid: bytes) -> bytes:
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
