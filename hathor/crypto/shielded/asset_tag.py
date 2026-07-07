# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Token UID normalization for the shielded crypto library."""

from hathorlib.conf.settings import HATHOR_TOKEN_UID

_CRYPTO_TOKEN_UID_SIZE = 32


def normalize_token_uid(token_uid: bytes) -> bytes:
    """Normalize a token UID to 32 bytes for the crypto library.

    Hathor uses b'\\x00' (1 byte) for HTR and 32-byte hashes for custom tokens.
    The crypto library always expects 32-byte token UIDs.
    """
    if token_uid == HATHOR_TOKEN_UID:
        token_uid = b'\x00' * _CRYPTO_TOKEN_UID_SIZE
    assert len(token_uid) == _CRYPTO_TOKEN_UID_SIZE
    return token_uid
