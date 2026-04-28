# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Helpers for parsing hex-encoded bytes from user input."""

from __future__ import annotations

HASH32_HEX_LEN = 64


def parse_hash32(value: str) -> bytes:
    """Parse a hex-encoded 32-byte hash (64 hex characters) into bytes.

    Raises ValueError if the input is not exactly 64 hex characters.
    """
    if len(value) != HASH32_HEX_LEN:
        raise ValueError(
            f'expected {HASH32_HEX_LEN} hex characters, got {len(value)}'
        )
    # bytes.fromhex ignores ASCII whitespace, so a 64-char string with
    # embedded spaces would decode to fewer than 32 bytes and pass the
    # length check. Validate the decoded length to reject such inputs.
    result = bytes.fromhex(value)
    if len(result) != HASH32_HEX_LEN // 2:
        raise ValueError('hash must be 64 hex characters with no whitespace')
    return result
