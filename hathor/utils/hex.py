#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

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
