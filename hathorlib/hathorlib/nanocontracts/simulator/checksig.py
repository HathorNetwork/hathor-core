# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Simulated checksig backend for testing SignedData in the NanoSimulator."""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# Sentinel values for use as script_input when constructing SignedData.
# Use CHECKSIG_VALID to make checksig() return True, CHECKSIG_INVALID to make it return False.
CHECKSIG_VALID: bytes = b'__checksig_valid__'
CHECKSIG_INVALID: bytes = b'__checksig_invalid__'


def simulated_checksig_backend(sighash_all_data: bytes, script_input: bytes, script: bytes) -> bool:
    """Simulated checksig backend that uses sentinel values instead of real cryptography.

    - script_input == CHECKSIG_VALID  → True
    - script_input == CHECKSIG_INVALID → False
    - anything else → False + warning log
    """
    if script_input == CHECKSIG_VALID:
        return True
    if script_input == CHECKSIG_INVALID:
        return False
    logger.warning(
        'Simulated checksig received unrecognized script_input %r. '
        'Use CHECKSIG_VALID or CHECKSIG_INVALID as the script_input, '
        'or provide a custom backend via with_simulated_checksig() or checksig_backend().',
        script_input,
    )
    return False
