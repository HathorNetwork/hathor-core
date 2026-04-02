# Copyright 2026 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Simulated checksig backend for testing SignedData in the Simulator."""

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
