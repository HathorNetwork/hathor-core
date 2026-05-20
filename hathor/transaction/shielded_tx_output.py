# Copyright 2024 Hathor Labs
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

"""Shielded transaction output models and serialization.

Canonical definitions live in hathorlib; this module re-exports them
for backward compatibility.
"""

# Re-export canonical definitions from hathorlib
from hathorlib.transaction.shielded_tx_output import (  # noqa: F401
    ASSET_COMMITMENT_SIZE,
    COMMITMENT_SIZE,
    EPHEMERAL_PUBKEY_SIZE,
    MAX_RANGE_PROOF_SIZE,
    MAX_SHIELDED_OUTPUT_SCRIPT_SIZE,
    MAX_SHIELDED_OUTPUTS,
    MAX_SURJECTION_PROOF_SIZE,
    AmountShieldedOutput,
    FullShieldedOutput,
    OutputMode,
    ShieldedOutput,
    ShieldedOutputSecrets,
    deserialize_shielded_output,
    get_sighash_bytes,
    serialize_shielded_output,
)
