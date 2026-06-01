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

from __future__ import annotations

from dataclasses import dataclass

EXCESS_BLINDING_FACTOR_SIZE = 32


@dataclass(frozen=True, slots=True)
class UnshieldBalanceHeader:
    """Carries the excess blinding factor for a full-unshield tx.

    A tx that spends shielded inputs into transparent-only outputs needs to
    reveal `excess = sum(r_in) - sum(r_out)` so the Pedersen balance equation
    sum(C_in) = sum(C_out) + excess*G can hold. Mutually exclusive with
    ShieldedOutputsHeader: present only when the tx has no shielded outputs.
    The mutual-exclusion invariant is enforced at verification time.

    Privacy: with exactly one shielded input the scalar is effectively r_in
    of that input, but the transparent outputs of a full unshield already
    expose the spent amount, so nothing previously-private is additionally
    leaked. With two or more shielded inputs only the sum of their blinding
    factors is revealed; individual input amounts remain confidential.
    """

    excess_blinding_factor: bytes

    def __post_init__(self) -> None:
        if len(self.excess_blinding_factor) != EXCESS_BLINDING_FACTOR_SIZE:
            raise ValueError(
                f'excess_blinding_factor must be {EXCESS_BLINDING_FACTOR_SIZE} bytes, '
                f'got {len(self.excess_blinding_factor)}'
            )
