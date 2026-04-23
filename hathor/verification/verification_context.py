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

from dataclasses import dataclass, field

from hathor.transaction.exceptions import VerificationChecksMissingError
from hathor.verification.verification_check import VerificationCheck


@dataclass(frozen=True)
class RequiredChecks:
    """The set of VerificationCheck flags that MUST be recorded for a vertex.

    all_of: every flag must be recorded (bit-AND semantics).
    any_of_groups: each group is a flag mask; at least one bit from each group
      must be recorded. Used for invariants like "BALANCE or BALANCE_POSTPONED"
      where either satisfies the verify-time requirement.
    """
    all_of: VerificationCheck = VerificationCheck(0)
    any_of_groups: tuple[VerificationCheck, ...] = ()

    def __or__(self, other: 'RequiredChecks') -> 'RequiredChecks':
        return RequiredChecks(
            all_of=self.all_of | other.all_of,
            any_of_groups=self.any_of_groups + other.any_of_groups,
        )


@dataclass
class VerificationContext:
    """Travels through the verification pipeline collecting check flags.

    Each verify_* call in the dispatcher is followed by ctx.record(flag).
    At the end of each stage, ctx.check(required, stage=...) asserts the
    recorded set covers the required set for the vertex's shape. Missing
    flags raise VerificationChecksMissingError — a loud failure, not silent.
    """
    vertex_hash: bytes = b''
    checks_run: VerificationCheck = field(default_factory=lambda: VerificationCheck(0))

    def record(self, check: VerificationCheck) -> None:
        self.checks_run |= check

    def has(self, check: VerificationCheck) -> bool:
        return bool(self.checks_run & check)

    def check(self, required: RequiredChecks, *, stage: str) -> None:
        missing_all = required.all_of & ~self.checks_run
        missing_any = tuple(g for g in required.any_of_groups if not (self.checks_run & g))
        if missing_all or missing_any:
            raise VerificationChecksMissingError(
                f'vertex {self.vertex_hash.hex()} stage={stage}: '
                f'missing_all={missing_all!r}, missing_any_groups={missing_any!r}'
            )
