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

# mypy: disable-error-code="attr-defined"

"""Sandbox execution counters for nano contracts."""

from __future__ import annotations

import sys
from dataclasses import dataclass

from typing_extensions import Self


@dataclass(frozen=True, slots=True)
class SandboxCounts:
    """Immutable container for sandbox execution counters.

    This dataclass holds the execution counters captured from the CPython sandbox.
    Being frozen ensures thread-safety and prevents accidental modifications.

    Attributes:
        operation_count: Number of bytecode operations executed.
        iteration_count: Number of loop/builtin iterations.
    """

    operation_count: int = 0
    iteration_count: int = 0

    @classmethod
    def from_dict(cls, counts: dict[str, int]) -> Self:
        """Create from a dict (e.g., sys.sandbox.get_counts())."""
        return cls(
            operation_count=counts.get('operation_count', 0),
            iteration_count=counts.get('iteration_count', 0),
        )

    @classmethod
    def capture(cls) -> Self:
        """Capture current sandbox counts.

        Returns zero counts if sandbox is not available.
        """
        from hathor.nanocontracts.sandbox.constants import SANDBOX_AVAILABLE
        if not SANDBOX_AVAILABLE:
            return cls()
        return cls.from_dict(dict(sys.sandbox.get_counts()))

    def to_dict(self) -> dict[str, int]:
        """Convert to dict for sys.sandbox.add_counts(**counts)."""
        return {'operation_count': self.operation_count, 'iteration_count': self.iteration_count}

    def __sub__(self, other: 'SandboxCounts') -> 'SandboxCounts':
        """Calculate delta between two counts."""
        return SandboxCounts(
            operation_count=self.operation_count - other.operation_count,
            iteration_count=self.iteration_count - other.iteration_count,
        )

    def __bool__(self) -> bool:
        """True if any counter is non-zero."""
        return self.operation_count != 0 or self.iteration_count != 0


@dataclass(slots=True)
class SandboxCounters:
    """Tracks sandbox operation counters for a single call between contracts.

    This is a mutable container used within the frozen CallRecord to store
    sandbox metrics before and after each call execution.

    Usage:
        counters = SandboxCounters()
        counters.capture_before()
        # ... execute call ...
        counters.capture_after()
        print(counters.delta)  # SandboxCounts(operation_count=1234, ...)
    """

    # Counters captured before the call execution
    before: SandboxCounts | None = None

    # Counters captured after the call execution
    after: SandboxCounts | None = None

    def capture_before(self) -> None:
        """Capture sandbox counters before call execution.

        Raises:
            AssertionError: If before counters were already captured.
        """
        assert self.before is None, "before counters already captured"
        self.before = SandboxCounts.capture()

    def capture_after(self) -> None:
        """Capture sandbox counters after call execution.

        Raises:
            AssertionError: If before counters were not captured first.
            AssertionError: If after counters were already captured.
        """
        assert self.before is not None, "must call capture_before() first"
        assert self.after is None, "after counters already captured"
        self.after = SandboxCounts.capture()

    @property
    def delta(self) -> SandboxCounts:
        """Calculate the difference between after and before counters.

        Returns:
            Zero SandboxCounts if counters are incomplete, otherwise the delta.
        """
        if self.before is None or self.after is None:
            return SandboxCounts()
        return self.after - self.before
