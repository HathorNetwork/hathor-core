# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass
from typing import Protocol

from hathor.transaction import Block, Transaction


@dataclass(slots=True, frozen=True, kw_only=True)
class SortedTransactions:
    sorted: tuple[Transaction, ...]
    cyclic: tuple[Transaction, ...]


class NCSorterCallable(Protocol):
    def __call__(self, block: Block, nc_calls: list[Transaction]) -> SortedTransactions:
        """
        Return the sorted execution order plus any transactions that must fail due to cyclic dependencies.

        `SortedTransactions.cyclic` is empty in the normal case. A non-empty tuple means the sorter
        detected a cycle in the dependency graph; the caller must mark those transactions as failed
        NC executions and skip executing them.
        """
        ...
