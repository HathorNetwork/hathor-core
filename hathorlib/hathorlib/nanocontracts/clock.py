# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import Protocol


class ClockProtocol(Protocol):
    """A minimal protocol for getting the current time. Used by NCLogger."""
    def seconds(self) -> float: ...
