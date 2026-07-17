# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from dataclasses import dataclass


@dataclass(slots=True, frozen=True, kw_only=True)
class NanoSettings:
    """
    This dataclass contains information about the settings used by the current Nano runtime.
    It is returned by the `get_settings` syscall. Note that settings are not constant, they may change over time.
    """
    fee_per_output: int
