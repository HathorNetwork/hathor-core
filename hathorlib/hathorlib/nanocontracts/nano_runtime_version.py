# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from enum import IntEnum


class NanoRuntimeVersion(IntEnum):
    """
    The runtime version of Nano Contracts.
    It must be updated via Feature Activation and can be used to add new syscalls, for example.

    V1:
      - Initial version

    V2:
      - Added `get_settings` syscall
    """
    V1 = 1
    V2 = 2
