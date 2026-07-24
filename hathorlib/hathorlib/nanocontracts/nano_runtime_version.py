# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from enum import IntEnum

from typing_extensions import assert_never

from hathorlib.conf.fee_policy import FeePolicyVersion


class NanoRuntimeVersion(IntEnum):
    """
    The runtime version of Nano Contracts.
    It must be updated via Feature Activation and can be used to add new syscalls, for example.

    V1:
      - Initial version

    V2:
      - Added `get_settings` syscall

    V3:
      - Change fee policy version from V1 to V2
    """
    V1 = 1
    V2 = 2
    V3 = 3

    def get_fee_policy_version(self) -> FeePolicyVersion:
        """Get the fee policy version used in the respective nano runtime."""
        match self:
            case NanoRuntimeVersion.V1 | NanoRuntimeVersion.V2:
                return FeePolicyVersion.V1
            case NanoRuntimeVersion.V3:
                return FeePolicyVersion.V2
            case _:
                assert_never(self)
