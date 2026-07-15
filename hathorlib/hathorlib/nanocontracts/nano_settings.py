# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Self

from htr_lib import UnsignedAmount
from typing_extensions import assert_never

from hathorlib.conf.fee_policy import FeePolicy as SettingsFeePolicy
from hathorlib.conf.settings import HathorSettings
from hathorlib.token_amount_version import TokenAmountVersion

if TYPE_CHECKING:
    from hathorlib.nanocontracts import NanoRuntimeVersion
    from hathorlib.nanocontracts.types import TokenUid


@dataclass(slots=True, frozen=True, kw_only=True)
class FeePolicy:
    deposit_address: str | None
    fee_based_tokens: int
    amount_shielded: int
    full_shielded: int

    @classmethod
    def __from_settings__(cls, fee_policy: SettingsFeePolicy, token_amount_version: TokenAmountVersion) -> Self:
        def denormalize(amount: UnsignedAmount) -> int:
            return amount.to_version(token_amount_version).raw()

        return cls(
            deposit_address=fee_policy.deposit_address,
            fee_based_tokens=denormalize(fee_policy.get_fee_based_tokens()),
            amount_shielded=denormalize(fee_policy.get_amount_shielded()),
            full_shielded=denormalize(fee_policy.get_full_shielded()),
        )


@dataclass(slots=True, frozen=True, kw_only=True)
class NanoSettings:
    """
    This dataclass contains information about the settings used by the current Nano runtime.
    It is returned by the `get_settings` syscall. Note that settings are not constant, they may change over time.
    """
    fee_policies: dict[TokenUid, FeePolicy]

    @classmethod
    def __from_settings__(
        cls,
        *,
        settings: HathorSettings,
        runtime_version: NanoRuntimeVersion,
        token_amount_version: TokenAmountVersion,
    ) -> Self:
        from hathorlib.nanocontracts import NanoRuntimeVersion, NCFail
        from hathorlib.nanocontracts.types import TokenUid
        match runtime_version:
            case NanoRuntimeVersion.V1:
                raise NCFail('syscall `get_settings` is not yet supported')
            case NanoRuntimeVersion.V2 | NanoRuntimeVersion.V3:
                fee_policy_version = runtime_version.get_fee_policy_version()
                fee_policy_per_token = settings.get_fee_policies(fee_policy_version)
                fee_policies = {
                    TokenUid(token_uid): FeePolicy.__from_settings__(fee_policy, token_amount_version)
                    for token_uid, fee_policy in fee_policy_per_token.items()
                }
                return cls(
                    fee_policies=fee_policies,
                )
            case _:
                assert_never(runtime_version)
