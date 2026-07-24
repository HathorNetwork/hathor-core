#  SPDX-FileCopyrightText: Hathor Labs
#  SPDX-License-Identifier: Apache-2.0

from enum import StrEnum, auto, unique
from functools import lru_cache
from typing import Annotated, TypeAlias

from htr_lib import UnsignedAmount
from pydantic import BeforeValidator

from hathorlib.conf.utils import parse_hex_str
from hathorlib.utils.pydantic import BaseModel


@unique
class FeePolicyVersion(StrEnum):
    """The version of the fee policy, activated through feature activation."""
    V1 = auto()
    V2 = auto()


class FeePolicy(BaseModel):
    """The fee policy for a single token, that is, the fee amounts charged when paying with that token."""
    deposit_address: str | None
    fee_based_tokens: str
    amount_shielded: str
    full_shielded: str

    @lru_cache
    def get_fee_based_tokens(self) -> UnsignedAmount:
        return UnsignedAmount.parse(self.fee_based_tokens)

    @lru_cache
    def get_amount_shielded(self) -> UnsignedAmount:
        return UnsignedAmount.parse(self.amount_shielded)

    @lru_cache
    def get_full_shielded(self) -> UnsignedAmount:
        return UnsignedAmount.parse(self.full_shielded)


FeePolicyPerToken: TypeAlias = dict[Annotated[bytes, BeforeValidator(parse_hex_str)], FeePolicy]
