# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import pytest

from hathorlib.conf import HathorSettings as get_settings
from hathorlib.conf.fee_policy import FeePolicy, FeePolicyVersion
from hathorlib.conf.settings import HATHOR_TOKEN_UID, HathorSettings
from hathorlib.exceptions import InvalidFeePaymentToken
from hathorlib.nanocontracts.runner.token_fees import aggregate_fee_charges
from hathorlib.token_amount import UnsignedAmount
from hathorlib.token_info import TokenVersion

DEPOSIT_TOKEN = b'\x01' * 32
FEE_TOKEN = b'\x02' * 32

settings = get_settings()


def test_get_fee_charge_without_fees() -> None:
    """A tx without fees pays nothing, and HTR is reported as the paying token."""
    fee_charge = aggregate_fee_charges(settings=settings, fee_policy_version=FeePolicyVersion.V1, charges=[])
    assert fee_charge.token_uid == HATHOR_TOKEN_UID
    assert fee_charge.policy == settings.get_htr_policy(FeePolicyVersion.V1)
    assert fee_charge.amount == UnsignedAmount.zero()


def test_get_fee_charge_in_htr() -> None:
    fee_charge = aggregate_fee_charges(
        settings=settings,
        fee_policy_version=FeePolicyVersion.V1,
        charges=[(HATHOR_TOKEN_UID, TokenVersion.NATIVE, UnsignedAmount.from_v1(100))],
    )
    assert fee_charge.token_uid == HATHOR_TOKEN_UID
    assert fee_charge.amount == UnsignedAmount.from_v1(100)


def test_get_fee_charge_converts_deposit_token_to_htr() -> None:
    """A deposit-based token has no policy of its own, so its amount is withdrawn as HTR."""
    fee_charge = aggregate_fee_charges(
        settings=settings,
        fee_policy_version=FeePolicyVersion.V1,
        charges=[(DEPOSIT_TOKEN, TokenVersion.DEPOSIT, UnsignedAmount.from_v1(1000))],
    )
    assert fee_charge.token_uid == HATHOR_TOKEN_UID
    # The deposit percentage is 1%, so melting 10.00 of the token withdraws 0.10 HTR.
    assert fee_charge.amount == UnsignedAmount.from_v1(10)


def test_get_fee_charge_sums_htr_and_deposit_token() -> None:
    fee_charge = aggregate_fee_charges(
        settings=settings,
        fee_policy_version=FeePolicyVersion.V1,
        charges=[
            (HATHOR_TOKEN_UID, TokenVersion.NATIVE, UnsignedAmount.from_v1(5)),
            (DEPOSIT_TOKEN, TokenVersion.DEPOSIT, UnsignedAmount.from_v1(1000)),
        ],
    )
    assert fee_charge.token_uid == HATHOR_TOKEN_UID
    assert fee_charge.amount == UnsignedAmount.from_v1(15)


def test_get_fee_charge_sums_entries_of_the_same_token() -> None:
    fee_charge = aggregate_fee_charges(
        settings=settings,
        fee_policy_version=FeePolicyVersion.V1,
        charges=[
            (HATHOR_TOKEN_UID, TokenVersion.NATIVE, UnsignedAmount.from_v1(5)),
            (HATHOR_TOKEN_UID, TokenVersion.NATIVE, UnsignedAmount.from_v1(7)),
        ],
    )
    assert fee_charge.token_uid == HATHOR_TOKEN_UID
    assert fee_charge.amount == UnsignedAmount.from_v1(12)


def test_get_fee_charge_rejects_fee_based_token_without_policy() -> None:
    msg = f'cannot pay fees with token {FEE_TOKEN.hex()}'
    with pytest.raises(InvalidFeePaymentToken) as e:
        aggregate_fee_charges(
            settings=settings,
            fee_policy_version=FeePolicyVersion.V1,
            charges=[(FEE_TOKEN, TokenVersion.FEE, UnsignedAmount.from_v1(1))],
        )
    assert str(e.value) == msg


def test_get_fee_charge_with_two_policy_tokens() -> None:
    """Fees must all be payable by a single token, so two tokens with policies of their own is an error."""
    custom_settings = HathorSettings(
        P2PKH_VERSION_BYTE=b'\x28',
        MULTISIG_VERSION_BYTE=b'\x64',
        NETWORK_NAME='testing',
        FEE_POLICIES={
            FeePolicyVersion.V1: {
                HATHOR_TOKEN_UID: FeePolicy(
                    deposit_address=None,
                    fee_based_tokens='0.01',
                    amount_shielded='0.01',
                    full_shielded='0.02',
                ),
                FEE_TOKEN: FeePolicy(
                    deposit_address=None,
                    fee_based_tokens='0.005',
                    amount_shielded='0.01',
                    full_shielded='0.02',
                ),
            },
        },
    )

    # A token with a policy of its own pays in itself, even if it's fee-based.
    fee_charge = aggregate_fee_charges(
        settings=custom_settings,
        fee_policy_version=FeePolicyVersion.V1,
        charges=[(FEE_TOKEN, TokenVersion.FEE, UnsignedAmount.from_v1(3))],
    )
    assert fee_charge.token_uid == FEE_TOKEN
    assert fee_charge.policy == custom_settings.get_fee_policies(FeePolicyVersion.V1)[FEE_TOKEN]
    assert fee_charge.amount == UnsignedAmount.from_v1(3)

    msg = 'fee payments must either use a combination of HTR and deposit-based tokens, or a single stablecoin'
    with pytest.raises(InvalidFeePaymentToken) as e:
        aggregate_fee_charges(
            settings=custom_settings,
            fee_policy_version=FeePolicyVersion.V1,
            charges=[
                (HATHOR_TOKEN_UID, TokenVersion.NATIVE, UnsignedAmount.from_v1(1)),
                (FEE_TOKEN, TokenVersion.FEE, UnsignedAmount.from_v1(1)),
            ],
        )
    assert str(e.value) == msg
