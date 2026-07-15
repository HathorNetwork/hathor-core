# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Tests for the stablecoin fee policy invariants.

Every test pins one invariant introduced by the fee-policy work: versioned `FEE_POLICIES` settings,
`aggregate_fee_charges` semantics, deposit-address fee payment in the transparent
verification path, per-token fee pricing, and the nano runner's actions-fee validation.
"""

import base58
import pytest
from pydantic import ValidationError

from hathor.crypto.util import decode_address
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.feature_activation.utils import Features
from hathor.nanocontracts import NC_EXECUTION_FAIL_ID
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCFail, NCInvalidFee
from hathor.nanocontracts.nc_exec_logs import NCLogConfig
from hathor.nanocontracts.storage.contract_storage import Balance
from hathor.nanocontracts.types import (
    BlueprintId,
    ContractId,
    NCActionType,
    NCDepositAction,
    NCFee,
    TokenUid,
    public,
)
from hathor.nanocontracts.utils import derive_child_token_id
from hathor.transaction import Block, Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import InputOutputMismatch, InvalidToken
from hathor.transaction.headers import FeeHeader
from hathor.transaction.headers.fee_header import FeeHeaderEntry
from hathor.transaction.headers.nano_header import NanoHeaderAction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor.transaction.scripts import P2PKH
from hathor.transaction.token_info import TokenInfoDict, TokenVersion
from hathor.verification.transaction_verifier import TransactionVerifier
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathor_tests.nanocontracts.utils import TestRunner, assert_nc_failure_reason
from hathor_tests.token_amount import SignedAmount, UnsignedAmount
from hathor_tests.unittest import TestCase
from hathor_tests.utils import add_blocks_unlock_reward, create_fee_tokens
from hathorlib.conf.fee_policy import FeePolicy, FeePolicyVersion
from hathorlib.conf.settings import HATHOR_TOKEN_UID, FeatureSetting
from hathorlib.exceptions import InvalidFeePaymentToken
from hathorlib.nanocontracts import NanoRuntimeVersion
from hathorlib.nanocontracts.nano_settings import FeePolicy as NanoFeePolicy, NanoSettings
from hathorlib.nanocontracts.runner.token_fees import FeeCharge, aggregate_fee_charges
from hathorlib.token_amount_version import TokenAmountVersion
from hathorlib.utils.address import get_checksum

# A valid mainnet-format address (same P2PKH version byte as the unittests network).
BURN_ADDRESS = 'HDeadDeadDeadDeadDeadDeadDeagTPgmn'


def _policy(
    *,
    deposit_address: str | None = None,
    fee_based_tokens: str = '0.01',
    amount_shielded: str = '0.01',
    full_shielded: str = '0.02',
) -> FeePolicy:
    """Build a `FeePolicy` with defaults matching the standard V1 HTR policy."""
    return FeePolicy(
        deposit_address=deposit_address,
        fee_based_tokens=fee_based_tokens,
        amount_shielded=amount_shielded,
        full_shielded=full_shielded,
    )


class TestFeePolicySettings(TestCase):
    """Invariants on the `FEE_POLICIES` settings structure itself."""

    def _rebuild_settings(self, fee_policies: dict[FeePolicyVersion, dict[bytes, FeePolicy]]) -> None:
        """Reconstruct the test settings with `FEE_POLICIES` replaced, re-running all model validators."""
        type(self._settings)(**{**self._settings.model_dump(), 'FEE_POLICIES': fee_policies})

    @staticmethod
    def _assert_single_error(exc_info: pytest.ExceptionInfo[ValidationError], expected_msg: str) -> None:
        """Assert a `ValidationError` carries exactly one error with the expected message."""
        errors = exc_info.value.errors()
        assert len(errors) == 1
        assert errors[0]['msg'] == f'Value error, {expected_msg}'

    def test_every_fee_policy_version_defines_htr(self) -> None:
        """Every version in `FEE_POLICIES` must define a policy for HTR (`b'\\x00'`).

        `aggregate_fee_charges` and `_calculate_unit_fee_token_fee` unconditionally index
        `fee_policies[HATHOR_TOKEN_UID]`, so a version map without an HTR entry crashes
        consensus paths with a `KeyError` instead of failing validation.
        """
        stablecoin_uid = b'\xaa' * 32
        with pytest.raises(ValidationError) as e:
            self._rebuild_settings({
                FeePolicyVersion.V1: {HATHOR_TOKEN_UID: _policy()},
                FeePolicyVersion.V2: {stablecoin_uid: _policy(deposit_address=BURN_ADDRESS)},
            })
        self._assert_single_error(e, 'HTR policy must be defined in fee policy version v2')

    def test_fee_policy_v1_always_present(self) -> None:
        """`FEE_POLICIES` must always contain `FeePolicyVersion.V1`.

        Verification defaults to V1 before feature activation, on every network,
        so a settings object without a V1 entry is invalid.
        """
        with pytest.raises(ValidationError) as e:
            self._rebuild_settings({
                FeePolicyVersion.V2: {HATHOR_TOKEN_UID: _policy()},
            })
        self._assert_single_error(e, 'FEE_POLICIES must define the V1 policy')

    def test_fee_policy_deposit_address_is_valid_for_network(self) -> None:
        """A non-null `deposit_address` must be a valid base58 address for the network.

        The deposit check compares parsed output addresses against this string; an invalid
        or wrong-network address would silently make every stablecoin fee payment unverifiable.
        """
        stablecoin_uid = b'\xaa' * 32

        def fee_policies(deposit_address: str) -> dict[FeePolicyVersion, dict[bytes, FeePolicy]]:
            return {
                FeePolicyVersion.V1: {
                    HATHOR_TOKEN_UID: _policy(),
                    stablecoin_uid: _policy(deposit_address=deposit_address),
                },
            }

        with pytest.raises(ValidationError) as e:
            self._rebuild_settings(fee_policies('not-a-base58-address'))
        self._assert_single_error(
            e,
            f"invalid deposit address 'not-a-base58-address' for token {stablecoin_uid.hex()} "
            f'in fee policy version v1: Invalid base58 address'
        )

        # A structurally valid address with a version byte from another network is rejected.
        payload = b'\x00' + b'\x11' * 20
        wrong_network_address = base58.b58encode(payload + get_checksum(payload)).decode()
        with pytest.raises(ValidationError) as e:
            self._rebuild_settings(fee_policies(wrong_network_address))
        self._assert_single_error(
            e,
            f'deposit address {wrong_network_address!r} for token {stablecoin_uid.hex()} '
            f'in fee policy version v1 is not valid for network {self._settings.NETWORK_NAME}'
        )

        # A valid address for this network is accepted.
        self._rebuild_settings(fee_policies(BURN_ADDRESS))

    def test_htr_policy_must_not_define_deposit_address(self) -> None:
        """A settings object whose HTR policy defines a `deposit_address` is rejected at load time.

        The transaction fee path burns HTR-denominated fees unconditionally, so an HTR deposit
        address would be silently ignored; the validator forbids it instead.
        """
        with pytest.raises(ValidationError) as e:
            self._rebuild_settings({
                FeePolicyVersion.V1: {HATHOR_TOKEN_UID: _policy(deposit_address=BURN_ADDRESS)},
            })
        self._assert_single_error(e, 'HTR policy must not define a deposit address')

    def test_get_fee_policies_unknown_version_raises(self) -> None:
        """`HathorSettings.get_fee_policies` raises `ValueError` for a version absent from `FEE_POLICIES`."""
        assert set(self._settings.FEE_POLICIES.keys()) == {FeePolicyVersion.V1, FeePolicyVersion.V2}
        with pytest.raises(ValueError) as e:
            self._settings.get_fee_policies('v3')  # type: ignore[arg-type]
        assert str(e.value) == 'No policy configured for version v3'


class TestGetFeeCharge(TestCase):
    """Invariants of `hathorlib.nanocontracts.runner.token_fees.aggregate_fee_charges`."""

    def setUp(self) -> None:
        super().setUp()
        self.stablecoin_uid = b'\xaa' * 32
        self.other_stablecoin_uid = b'\xab' * 32
        self.deposit_token_uid = b'\xba' * 32
        self.fee_token_uid = b'\xbb' * 32

        self.htr_policy = self._settings.FEE_POLICIES[FeePolicyVersion.V1][HATHOR_TOKEN_UID]
        self.stablecoin_policy = _policy(deposit_address=BURN_ADDRESS, fee_based_tokens='0.005')
        self.other_stablecoin_policy = _policy(deposit_address=BURN_ADDRESS, fee_based_tokens='0.05')
        self.settings = self._settings.model_copy(update={'FEE_POLICIES': {
            FeePolicyVersion.V1: {
                HATHOR_TOKEN_UID: self.htr_policy,
                self.stablecoin_uid: self.stablecoin_policy,
                self.other_stablecoin_uid: self.other_stablecoin_policy,
            },
        }})

    def _get_fee_charge(self, charges: list[tuple[bytes, TokenVersion, UnsignedAmount]]) -> FeeCharge:
        """Call `aggregate_fee_charges` with the test settings and the V1 fee policy version."""
        return aggregate_fee_charges(settings=self.settings, fee_policy_version=FeePolicyVersion.V1, charges=charges)

    def test_htr_only_fees(self) -> None:
        """Fees paid only in HTR return a `FeeCharge` of HTR, the HTR policy, and the sum of amounts."""
        charge = self._get_fee_charge([
            (HATHOR_TOKEN_UID, TokenVersion.NATIVE, UnsignedAmount.from_v1(1)),
            (HATHOR_TOKEN_UID, TokenVersion.NATIVE, UnsignedAmount.from_v1(2)),
        ])
        assert charge == FeeCharge(
            token_uid=HATHOR_TOKEN_UID, policy=self.htr_policy, amount=UnsignedAmount.from_v1(3)
        )

    def test_deposit_tokens_convert_to_htr(self) -> None:
        """Fees paid in non-policy deposit-based tokens are converted to HTR via the withdraw rate."""
        charge = self._get_fee_charge([
            (self.deposit_token_uid, TokenVersion.DEPOSIT, UnsignedAmount.from_v1(100)),
        ])
        # 100 deposit-token units withdraw to 1 HTR unit at the 1% deposit rate.
        assert charge == FeeCharge(
            token_uid=HATHOR_TOKEN_UID, policy=self.htr_policy, amount=UnsignedAmount.from_v1(1)
        )

    def test_htr_and_deposit_token_combination_allowed(self) -> None:
        """A combination of HTR and deposit-based tokens is a single HTR-denominated payment."""
        charge = self._get_fee_charge([
            (HATHOR_TOKEN_UID, TokenVersion.NATIVE, UnsignedAmount.from_v1(1)),
            (self.deposit_token_uid, TokenVersion.DEPOSIT, UnsignedAmount.from_v1(100)),
        ])
        assert charge == FeeCharge(
            token_uid=HATHOR_TOKEN_UID, policy=self.htr_policy, amount=UnsignedAmount.from_v1(2)
        )

    def test_single_stablecoin_allowed(self) -> None:
        """A fee paid with a single policy (stablecoin) token returns that token, its policy,
        and its own amount, with no conversion to HTR."""
        charge = self._get_fee_charge([
            (self.stablecoin_uid, TokenVersion.FEE, UnsignedAmount.from_v1(7)),
        ])
        assert charge == FeeCharge(
            token_uid=self.stablecoin_uid, policy=self.stablecoin_policy, amount=UnsignedAmount.from_v1(7)
        )

    def test_policy_token_charged_regardless_of_token_version(self) -> None:
        """A token listed in the active policy version is charged its own amount whether it is
        fee-based or deposit-based."""
        for token_version in (TokenVersion.FEE, TokenVersion.DEPOSIT):
            charge = self._get_fee_charge([
                (self.stablecoin_uid, token_version, UnsignedAmount.from_v1(100)),
            ])
            assert charge == FeeCharge(
                token_uid=self.stablecoin_uid, policy=self.stablecoin_policy, amount=UnsignedAmount.from_v1(100)
            )

    def test_non_policy_fee_based_token_rejected(self) -> None:
        """A fee-based token outside the policy raises `InvalidFeePaymentToken` naming the token."""
        with pytest.raises(InvalidFeePaymentToken) as e:
            self._get_fee_charge([
                (self.fee_token_uid, TokenVersion.FEE, UnsignedAmount.from_v1(100)),
            ])
        assert str(e.value) == f'cannot pay fees with token {self.fee_token_uid.hex()}'

    def test_policy_lookup_respects_version(self) -> None:
        """A token present only in the V2 policy is not payable while V1 is active, and vice versa."""
        v1_only_uid = self.other_stablecoin_uid
        v2_only_uid = self.stablecoin_uid
        settings = self._settings.model_copy(update={'FEE_POLICIES': {
            FeePolicyVersion.V1: {
                HATHOR_TOKEN_UID: self.htr_policy,
                v1_only_uid: self.other_stablecoin_policy,
            },
            FeePolicyVersion.V2: {
                HATHOR_TOKEN_UID: self.htr_policy,
                v2_only_uid: self.stablecoin_policy,
            },
        }})

        def charge(version: FeePolicyVersion, token_uid: bytes) -> FeeCharge:
            charges = [(token_uid, TokenVersion.FEE, UnsignedAmount.from_v1(100))]
            return aggregate_fee_charges(settings=settings, fee_policy_version=version, charges=charges)

        with pytest.raises(InvalidFeePaymentToken) as e:
            charge(FeePolicyVersion.V1, v2_only_uid)
        assert str(e.value) == f'cannot pay fees with token {v2_only_uid.hex()}'
        assert charge(FeePolicyVersion.V2, v2_only_uid).token_uid == v2_only_uid

        with pytest.raises(InvalidFeePaymentToken) as e:
            charge(FeePolicyVersion.V2, v1_only_uid)
        assert str(e.value) == f'cannot pay fees with token {v1_only_uid.hex()}'
        assert charge(FeePolicyVersion.V1, v1_only_uid).token_uid == v1_only_uid

    def test_stablecoin_plus_htr_rejected(self) -> None:
        """Mixing a policy token with HTR raises `InvalidFeePaymentToken`."""
        with pytest.raises(InvalidFeePaymentToken) as e:
            self._get_fee_charge([
                (self.stablecoin_uid, TokenVersion.FEE, UnsignedAmount.from_v1(100)),
                (HATHOR_TOKEN_UID, TokenVersion.NATIVE, UnsignedAmount.from_v1(1)),
            ])
        assert str(e.value) == (
            'fee payments must either use a combination of HTR and deposit-based tokens, or a single stablecoin'
        )

    def test_stablecoin_plus_deposit_token_rejected(self) -> None:
        """Mixing a policy token with a deposit-based token raises `InvalidFeePaymentToken`."""
        with pytest.raises(InvalidFeePaymentToken) as e:
            self._get_fee_charge([
                (self.stablecoin_uid, TokenVersion.FEE, UnsignedAmount.from_v1(100)),
                (self.deposit_token_uid, TokenVersion.DEPOSIT, UnsignedAmount.from_v1(100)),
            ])
        assert str(e.value) == (
            'fee payments must either use a combination of HTR and deposit-based tokens, or a single stablecoin'
        )

    def test_two_stablecoins_rejected(self) -> None:
        """Mixing two different policy tokens raises `InvalidFeePaymentToken`."""
        with pytest.raises(InvalidFeePaymentToken) as e:
            self._get_fee_charge([
                (self.stablecoin_uid, TokenVersion.FEE, UnsignedAmount.from_v1(100)),
                (self.other_stablecoin_uid, TokenVersion.FEE, UnsignedAmount.from_v1(100)),
            ])
        assert str(e.value) == (
            'fee payments must either use a combination of HTR and deposit-based tokens, or a single stablecoin'
        )

    def test_empty_fees_return_zero_htr(self) -> None:
        """An empty fee iterable returns a `FeeCharge` of HTR, the HTR policy, and a zero amount."""
        charge = self._get_fee_charge([])
        assert charge == FeeCharge(
            token_uid=HATHOR_TOKEN_UID, policy=self.htr_policy, amount=UnsignedAmount.zero()
        )

    def test_duplicate_entries_for_same_token_are_summed(self) -> None:
        """Multiple fee entries for the same token are summed, never last-one-wins."""
        charge = self._get_fee_charge([
            (self.stablecoin_uid, TokenVersion.FEE, UnsignedAmount.from_v1(1)),
            (self.stablecoin_uid, TokenVersion.FEE, UnsignedAmount.from_v1(2)),
        ])
        assert charge == FeeCharge(
            token_uid=self.stablecoin_uid, policy=self.stablecoin_policy, amount=UnsignedAmount.from_v1(3)
        )


class _CreateFeeTokenBlueprint(Blueprint):
    @public(allow_deposit=True)
    def initialize(self, ctx: Context) -> None:
        pass

    @public(allow_withdrawal=True)
    def create_fee_token(self, ctx: Context) -> None:
        self.syscall.create_fee_token(
            token_name='fee-based token',
            token_symbol='FBT',
            amount=10 ** 9,
        )


class TestFeeHeaderVerification(TestCase):
    """Invariants of `Transaction._update_token_info_from_fees` and `verify_transparent_balance`."""

    def setUp(self) -> None:
        super().setUp()
        self.manager = self.create_peer('testnet', unlock_wallet=True, wallet_index=True)
        self.address_b58 = self.manager.wallet.get_unused_address()
        self.address = decode_address(self.address_b58)
        self.deposit_address_b58 = self.manager.wallet.get_unused_address()
        self.script = P2PKH.create_output_script(self.address)
        self.deposit_script = P2PKH.create_output_script(decode_address(self.deposit_address_b58))
        add_blocks_unlock_reward(self.manager)

        # A fee-based token that plays the stablecoin role: 5.00 STB minted at output 0, and 1.00 HTR at output 4.
        self.stablecoin_tx = create_fee_tokens(
            self.manager,
            self.address_b58,
            mint_amount=500,
            token_name='StableCoin',
            token_symbol='STB',
            genesis_output_amount=100,
        )
        self.stablecoin_uid = self.stablecoin_tx.tokens[0]

        manager_settings = self.manager._settings
        self.htr_policy = manager_settings.FEE_POLICIES[FeePolicyVersion.V1][HATHOR_TOKEN_UID]
        self.stablecoin_policy = _policy(
            deposit_address=self.deposit_address_b58,
            fee_based_tokens='0.005',
        )
        self.custom_settings = manager_settings.model_copy(update={'FEE_POLICIES': {
            FeePolicyVersion.V1: {HATHOR_TOKEN_UID: self.htr_policy},
            FeePolicyVersion.V2: {
                HATHOR_TOKEN_UID: self.htr_policy,
                self.stablecoin_uid: self.stablecoin_policy,
            },
        }})

    def _build_tx(
        self,
        *,
        inputs: list[TxInput],
        outputs: list[TxOutput],
        fees: list[FeeHeaderEntry],
    ) -> Transaction:
        """Build a transaction carrying a fee header, with the stablecoin at token index 1."""
        tx = Transaction(
            weight=1,
            inputs=inputs,
            outputs=outputs,
            parents=self.manager.get_new_tx_parents(),
            tokens=[self.stablecoin_uid],
            storage=self.manager.tx_storage,
            timestamp=int(self.clock.seconds()),
            settings=self.custom_settings,
        )
        tx.headers.append(FeeHeader(settings=self.custom_settings, tx=tx, fees=fees))
        return tx

    def _build_stablecoin_tx(
        self,
        *,
        outputs: list[TxOutput],
        fee_amount: UnsignedAmount,
        extra_inputs: list[TxInput] | None = None,
    ) -> Transaction:
        """Build a transaction spending the 5.00 STB output and paying its fee in STB."""
        inputs = [TxInput(self.stablecoin_tx.hash, 0, b''), *(extra_inputs or [])]
        return self._build_tx(
            inputs=inputs,
            outputs=outputs,
            fees=[FeeHeaderEntry(token_index=1, amount=fee_amount)],
        )

    def _get_token_info(
        self,
        tx: Transaction,
        fee_policy_version: FeePolicyVersion = FeePolicyVersion.V2,
    ) -> TokenInfoDict:
        nc_storage = self.manager.get_nc_block_storage(self.manager.tx_storage.get_best_block())
        return tx.get_complete_token_info(nc_storage, fee_policy_version=fee_policy_version)

    def test_htr_fee_is_burned(self) -> None:
        """An HTR fee subtracts from the HTR balance (the fee is burned), preserving V1 behavior."""
        manager = self.create_peer('testnet', unlock_wallet=True, wallet_index=True)
        dag_builder = TestDAGBuilder.from_manager(manager)
        artifacts = dag_builder.build_from_str('''
            blockchain genesis b[1..11]
            b10 < dummy

            FBT.token_version = fee
            FBT.fee = 1 HTR

            tx1.out[0] = 123 FBT
            tx1.fee = 1 HTR
        ''')
        artifacts.propagate_with(manager)

        # 11 blocks minted rewards; the FBT creation fee and the tx1 fee (0.01 HTR each) were burned.
        settings = manager._settings
        expected_htr_total = (
            settings.GENESIS_TOKEN_ATOMIC_UNITS
            + 11 * settings.INITIAL_TOKEN_ATOMIC_UNITS_PER_BLOCK
            - 2
        )
        tokens_index = manager.tx_storage.indexes.tokens
        assert tokens_index.get_token_info(HATHOR_TOKEN_UID).get_total() == UnsignedAmount.from_v1(
            expected_htr_total
        )

    def test_stablecoin_fee_requires_deposit_output(self) -> None:
        """A stablecoin fee is valid only when outputs to the policy's deposit address
        cover at least the total header fee amount."""
        # Without any output to the deposit address, the fee (one chargeable output) is unpaid.
        tx = self._build_stablecoin_tx(
            outputs=[TxOutput(UnsignedAmount.from_v1(500), self.script, 1)],
            fee_amount=UnsignedAmount.parse('0.005'),
        )
        token_info = self._get_token_info(tx)
        with pytest.raises(InputOutputMismatch) as e:
            TransactionVerifier.verify_transparent_balance(self.custom_settings, tx, token_info)
        assert str(e.value) == (
            f'expected 0.005 of token {self.stablecoin_uid.hex()} '
            f'fee paid to {self.deposit_address_b58}, found 0.0'
        )

        # With a deposit-address output covering the fee, the transaction is fully valid.
        tx = self._build_stablecoin_tx(
            outputs=[
                TxOutput(UnsignedAmount.from_v1(1), self.deposit_script, 1),
                TxOutput(UnsignedAmount.from_v1(499), self.script, 1),
            ],
            fee_amount=UnsignedAmount.from_v1(1),
        )
        token_info = self._get_token_info(tx)
        TransactionVerifier.verify_transparent_balance(self.custom_settings, tx, token_info)

    def test_stablecoin_fee_is_not_burned(self) -> None:
        """A stablecoin fee does not subtract from the fee token's balance; the payment is the
        regular output to the deposit address, so total supply is preserved."""
        tx = self._build_stablecoin_tx(
            outputs=[
                TxOutput(UnsignedAmount.from_v1(1), self.deposit_script, 1),
                TxOutput(UnsignedAmount.from_v1(499), self.script, 1),
            ],
            fee_amount=UnsignedAmount.from_v1(1),
        )
        token_info = self._get_token_info(tx)
        assert token_info.header_fee == FeeCharge(
            token_uid=self.stablecoin_uid, policy=self.stablecoin_policy, amount=UnsignedAmount.from_v1(1)
        )
        # Outputs (deposit + change) equal the inputs exactly: the fee did not touch the balance.
        assert token_info[self.stablecoin_uid].amount == SignedAmount(0)
        TransactionVerifier.verify_transparent_balance(self.custom_settings, tx, token_info)

    def test_deposit_output_must_be_in_fee_token(self) -> None:
        """Only outputs denominated in the fee-paying token count toward the deposit address sum.

        An output of any other token (including HTR) sent to the deposit address must not
        satisfy a stablecoin fee, even if its face value covers the fee amount.
        """
        tx = self._build_stablecoin_tx(
            outputs=[
                # 1.00 HTR to the deposit address: covers the 0.005 fee at face value, but in the wrong token.
                TxOutput(UnsignedAmount.from_v1(100), self.deposit_script, 0),
                TxOutput(UnsignedAmount.from_v1(500), self.script, 1),
            ],
            fee_amount=UnsignedAmount.parse('0.005'),
            extra_inputs=[TxInput(self.stablecoin_tx.hash, 4, b'')],
        )
        token_info = self._get_token_info(tx)
        with pytest.raises(InputOutputMismatch) as e:
            TransactionVerifier.verify_transparent_balance(self.custom_settings, tx, token_info)
        assert str(e.value) == (
            f'expected 0.005 of token {self.stablecoin_uid.hex()} '
            f'fee paid to {self.deposit_address_b58}, found 0.0'
        )

    def test_authority_output_to_deposit_address_not_counted(self) -> None:
        """Authority outputs sent to the deposit address contribute nothing to the deposit sum;
        their `value` field is an authority mask, not an amount."""
        tx = self._build_stablecoin_tx(
            outputs=[
                TxOutput(UnsignedAmount.from_v1(TxOutput.TOKEN_MELT_MASK), self.deposit_script, 0b10000001),
                TxOutput(UnsignedAmount.from_v1(500), self.script, 1),
            ],
            fee_amount=UnsignedAmount.parse('0.005'),
            extra_inputs=[TxInput(self.stablecoin_tx.hash, 2, b'')],
        )
        token_info = self._get_token_info(tx)
        with pytest.raises(InputOutputMismatch) as e:
            TransactionVerifier.verify_transparent_balance(self.custom_settings, tx, token_info)
        assert str(e.value) == (
            f'expected 0.005 of token {self.stablecoin_uid.hex()} '
            f'fee paid to {self.deposit_address_b58}, found 0.0'
        )

    def test_insufficient_deposit_output_rejected(self) -> None:
        """A deposit-address output sum below the header fee amount raises `InputOutputMismatch`."""
        # Three chargeable outputs make a 0.015 fee, but only 0.01 is paid to the deposit address.
        tx = self._build_stablecoin_tx(
            outputs=[
                TxOutput(UnsignedAmount.from_v1(1), self.deposit_script, 1),
                TxOutput(UnsignedAmount.from_v1(1), self.script, 1),
                TxOutput(UnsignedAmount.from_v1(498), self.script, 1),
            ],
            fee_amount=UnsignedAmount.parse('0.015'),
        )
        token_info = self._get_token_info(tx)
        with pytest.raises(InputOutputMismatch) as e:
            TransactionVerifier.verify_transparent_balance(self.custom_settings, tx, token_info)
        assert str(e.value) == (
            f'expected 0.015 of token {self.stablecoin_uid.hex()} '
            f'fee paid to {self.deposit_address_b58}, found 0.01'
        )

    def test_timelocked_deposit_output_not_counted(self) -> None:
        """Timelocked outputs to the deposit address contribute nothing to the deposit sum.

        A timelocked output defers the deposit address's ability to spend it, so it does not
        count as fee payment, regardless of whether the timelock is in the past or the future.
        """
        now = int(self.clock.seconds())
        deposit_address = decode_address(self.deposit_address_b58)
        past_script = P2PKH.create_output_script(deposit_address, timelock=now - 1000)
        future_script = P2PKH.create_output_script(deposit_address, timelock=now + 1000)
        tx = self._build_stablecoin_tx(
            outputs=[
                TxOutput(UnsignedAmount.from_v1(1), past_script, 1),
                TxOutput(UnsignedAmount.from_v1(1), future_script, 1),
                TxOutput(UnsignedAmount.from_v1(498), self.script, 1),
            ],
            fee_amount=UnsignedAmount.parse('0.015'),
        )
        token_info = self._get_token_info(tx)
        with pytest.raises(InputOutputMismatch) as e:
            TransactionVerifier.verify_transparent_balance(self.custom_settings, tx, token_info)
        assert str(e.value) == (
            f'expected 0.015 of token {self.stablecoin_uid.hex()} '
            f'fee paid to {self.deposit_address_b58}, found 0.0'
        )

    def test_overpaying_deposit_output_rejected(self) -> None:
        """A deposit-address output sum above the header fee amount is rejected."""
        tx = self._build_stablecoin_tx(
            outputs=[
                TxOutput(UnsignedAmount.from_v1(2), self.deposit_script, 1),
                TxOutput(UnsignedAmount.from_v1(498), self.script, 1),
            ],
            fee_amount=UnsignedAmount.from_v1(1),
        )
        token_info = self._get_token_info(tx)
        with pytest.raises(InputOutputMismatch) as e:
            TransactionVerifier.verify_transparent_balance(self.custom_settings, tx, token_info)
        assert str(e.value) == (
            f'expected 0.01 of token {self.stablecoin_uid.hex()} '
            f'fee paid to {self.deposit_address_b58}, found 0.02'
        )

    def test_fee_token_without_inputs_or_actions_rejected(self) -> None:
        """A fee entry for a token absent from inputs and nano actions raises `InvalidToken`."""
        tx = self._build_tx(
            inputs=[TxInput(self.stablecoin_tx.hash, 4, b'')],
            outputs=[TxOutput(UnsignedAmount.from_v1(100), self.script, 0)],
            fees=[FeeHeaderEntry(token_index=1, amount=UnsignedAmount.from_v1(1))],
        )
        with pytest.raises(InvalidToken) as e:
            self._get_token_info(tx)
        assert str(e.value) == f'no inputs/actions for token {self.stablecoin_uid.hex()}'

    def test_non_payable_token_in_fee_header_rejected(self) -> None:
        """A fee entry using a fee-based token outside the policy raises `InvalidFeePaymentToken`."""
        # The stablecoin has no policy in V1, so there it is just a regular fee-based token.
        tx = self._build_stablecoin_tx(
            outputs=[TxOutput(UnsignedAmount.from_v1(500), self.script, 1)],
            fee_amount=UnsignedAmount.from_v1(1),
        )
        with pytest.raises(InvalidFeePaymentToken) as e:
            self._get_token_info(tx, fee_policy_version=FeePolicyVersion.V1)
        assert str(e.value) == f'cannot pay fees with token {self.stablecoin_uid.hex()}'

    def test_fee_units_priced_by_paying_token(self) -> None:
        """`calculate_fee` charges chargeable units at the per-unit price of the paying token's policy:
        the same transaction owes 0.01/unit when paying in HTR (V1) and 0.005/unit when paying
        in hUSDC (V2)."""
        # Paying in HTR: two chargeable stablecoin outputs at 0.01/unit make a 0.02 HTR fee.
        htr_paying_tx = self._build_tx(
            inputs=[
                TxInput(self.stablecoin_tx.hash, 0, b''),
                TxInput(self.stablecoin_tx.hash, 4, b''),
            ],
            outputs=[
                TxOutput(UnsignedAmount.from_v1(250), self.script, 1),
                TxOutput(UnsignedAmount.from_v1(250), self.script, 1),
                TxOutput(UnsignedAmount.from_v1(98), self.script, 0),
            ],
            fees=[FeeHeaderEntry(token_index=0, amount=UnsignedAmount.from_v1(2))],
        )
        token_info = self._get_token_info(htr_paying_tx, fee_policy_version=FeePolicyVersion.V1)
        assert token_info.calculate_fee() == UnsignedAmount.from_v1(2)
        TransactionVerifier.verify_transparent_balance(self.custom_settings, htr_paying_tx, token_info)

        # Paying in the stablecoin: two chargeable stablecoin outputs at 0.005/unit make a 0.01 fee.
        stablecoin_paying_tx = self._build_stablecoin_tx(
            outputs=[
                TxOutput(UnsignedAmount.from_v1(1), self.deposit_script, 1),
                TxOutput(UnsignedAmount.from_v1(499), self.script, 1),
            ],
            fee_amount=UnsignedAmount.from_v1(1),
        )
        token_info = self._get_token_info(stablecoin_paying_tx)
        assert token_info.calculate_fee() == UnsignedAmount.from_v1(1)
        TransactionVerifier.verify_transparent_balance(self.custom_settings, stablecoin_paying_tx, token_info)

    def test_fee_amount_mismatch_reports_token(self) -> None:
        """A header fee amount different from the expected fee raises `InputOutputMismatch`
        naming the paying token, the header amount, and the expected amount."""
        tx = self._build_stablecoin_tx(
            outputs=[
                TxOutput(UnsignedAmount.from_v1(3), self.deposit_script, 1),
                TxOutput(UnsignedAmount.from_v1(497), self.script, 1),
            ],
            fee_amount=UnsignedAmount.from_v1(3),
        )
        token_info = self._get_token_info(tx)
        with pytest.raises(InputOutputMismatch) as e:
            TransactionVerifier.verify_transparent_balance(self.custom_settings, tx, token_info)
        assert str(e.value) == (
            f'Fee amount is different than expected. (token={self.stablecoin_uid.hex()}, '
            f'amount=0.03, expected=0.01)'
        )

    def test_nano_created_fee_token_deferred_payability(self) -> None:
        """A fee-header token created by this tx's own nano execution has no resolvable version at
        first verification, so fee validation is skipped there (fee amounts still count against the
        balance); the post-execution verification resolves the version and fails the execution if
        that token cannot pay fees."""
        manager = self.create_peer('unittests', nc_indexes=True, nc_log_config=NCLogConfig.FAILED,
                                   wallet_index=True)
        blueprint_id = BlueprintId(self.rng.randbytes(32))
        manager.blueprint_service.register_blueprint(blueprint_id, _CreateFeeTokenBlueprint)

        dag_builder = TestDAGBuilder.from_manager(manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            tx1.nc_id = "{blueprint_id.hex()}"
            tx1.nc_method = initialize()
            tx1.nc_deposit = 1 HTR

            tx2.nc_id = tx1
            tx2.nc_method = create_fee_token()

            tx1 < tx2
            tx1 <-- b11
            tx2 <-- b12
        ''')
        b12 = artifacts.get_typed_vertex('b12', Block)
        tx1, tx2 = artifacts.get_typed_vertices(('tx1', 'tx2'), Transaction)

        # tx2 withdraws the FBT its own execution creates, and pays its fee with that same token.
        # Custom-token fee amounts must be multiples of the fee divisor, hence the 1.00 FBT fee.
        fbt_id = derive_child_token_id(ContractId(tx1.hash), token_symbol='FBT')
        tx2.tokens.append(fbt_id)
        tx2.outputs.append(TxOutput(value=UnsignedAmount.from_v1(10 ** 9 - 100), script=b'', token_data=1))
        tx2.get_nano_header().nc_actions.append(
            NanoHeaderAction(
                type=NCActionType.WITHDRAWAL, token_index=1, amount=UnsignedAmount.from_v1(10 ** 9),
            ),
        )
        tx2.headers.append(FeeHeader(
            settings=manager._settings,
            tx=tx2,
            fees=[FeeHeaderEntry(token_index=1, amount=UnsignedAmount.from_v1(100))],
        ))

        artifacts.propagate_with(manager, up_to='b11')
        assert tx1.get_metadata().nc_execution == NCExecutionState.SUCCESS

        # tx2 passes first verification: the token has no resolvable version, so fee checks are skipped.
        artifacts.propagate_with(manager, up_to='b12')
        assert tx2.get_metadata().first_block == b12.hash

        # The post-execution verification resolves the token as fee-based outside the policy.
        assert tx2.get_metadata().nc_execution == NCExecutionState.FAILURE
        assert tx2.get_metadata().voided_by == {NC_EXECUTION_FAIL_ID, tx2.hash}
        assert_nc_failure_reason(
            manager=manager,
            tx_id=tx2.hash,
            block_id=b12.hash,
            reason=f'InvalidFeePaymentToken: cannot pay fees with token {fbt_id.hex()}',
        )

    def test_fee_on_fee_outputs_of_stablecoin(self) -> None:
        """When the stablecoin is itself fee-based, the deposit-address outputs are chargeable
        outputs of that token and are included in the expected fee unit count."""
        def build(fee_amount: UnsignedAmount) -> Transaction:
            return self._build_stablecoin_tx(
                outputs=[
                    TxOutput(UnsignedAmount.from_v1(1), self.deposit_script, 1),
                    TxOutput(UnsignedAmount.from_v1(499), self.script, 1),
                ],
                fee_amount=fee_amount,
            )

        # Both stablecoin outputs (deposit and change) are chargeable: 2 units at 0.005 make a 0.01 fee.
        tx = build(UnsignedAmount.from_v1(1))
        token_info = self._get_token_info(tx)
        assert token_info.calculate_fee() == UnsignedAmount.from_v1(1)
        TransactionVerifier.verify_transparent_balance(self.custom_settings, tx, token_info)

        # A header paying for a single unit is rejected, proving the deposit output is included.
        tx = build(UnsignedAmount.parse('0.005'))
        token_info = self._get_token_info(tx)
        with pytest.raises(InputOutputMismatch) as e:
            TransactionVerifier.verify_transparent_balance(self.custom_settings, tx, token_info)
        assert str(e.value) == (
            f'Fee amount is different than expected. (token={self.stablecoin_uid.hex()}, '
            f'amount=0.005, expected=0.01)'
        )


class _GetSettingsBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> int:
        settings = self.syscall.get_settings()
        return settings.fee_policies[TokenUid(HATHOR_TOKEN_UID)].fee_based_tokens


class TestFeePolicyVersionActivation(TestCase):
    """Invariants of fee policy version selection."""

    def test_default_fee_policy_version_is_v1(self) -> None:
        """Before any activation wiring, `Features.from_vertex` reports `FeePolicyVersion.V1`."""
        manager = self.create_peer('unittests')
        features = Features.from_vertex(
            settings=self._settings,
            feature_service=manager.feature_service,
            vertex=manager.tx_storage.get_best_block(),
        )
        assert features.fee_policy_version == FeePolicyVersion.V1
        assert Features.all_enabled().fee_policy_version == FeePolicyVersion.V2

    def test_nano_runtime_version_maps_to_fee_policy_version(self) -> None:
        """`NanoRuntimeVersion.V1` and `V2` map to `FeePolicyVersion.V1`; `V3` maps to `V2`."""
        assert NanoRuntimeVersion.V1.get_fee_policy_version() == FeePolicyVersion.V1
        assert NanoRuntimeVersion.V2.get_fee_policy_version() == FeePolicyVersion.V1
        assert NanoRuntimeVersion.V3.get_fee_policy_version() == FeePolicyVersion.V2

    def test_block_executor_uses_parent_block_features(self) -> None:
        """Nano execution of a block uses the feature state of the block's parent, so a
        transaction confirmed by the first block of an activation boundary still executes
        under the pre-activation feature set."""
        manager = self.create_peer('unittests', nc_indexes=True, nc_log_config=NCLogConfig.FAILED,
                                   wallet_index=True)
        blueprint_id = BlueprintId(self.rng.randbytes(32))
        manager.blueprint_service.register_blueprint(blueprint_id, _GetSettingsBlueprint)

        feature_settings = FeatureSettings(
            evaluation_interval=4,
            default_threshold=3,
            features={
                Feature.REDUCE_DAA_TARGET: Criteria(
                    bit=0,
                    start_height=4,
                    timeout_height=12,
                    version='0.0.0',
                ),
            },
        )
        settings = self._settings.model_copy(update=dict(
            ENABLE_DAA_V2=FeatureSetting.FEATURE_ACTIVATION,
            FEATURE_ACTIVATION=feature_settings,
        ))
        manager.feature_service._feature_settings = feature_settings
        manager.consensus_algorithm.block_executor._settings = settings

        dag_builder = TestDAGBuilder.from_manager(manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..13]
            b10 < dummy

            b5.signal_bits = 1
            b6.signal_bits = 1
            b7.signal_bits = 1

            nc1.nc_id = "{blueprint_id.hex()}"
            nc1.nc_method = initialize()

            nc2.nc_id = "{blueprint_id.hex()}"
            nc2.nc_method = initialize()

            nc1 <-- b12
            nc2 <-- b13
        ''')
        b12, b13 = artifacts.get_typed_vertices(('b12', 'b13'), Block)
        nc1, nc2 = artifacts.get_typed_vertices(('nc1', 'nc2'), Transaction)

        # DAA V2 raises the block reward from b13 onward.
        assert len(b13.outputs) == 1
        b13.outputs[0].value = UnsignedAmount.from_v1(1600)
        artifacts.propagate_with(manager)

        assert manager.feature_service.get_state(
            block=b12, feature=Feature.REDUCE_DAA_TARGET
        ) == FeatureState.ACTIVE
        assert nc1.get_metadata().first_block == b12.hash
        assert nc2.get_metadata().first_block == b13.hash

        # nc1 is confirmed by the first ACTIVE block, so it executes under the pre-activation
        # feature set of b11 (runtime V1), where `get_settings` is unavailable.
        assert nc1.get_metadata().nc_execution == NCExecutionState.FAILURE
        assert nc1.get_metadata().voided_by == {NC_EXECUTION_FAIL_ID, nc1.hash}
        assert_nc_failure_reason(
            manager=manager,
            tx_id=nc1.hash,
            block_id=b12.hash,
            reason='syscall `get_settings` is not yet supported',
        )

        # nc2 is confirmed by the next block, whose parent b12 is already ACTIVE (runtime V2).
        assert nc2.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert nc2.get_metadata().voided_by is None


STABLECOIN_UID = TokenUid(b'\x01' * 32)
NON_POLICY_FBT_UID = TokenUid(b'\x02' * 32)
DEPOSIT_TOKEN_UID = TokenUid(b'\x03' * 32)


class _ActionsFeeBlueprint(Blueprint):
    fbt_uid: TokenUid

    @public(allow_deposit=True)
    def initialize(self, ctx: Context) -> None:
        self.fbt_uid = self.syscall.create_fee_token(
            token_name='FeeToken',
            token_symbol='FTK',
            amount=1_000_000,
            mint_authority=True,
            melt_authority=True,
        )

    @public
    def move_fbt(
        self,
        ctx: Context,
        nc_id: ContractId,
        token_amount: int,
        fee_payment_token: TokenUid,
        fee_amount: int,
    ) -> None:
        action = NCDepositAction(token_uid=self.fbt_uid, amount=token_amount)
        fees = [NCFee(token_uid=fee_payment_token, amount=fee_amount)]
        self.syscall.get_contract(nc_id, blueprint_id=None).public(action, fees=fees).noop()

    @public
    def move_fbt_two_fees(
        self,
        ctx: Context,
        nc_id: ContractId,
        token_amount: int,
        token_a: TokenUid,
        amount_a: int,
        token_b: TokenUid,
        amount_b: int,
    ) -> None:
        action = NCDepositAction(token_uid=self.fbt_uid, amount=token_amount)
        fees = [NCFee(token_uid=token_a, amount=amount_a), NCFee(token_uid=token_b, amount=amount_b)]
        self.syscall.get_contract(nc_id, blueprint_id=None).public(action, fees=fees).noop()

    @public
    def mint(self, ctx: Context, token_uid: TokenUid, amount: int, fee_payment_token: TokenUid) -> None:
        self.syscall.mint_tokens(token_uid, amount=amount, fee_payment_token=fee_payment_token)

    @public
    def melt(self, ctx: Context, token_uid: TokenUid, amount: int, fee_payment_token: TokenUid) -> None:
        self.syscall.melt_tokens(token_uid, amount=amount, fee_payment_token=fee_payment_token)


class _ReceiverBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public(allow_deposit=True, allow_withdrawal=True)
    def noop(self, ctx: Context) -> None:
        pass


class TestNanoActionsFees(BlueprintTestCase):
    """Invariants of the runner's `_validate_actions_fees` and fee syscalls."""

    def setUp(self) -> None:
        super().setUp()
        htr_policy = self._settings.FEE_POLICIES[FeePolicyVersion.V1][HATHOR_TOKEN_UID]
        # 2.00 per unit: distinguishable from the 0.01 HTR unit price, and a multiple of the fee divisor.
        self.stablecoin_policy = _policy(
            deposit_address=BURN_ADDRESS,
            fee_based_tokens='2.00',
            amount_shielded='4.00',
            full_shielded='8.00',
        )
        self.custom_settings = self._settings.model_copy(update={'FEE_POLICIES': {
            FeePolicyVersion.V1: {
                HATHOR_TOKEN_UID: htr_policy,
                STABLECOIN_UID: self.stablecoin_policy,
            },
        }})
        self.runner = TestRunner(
            tx_storage=self.manager.tx_storage,
            blueprint_service=self.manager.blueprint_service,
            settings=self.custom_settings,
            reactor=self.reactor,
            runtime_version=NanoRuntimeVersion.V2,
            token_amount_version=TokenAmountVersion.V1,
        )
        self.create_token(STABLECOIN_UID, 'StableCoin', 'STB', TokenVersion.FEE)
        self.create_token(NON_POLICY_FBT_UID, 'OtherFee', 'OFT', TokenVersion.FEE)
        self.create_token(DEPOSIT_TOKEN_UID, 'DepositToken', 'DTK', TokenVersion.DEPOSIT)

        self.actions_blueprint_id = self._register_blueprint_class(_ActionsFeeBlueprint)
        self.receiver_blueprint_id = self._register_blueprint_class(_ReceiverBlueprint)
        self.nc1_id = self.gen_random_contract_id()
        self.nc2_id = self.gen_random_contract_id()
        self.fbt_uid = derive_child_token_id(self.nc1_id, 'FTK')

        # nc1 holds every fee-payment candidate: 1.00 HTR (0.01 goes to the FTK creation fee),
        # 10.00 STB, 10.00 OFT and 10.00 DTK.
        ctx = self.create_context(actions=[
            NCDepositAction(token_uid=TokenUid(HATHOR_TOKEN_UID), amount=100),
            NCDepositAction(token_uid=STABLECOIN_UID, amount=1000),
            NCDepositAction(token_uid=NON_POLICY_FBT_UID, amount=1000),
            NCDepositAction(token_uid=DEPOSIT_TOKEN_UID, amount=1000),
        ])
        self.runner.create_contract(self.nc1_id, self.actions_blueprint_id, ctx)
        self.runner.create_contract(self.nc2_id, self.receiver_blueprint_id, self.create_context())

    def _nc1_balance(self, token_uid: TokenUid) -> Balance:
        return self.runner.get_storage(self.nc1_id).get_balance(token_uid)

    def test_actions_fee_priced_by_paying_token(self) -> None:
        """Chargeable deposit/withdrawal actions on fee-based tokens are priced at the paying
        token's policy per-unit fee."""
        # One chargeable action paying in the stablecoin costs its 2.00/unit policy price.
        self.runner.call_public_method(
            self.nc1_id, 'move_fbt', self.create_context(), self.nc2_id,
            token_amount=1000, fee_payment_token=STABLECOIN_UID, fee_amount=200,
        )
        assert self._nc1_balance(STABLECOIN_UID) == Balance(
            value=UnsignedAmount.from_v1(800).to_signed(), can_mint=False, can_melt=False
        )

        # The same action paying in HTR costs the 0.01/unit HTR policy price.
        self.runner.call_public_method(
            self.nc1_id, 'move_fbt', self.create_context(), self.nc2_id,
            token_amount=1000, fee_payment_token=TokenUid(HATHOR_TOKEN_UID), fee_amount=1,
        )
        assert self._nc1_balance(TokenUid(HATHOR_TOKEN_UID)) == Balance(
            value=UnsignedAmount.from_v1(98).to_signed(), can_mint=False, can_melt=False
        )

        assert self.runner.get_storage(self.nc2_id).get_balance(self.fbt_uid) == Balance(
            value=UnsignedAmount.from_v1(2000).to_signed(), can_mint=False, can_melt=False
        )

    def test_actions_fee_with_non_policy_fee_token_rejected(self) -> None:
        """Paying actions fees with a fee-based token outside the policy fails the execution
        with an `NCFail` whose cause is an `InvalidFeePaymentToken` naming the token."""
        with pytest.raises(NCFail) as e:
            self.runner.call_public_method(
                self.nc1_id, 'move_fbt', self.create_context(), self.nc2_id,
                token_amount=1000, fee_payment_token=NON_POLICY_FBT_UID, fee_amount=100,
            )
        assert isinstance(e.value.__cause__, InvalidFeePaymentToken)
        assert str(e.value.__cause__) == f'cannot pay fees with token {NON_POLICY_FBT_UID.hex()}'

    def test_actions_fee_mixing_stablecoin_fails_execution(self) -> None:
        """Mixing a stablecoin with other fee tokens in actions fees fails the nano execution
        (converted to `NCFail`), and never propagates as an unhandled exception out of
        block execution."""
        expected_msg = (
            'fee payments must either use a combination of HTR and deposit-based tokens, or a single stablecoin'
        )

        with pytest.raises(NCFail) as e:
            self.runner.call_public_method(
                self.nc1_id, 'move_fbt_two_fees', self.create_context(), self.nc2_id,
                token_amount=1000,
                token_a=STABLECOIN_UID, amount_a=200,
                token_b=TokenUid(HATHOR_TOKEN_UID), amount_b=1,
            )
        assert isinstance(e.value.__cause__, InvalidFeePaymentToken)
        assert str(e.value.__cause__) == expected_msg

        with pytest.raises(NCFail) as e:
            self.runner.call_public_method(
                self.nc1_id, 'move_fbt_two_fees', self.create_context(), self.nc2_id,
                token_amount=1000,
                token_a=STABLECOIN_UID, amount_a=200,
                token_b=DEPOSIT_TOKEN_UID, amount_b=100,
            )
        assert isinstance(e.value.__cause__, InvalidFeePaymentToken)
        assert str(e.value.__cause__) == expected_msg

    def test_actions_fee_mismatch_rejected(self) -> None:
        """A paid actions-fee total different from the expected total raises `NCInvalidFee`."""
        with pytest.raises(NCInvalidFee) as e:
            self.runner.call_public_method(
                self.nc1_id, 'move_fbt', self.create_context(), self.nc2_id,
                token_amount=1000, fee_payment_token=STABLECOIN_UID, fee_amount=400,
            )
        # Both totals are aggregated as V2 amounts, so they render with a single decimal place.
        assert str(e.value) == 'Fee payment balance is different than expected. (amount=4.0, expected=2.0)'

    def test_actions_fee_duplicate_token_rejected(self) -> None:
        """Two `NCFee` entries for the same token in a single call raise `NCInvalidFee`,
        mirroring the duplicate restrictions on actions and on tx fee header entries."""
        with pytest.raises(NCInvalidFee) as e:
            self.runner.call_public_method(
                self.nc1_id, 'move_fbt_two_fees', self.create_context(), self.nc2_id,
                token_amount=1000,
                token_a=STABLECOIN_UID, amount_a=200,
                token_b=STABLECOIN_UID, amount_b=200,
            )
        assert str(e.value) == f'duplicate fees for token {STABLECOIN_UID.hex()}'

    def test_mint_fee_uses_policy_per_unit(self) -> None:
        """Minting a fee-based token charges the policy per-unit fee of the payment token,
        converting through the deposit rate only for non-policy payment tokens."""
        # Paying in the stablecoin charges its own 2.00 policy price.
        self.runner.call_public_method(
            self.nc1_id, 'mint', self.create_context(),
            self.fbt_uid, amount=500, fee_payment_token=STABLECOIN_UID,
        )
        assert self._nc1_balance(STABLECOIN_UID) == Balance(
            value=UnsignedAmount.from_v1(800).to_signed(), can_mint=False, can_melt=False
        )

        # Paying in a non-policy deposit-based token converts the 0.01 HTR unit fee to 1.00 DTK.
        self.runner.call_public_method(
            self.nc1_id, 'mint', self.create_context(),
            self.fbt_uid, amount=500, fee_payment_token=DEPOSIT_TOKEN_UID,
        )
        assert self._nc1_balance(DEPOSIT_TOKEN_UID) == Balance(
            value=UnsignedAmount.from_v1(900).to_signed(), can_mint=False, can_melt=False
        )

        assert self._nc1_balance(self.fbt_uid) == Balance(
            value=UnsignedAmount.from_v1(1_001_000).to_signed(), can_mint=True, can_melt=True
        )

    def test_melt_fee_uses_policy_per_unit(self) -> None:
        """Melting a fee-based token charges the policy per-unit fee of the payment token,
        converting through the deposit rate only for non-policy payment tokens."""
        # Paying in the stablecoin charges its own 2.00 policy price.
        self.runner.call_public_method(
            self.nc1_id, 'melt', self.create_context(),
            self.fbt_uid, amount=500, fee_payment_token=STABLECOIN_UID,
        )
        assert self._nc1_balance(STABLECOIN_UID) == Balance(
            value=UnsignedAmount.from_v1(800).to_signed(), can_mint=False, can_melt=False
        )

        # Paying in a non-policy deposit-based token converts the 0.01 HTR unit fee to 1.00 DTK.
        self.runner.call_public_method(
            self.nc1_id, 'melt', self.create_context(),
            self.fbt_uid, amount=500, fee_payment_token=DEPOSIT_TOKEN_UID,
        )
        assert self._nc1_balance(DEPOSIT_TOKEN_UID) == Balance(
            value=UnsignedAmount.from_v1(900).to_signed(), can_mint=False, can_melt=False
        )

        assert self._nc1_balance(self.fbt_uid) == Balance(
            value=UnsignedAmount.from_v1(999_000).to_signed(), can_mint=True, can_melt=True
        )

    @pytest.mark.xfail(reason='crediting actions fees to the policy deposit address is not implemented yet')
    def test_stablecoin_actions_fee_deposited_not_burned(self) -> None:
        """Actions fees paid in a stablecoin with a deposit address are credited to that address
        instead of being burned."""
        raise NotImplementedError


class TestNanoSettingsSyscall(TestCase):
    """Invariants of `NanoSettings.__from_settings__` exposed via the `get_settings` syscall."""

    def setUp(self) -> None:
        super().setUp()
        self.stablecoin_uid = TokenUid(b'\xaa' * 32)
        htr_policy = self._settings.FEE_POLICIES[FeePolicyVersion.V1][HATHOR_TOKEN_UID]
        self.settings = self._settings.model_copy(update={'FEE_POLICIES': {
            FeePolicyVersion.V1: {
                HATHOR_TOKEN_UID: htr_policy,
                self.stablecoin_uid: _policy(
                    deposit_address=BURN_ADDRESS,
                    fee_based_tokens='0.05',
                    amount_shielded='0.10',
                    full_shielded='0.20',
                ),
            },
            FeePolicyVersion.V2: {
                HATHOR_TOKEN_UID: _policy(
                    fee_based_tokens='1.00',
                    amount_shielded='2.00',
                    full_shielded='4.00',
                ),
            },
        }})

    def test_get_settings_unsupported_on_runtime_v1(self) -> None:
        """The `get_settings` syscall raises `NCFail` on runtime V1."""
        with pytest.raises(NCFail) as e:
            NanoSettings.__from_settings__(
                settings=self.settings,
                runtime_version=NanoRuntimeVersion.V1,
                token_amount_version=TokenAmountVersion.V1,
            )
        assert str(e.value) == 'syscall `get_settings` is not yet supported'

    def test_get_settings_exposes_fee_policies(self) -> None:
        """On runtime V2+, `get_settings` returns one `FeePolicy` per token of the runtime's
        fee policy version, keyed by `TokenUid`."""
        # Runtime V2 exposes the V1 fee policy version.
        nano_settings = NanoSettings.__from_settings__(
            settings=self.settings,
            runtime_version=NanoRuntimeVersion.V2,
            token_amount_version=TokenAmountVersion.V1,
        )
        assert nano_settings == NanoSettings(fee_policies={
            TokenUid(HATHOR_TOKEN_UID): NanoFeePolicy(
                deposit_address=None, fee_based_tokens=1, amount_shielded=1, full_shielded=2,
            ),
            self.stablecoin_uid: NanoFeePolicy(
                deposit_address=BURN_ADDRESS, fee_based_tokens=5, amount_shielded=10, full_shielded=20,
            ),
        })

        # Runtime V3 exposes the V2 fee policy version.
        nano_settings = NanoSettings.__from_settings__(
            settings=self.settings,
            runtime_version=NanoRuntimeVersion.V3,
            token_amount_version=TokenAmountVersion.V1,
        )
        assert nano_settings == NanoSettings(fee_policies={
            TokenUid(HATHOR_TOKEN_UID): NanoFeePolicy(
                deposit_address=None, fee_based_tokens=100, amount_shielded=200, full_shielded=400,
            ),
        })

    def test_get_settings_amounts_follow_token_amount_version(self) -> None:
        """Fee amounts in the syscall result are integers in the contract's token amount version:
        raw V1 units under `TokenAmountVersion.V1` and normalized units under `V2`."""
        v1_policies = NanoSettings.__from_settings__(
            settings=self.settings,
            runtime_version=NanoRuntimeVersion.V2,
            token_amount_version=TokenAmountVersion.V1,
        ).fee_policies
        assert v1_policies[TokenUid(HATHOR_TOKEN_UID)] == NanoFeePolicy(
            deposit_address=None, fee_based_tokens=1, amount_shielded=1, full_shielded=2,
        )

        v2_policies = NanoSettings.__from_settings__(
            settings=self.settings,
            runtime_version=NanoRuntimeVersion.V2,
            token_amount_version=TokenAmountVersion.V2,
        ).fee_policies
        assert v2_policies[TokenUid(HATHOR_TOKEN_UID)] == NanoFeePolicy(
            deposit_address=None,
            fee_based_tokens=10 ** 16,
            amount_shielded=10 ** 16,
            full_shielded=2 * 10 ** 16,
        )
