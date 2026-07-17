# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Nano contract actions, balances, runner verifications, and execution under V1 vs V2 token amounts.

A nano tx's token amount version (derived from `signal_bits`) governs how every deposit/withdrawal/mint/melt
amount it carries is interpreted, and it must match the blueprint's registered version: the runner refuses to
instantiate a blueprint whose version differs from the tx's, raising `NCFail`. Contract balances are stored as
`SignedAmount` in the shared normalized unit, so V1 and V2 amounts accumulate losslessly. These tests drive
deposits/withdrawals/mint/melt through the runner, the cross-version guard and the block executor through the
DAG builder, and the feature gate/reorg rule through both the verifier and a full feature-activation lifecycle.
"""

import dataclasses
import re

import pytest
from htr_lib import UnsignedAmount

from hathor.daa import DAAFactory, TestMode
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.feature_activation.utils import Features
from hathor.nanocontracts import HATHOR_TOKEN_UID, NC_EXECUTION_FAIL_ID
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCInsufficientFunds
from hathor.nanocontracts.storage.contract_storage import Balance, BalanceKey
from hathor.nanocontracts.types import (
    BlueprintId,
    ContractId,
    NCDepositAction,
    NCGrantAuthorityAction,
    NCWithdrawalAction,
    TokenUid,
)
from hathor.transaction import Block, Transaction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor.transaction.token_info import TokenVersion
from hathor.verification.verification_params import VerificationParams
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathor_tests.nanocontracts.utils import assert_nc_failure_reason
from hathorlib.conf.settings import FeatureSetting
from hathorlib.exceptions import TxValidationError
from hathorlib.nanocontracts import NCFail
from hathorlib.nanocontracts.types import public
from hathorlib.token_amount_version import TokenAmountVersion

# One V2 "cent" in normalized units: the smallest amount representable in V1 (10**-2) expressed at V2's
# 18-decimal scale. A V2 amount that is not a multiple of this is "sub-cent" and has no V1 representation.
ONE_V2_CENT = 10 ** 16


class MyBlueprint(Blueprint):
    """A blueprint that accepts deposits/withdrawals, mints/melts, and calls into other contracts."""

    @public(allow_deposit=True, allow_grant_authority=True)
    def initialize(self, ctx: Context) -> None:
        pass

    @public(allow_deposit=True, allow_withdrawal=True)
    def nop(self, ctx: Context) -> None:
        pass

    @public
    def mint(self, ctx: Context, token_uid: TokenUid) -> None:
        # A whole-cent V2 mint fee needs an amount of at least `10**18` raw units. Serialized method args are
        # int32-bounded, so the amount is fixed in the method body to stay outside that bound.
        self.syscall.mint_tokens(token_uid, amount=2 * 10 ** 18)

    @public
    def melt(self, ctx: Context, token_uid: TokenUid) -> None:
        self.syscall.melt_tokens(token_uid, amount=10 ** 18)

    @public
    def call_other_public(self, ctx: Context, contract_id: ContractId) -> None:
        contract = self.syscall.get_contract(contract_id, blueprint_id=None)
        contract.public().nop()


class TestNanoContractsTokenAmountVersion(BlueprintTestCase):
    """Nano contract actions, balances, runner verifications, and execution under V1 vs V2 token amounts."""

    def setUp(self) -> None:
        super().setUp()
        self.blueprint_id_v1 = self._register_blueprint_class(MyBlueprint, token_amount_version=TokenAmountVersion.V1)
        self.blueprint_id_v2 = self._register_blueprint_class(MyBlueprint, token_amount_version=TokenAmountVersion.V2)
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)
        self.htr_uid = TokenUid(HATHOR_TOKEN_UID)

    def test_deposit_v1_token_updates_contract_balance(self) -> None:
        """A V1 nano tx deposits HTR into a contract; assert the contract balance increases to the expected
        `SignedAmount` and the token index total matches. Control for V1 deposit accounting."""
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        contract_id = self.gen_random_contract_id()
        runner.create_contract(
            contract_id,
            self.blueprint_id_v1,
            self.create_context(actions=[NCDepositAction(token_uid=self.htr_uid, amount=100)]),
        )
        htr_key = BalanceKey(nc_id=contract_id, token_uid=HATHOR_TOKEN_UID)

        expected = Balance(value=UnsignedAmount.from_v1(100).to_signed(), can_mint=False, can_melt=False)
        assert runner.get_storage(contract_id).get_all_balances() == {htr_key: expected}
        # The contract's stored per-token total tracks the deposit; a V1 raw of 100 normalizes by the factor.
        assert runner.get_current_balance(contract_id, self.htr_uid) == expected
        assert expected.value.raw() == 100 * UnsignedAmount.get_normalization_factor()

    def test_deposit_v2_token_updates_contract_balance(self) -> None:
        """A V2 nano tx (V2 blueprint, LSB 1) deposits a V2-encoded amount; assert the resulting balance is the
        V2-tagged `SignedAmount` whose `.raw()` equals the action amount and that balance validation accepts it.
        Pins V2 deposit accounting end-to-end."""
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        contract_id = self.gen_random_contract_id()
        runner.create_contract(
            contract_id,
            self.blueprint_id_v2,
            self.create_context(actions=[NCDepositAction(token_uid=self.htr_uid, amount=100)]),
        )
        htr_key = BalanceKey(nc_id=contract_id, token_uid=HATHOR_TOKEN_UID)

        expected = Balance(value=UnsignedAmount.from_v2(100).to_signed(), can_mint=False, can_melt=False)
        assert runner.get_storage(contract_id).get_all_balances() == {htr_key: expected}
        assert runner.get_current_balance(contract_id, self.htr_uid) == expected
        # A V2 raw and its normalized value coincide, so `.raw()` equals the action amount.
        assert expected.value.raw() == 100

    def test_deposit_sub_cent_v2_amount(self) -> None:
        """Deposit a V2 amount not representable in V1 (smallest raw unit); assert the contract balance holds the
        exact sub-cent value. Pins that V2 enables amounts a V1 contract could not encode."""
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        contract_id = self.gen_random_contract_id()
        runner.create_contract(
            contract_id,
            self.blueprint_id_v2,
            self.create_context(actions=[NCDepositAction(token_uid=self.htr_uid, amount=1)]),
        )
        htr_key = BalanceKey(nc_id=contract_id, token_uid=HATHOR_TOKEN_UID)

        expected = Balance(value=UnsignedAmount.from_v2(1).to_signed(), can_mint=False, can_melt=False)
        assert runner.get_storage(contract_id).get_all_balances() == {htr_key: expected}
        assert expected.value.raw() == 1
        # One raw V2 unit is a fraction of a cent, so it has no V1 representation.
        assert expected.value.raw() % ONE_V2_CENT != 0

    def test_withdrawal_v1_token_updates_contract_balance(self) -> None:
        """A V1 withdrawal decreases the contract balance to the expected V1 `SignedAmount`; index total updated.
        Control for V1 withdrawal."""
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        contract_id = self.gen_random_contract_id()
        runner.create_contract(
            contract_id,
            self.blueprint_id_v1,
            self.create_context(actions=[NCDepositAction(token_uid=self.htr_uid, amount=100)]),
        )
        runner.call_public_method(
            contract_id,
            'nop',
            self.create_context(actions=[NCWithdrawalAction(token_uid=self.htr_uid, amount=30)]),
        )
        htr_key = BalanceKey(nc_id=contract_id, token_uid=HATHOR_TOKEN_UID)

        expected = Balance(value=UnsignedAmount.from_v1(70).to_signed(), can_mint=False, can_melt=False)
        assert runner.get_storage(contract_id).get_all_balances() == {htr_key: expected}
        assert runner.get_current_balance(contract_id, self.htr_uid) == expected

    def test_withdrawal_v2_token_updates_contract_balance(self) -> None:
        """A V2 withdrawal moves V2-encoded tokens out to a V2 output; assert the post-withdrawal balance equals
        deposit-minus-withdrawal as a V2 `SignedAmount`. Pins V2 withdrawal accounting."""
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        contract_id = self.gen_random_contract_id()
        runner.create_contract(
            contract_id,
            self.blueprint_id_v2,
            self.create_context(actions=[NCDepositAction(token_uid=self.htr_uid, amount=100)]),
        )
        runner.call_public_method(
            contract_id,
            'nop',
            self.create_context(actions=[NCWithdrawalAction(token_uid=self.htr_uid, amount=30)]),
        )
        htr_key = BalanceKey(nc_id=contract_id, token_uid=HATHOR_TOKEN_UID)

        expected = Balance(value=UnsignedAmount.from_v2(70).to_signed(), can_mint=False, can_melt=False)
        assert runner.get_storage(contract_id).get_all_balances() == {htr_key: expected}
        assert expected.value.raw() == 70

    def test_withdrawal_exceeding_balance_raises_insufficient_funds_v2(self) -> None:
        """A V2 withdrawal larger than the contract balance drives the change tracker negative; assert
        `NCInsufficientFunds`. Pins the final-balance guard under V2."""
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        contract_id = self.gen_random_contract_id()
        runner.create_contract(
            contract_id,
            self.blueprint_id_v2,
            self.create_context(actions=[NCDepositAction(token_uid=self.htr_uid, amount=100)]),
        )

        with pytest.raises(NCInsufficientFunds, match=re.escape(f'negative balance for contract {contract_id.hex()}')):
            runner.call_public_method(
                contract_id,
                'nop',
                self.create_context(actions=[NCWithdrawalAction(token_uid=self.htr_uid, amount=150)]),
            )

    def test_mint_and_melt_inside_v2_contract(self) -> None:
        """A V2 contract with mint authority mints, then melts, tokens via syscalls; assert minted balance and the
        consumed/freed HTR are accounted as V2 amounts and balance validation reconciles."""
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V2)
        token_uid = self.gen_random_token_uid()
        runner._runner.block_storage.create_token(
            token_id=token_uid,
            token_name='Test Token',
            token_symbol='TST',
            token_version=TokenVersion.DEPOSIT,
        )
        contract_id = self.gen_random_contract_id()
        runner.create_contract(
            contract_id,
            self.blueprint_id_v2,
            self.create_context(actions=[
                NCDepositAction(token_uid=self.htr_uid, amount=3 * 10 ** 16),
                NCGrantAuthorityAction(token_uid=token_uid, mint=True, melt=True),
            ]),
        )

        # Mint `2 * 10**18` raw V2 tokens: the deposit-based mint fee is 1% rounded up to a whole cent, which is
        # `2 * 10**16` HTR. Melt `10**18`: the refund is 1% rounded down to a whole cent, i.e. `10**16` HTR back.
        runner.call_public_method(contract_id, 'mint', self.create_context(), token_uid)
        runner.call_public_method(contract_id, 'melt', self.create_context(), token_uid)

        htr_key = BalanceKey(nc_id=contract_id, token_uid=HATHOR_TOKEN_UID)
        token_key = BalanceKey(nc_id=contract_id, token_uid=token_uid)
        assert runner.get_storage(contract_id).get_all_balances() == {
            htr_key: Balance(
                value=UnsignedAmount.from_v2(2 * 10 ** 16).to_signed(), can_mint=False, can_melt=False
            ),
            token_key: Balance(
                value=UnsignedAmount.from_v2(10 ** 18).to_signed(), can_mint=True, can_melt=True
            ),
        }

    def test_create_contract_cross_version_raises_ncfail(self) -> None:
        """A V2-version runner creating a V1-registered blueprint (and the mirror) raises `NCFail('cannot call
        blueprints across token amount versions ...')`. Pins the create-time version guard."""
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            v1_over_v2.nc_id = "{self.blueprint_id_v2.hex()}"
            v1_over_v2.nc_method = initialize()

            v2_over_v1.nc_id = "{self.blueprint_id_v1.hex()}"
            v2_over_v1.nc_method = initialize()
            v2_over_v1.token_amount_version = V2

            v1_over_v2 <-- b11
            v2_over_v1 <-- b11
        ''')
        artifacts.propagate_with(self.manager)
        b11 = artifacts.get_typed_vertex('b11', Block)
        v1_over_v2, v2_over_v1 = artifacts.get_typed_vertices(('v1_over_v2', 'v2_over_v1'), Transaction)

        # A V1 tx creating a V2 blueprint: runner version 1, blueprint version 2.
        assert v1_over_v2.get_metadata().voided_by == {v1_over_v2.hash, NC_EXECUTION_FAIL_ID}
        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=v1_over_v2.hash,
            block_id=b11.hash,
            reason='NCFail: cannot call blueprints across token amount versions (tx = 1, blueprint = 2)',
        )

        # The mirror: a V2 tx creating a V1 blueprint.
        assert v2_over_v1.get_metadata().voided_by == {v2_over_v1.hash, NC_EXECUTION_FAIL_ID}
        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=v2_over_v1.hash,
            block_id=b11.hash,
            reason='NCFail: cannot call blueprints across token amount versions (tx = 2, blueprint = 1)',
        )

    def test_call_method_cross_version_raises_ncfail(self) -> None:
        """Calling a public or view method on a contract whose blueprint version differs from the tx's runtime
        version raises the same `NCFail`; same-version calls succeed."""
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..13]
            b10 < dummy

            nc_create.nc_id = "{self.blueprint_id_v2.hex()}"
            nc_create.nc_method = initialize()
            nc_create.token_amount_version = V2

            nc_call.nc_id = nc_create
            nc_call.nc_method = nop()

            nc_create <-- b11
            nc_call <-- b12
            b11 < nc_call
            b12 < b13
        ''')
        artifacts.propagate_with(self.manager)
        b12 = artifacts.get_typed_vertex('b12', Block)
        nc_create, nc_call = artifacts.get_typed_vertices(('nc_create', 'nc_call'), Transaction)

        # The same-version create (V2 tx over V2 blueprint) succeeds.
        assert nc_create.get_metadata().voided_by is None
        assert nc_create.get_metadata().nc_execution == NCExecutionState.SUCCESS

        # The cross-version call (V1 tx over the V2 contract) fails.
        assert nc_call.get_metadata().voided_by == {nc_call.hash, NC_EXECUTION_FAIL_ID}
        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=nc_call.hash,
            block_id=b12.hash,
            reason='NCFail: cannot call blueprints across token amount versions (tx = 1, blueprint = 2)',
        )

    def test_inter_contract_call_cross_version_raises_ncfail(self) -> None:
        """A V1 contract calling a V2 contract's public method raises `NCFail` while instantiating the callee's
        blueprint, before any balance mutation; both contracts' balances are left unchanged."""
        runner = self.build_runner(token_amount_version=TokenAmountVersion.V1)
        v1_id = self.gen_random_contract_id()
        v2_id = self.gen_random_contract_id()

        runner.create_contract(
            v1_id,
            self.blueprint_id_v1,
            self.create_context(actions=[NCDepositAction(token_uid=self.htr_uid, amount=1000)]),
        )
        runner._runner.token_amount_version = TokenAmountVersion.V2
        runner.create_contract(
            v2_id,
            self.blueprint_id_v2,
            self.create_context(actions=[NCDepositAction(token_uid=self.htr_uid, amount=1000)]),
        )
        runner._runner.token_amount_version = TokenAmountVersion.V1

        v1_balances = runner.get_storage(v1_id).get_all_balances()
        v2_balances = runner.get_storage(v2_id).get_all_balances()

        msg = 'cannot call blueprints across token amount versions (tx = 1, blueprint = 2)'
        with pytest.raises(NCFail, match=re.escape(msg)):
            runner.call_public_method(v1_id, 'call_other_public', self.create_context(), v2_id)

        # The guard fires while instantiating the callee's blueprint, before any balance mutation commits.
        assert runner.get_storage(v1_id).get_all_balances() == v1_balances
        assert runner.get_storage(v2_id).get_all_balances() == v2_balances
        assert v1_balances == {
            BalanceKey(nc_id=v1_id, token_uid=HATHOR_TOKEN_UID):
                Balance(value=UnsignedAmount.from_v1(1000).to_signed(), can_mint=False, can_melt=False),
        }
        assert v2_balances == {
            BalanceKey(nc_id=v2_id, token_uid=HATHOR_TOKEN_UID):
                Balance(value=UnsignedAmount.from_v2(1000).to_signed(), can_mint=False, can_melt=False),
        }

    def test_block_executor_runs_v2_nano_tx(self) -> None:
        """Propagate a block containing a V2 nano deposit; assert the executor builds the runner with V2, execution
        succeeds, and the stored contract balance is the expected V2 value. Pins the executor's version wiring."""
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            nc.nc_id = "{self.blueprint_id_v2.hex()}"
            nc.nc_method = initialize()
            nc.nc_deposit = 1.00 HTR
            nc.token_amount_version = V2

            nc <-- b11
            b11 < b12
        ''')
        artifacts.propagate_with(self.manager)
        nc = artifacts.get_typed_vertex('nc', Transaction)

        assert nc.get_token_amount_version() == TokenAmountVersion.V2
        assert nc.get_metadata().voided_by is None
        assert nc.get_metadata().nc_execution == NCExecutionState.SUCCESS

        htr_key = BalanceKey(nc_id=nc.hash, token_uid=HATHOR_TOKEN_UID)
        balances = self.manager.get_best_block_nc_storage(nc.hash).get_all_balances()
        assert balances == {
            htr_key: Balance(value=UnsignedAmount.from_v2(10 ** 18).to_signed(), can_mint=False, can_melt=False),
        }

    def test_v2_nano_tx_rejected_when_feature_inactive(self) -> None:
        """With `ENABLE_TOKEN_AMOUNT_V2` inactive, submitting a nano tx with LSB 1 raises `TxValidationError('invalid
        token amount version: V2')`. Pins the feature gate for nano vertices."""
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            nc.nc_id = "{self.blueprint_id_v2.hex()}"
            nc.nc_method = initialize()
            nc.nc_deposit = 1.00 HTR
            nc.token_amount_version = V2

            nc <-- b11
            b11 < b12
        ''')
        artifacts.propagate_with(self.manager)
        nc = artifacts.get_typed_vertex('nc', Transaction)

        assert nc.is_nano_contract()
        assert nc.get_token_amount_version() == TokenAmountVersion.V2

        # When the feature is inactive the params allow only V1, so the gate rejects the V2 nano tx.
        features = dataclasses.replace(Features.all_enabled(), token_amount_version=TokenAmountVersion.V1)
        params = VerificationParams(nc_block_root_id=None, features=features)
        with pytest.raises(TxValidationError, match=re.escape('invalid token amount version: V2')):
            self.manager.verification_service.verifiers.tx.verify_token_amount_version(nc, params)

    def test_reorg_deactivating_feature_voids_v2_nano_tx(self) -> None:
        """A reorg that moves the best chain below activation voids a confirmed V2 nano tx. Pins the consensus
        reorg rule applied to nano txs."""
        feature_settings = FeatureSettings(
            evaluation_interval=4,
            default_threshold=3,
            features={
                Feature.TOKEN_AMOUNT_V2: Criteria(
                    bit=0,
                    start_height=4,
                    timeout_height=12,
                    signal_support_by_default=True,
                    version='0.0.0',
                ),
            },
        )
        settings = self._settings.model_copy(update=dict(
            ENABLE_TOKEN_AMOUNT_V2=FeatureSetting.FEATURE_ACTIVATION,
            FEATURE_ACTIVATION=feature_settings,
        ))
        daa_factory = DAAFactory(settings=settings, test_mode=TestMode.TEST_ALL_WEIGHT)
        builder = self.get_builder(settings).set_daa_factory(daa_factory)
        manager = self.create_peer_from_builder(builder)
        feature_service = manager.feature_service
        bit_signaling_service = manager._bit_signaling_service
        dag_builder = TestDAGBuilder.from_manager(manager)

        blueprint_id = BlueprintId(self.rng.randbytes(32))
        manager.blueprint_service.register_blueprint(
            blueprint_id, MyBlueprint, token_amount_version=TokenAmountVersion.V2
        )

        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..13]
            blockchain b10 a[11..11]

            nc1.nc_id = "{blueprint_id.hex()}"
            nc1.nc_method = initialize()
            nc1.nc_deposit = 1.00 HTR
            nc1.token_amount_version = V2
            nc1 <-- b13

            b12 < dummy < nc1 < b13 < a11
            a11.weight = 20
        ''')
        b12, b13, a11 = artifacts.get_typed_vertices(('b12', 'b13', 'a11'), Block)
        nc1, = artifacts.get_typed_vertices(('nc1',), Transaction)

        artifacts.propagate_with(manager, up_to='b4')
        for block_name in ('b5', 'b6', 'b7'):
            block = artifacts.by_name[block_name].vertex
            assert isinstance(block, Block)
            block.storage = manager.tx_storage
            block.signal_bits = bit_signaling_service.generate_signal_bits(block=block.get_block_parent())
            artifacts.propagate_with(manager, up_to=block_name)

        artifacts.propagate_with(manager, up_to='b12')
        assert feature_service.get_state(block=b12, feature=Feature.TOKEN_AMOUNT_V2) == FeatureState.ACTIVE

        # The V2 nano tx is accepted while the feature is active, then confirmed by b13.
        artifacts.propagate_with(manager, up_to='nc1')
        assert nc1.get_metadata().validation.is_valid()
        assert nc1.get_metadata().voided_by is None

        artifacts.propagate_with(manager, up_to='b13')
        assert nc1.get_metadata().nc_execution == NCExecutionState.SUCCESS

        # A heavier side chain reorgs the best block down to height 11, where the feature is not active.
        artifacts.propagate_with(manager, up_to='a11')
        assert a11.get_metadata().validation.is_valid()
        assert a11.get_metadata().voided_by is None
        assert feature_service.get_state(block=a11, feature=Feature.TOKEN_AMOUNT_V2) != FeatureState.ACTIVE
        assert b13.get_metadata().validation.is_invalid()
        assert nc1.get_metadata().validation.is_invalid()

        # The voided V2 nano tx is removed from storage and from the mempool tips.
        assert not manager.tx_storage.transaction_exists(nc1.hash)
        assert nc1 not in list(manager.tx_storage.iter_mempool_tips())

    def test_token_created_v2_deposited_by_v1_tx_uses_tx_version(self) -> None:
        """A token minted by a V2 token-creation tx is later deposited by a V1 nano tx into a V1 contract; assert
        the deposit is interpreted in the depositing TX's version (token's own creation version is irrelevant to
        accounting) and no cross-version error is raised."""
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..13]
            b10 < dummy

            tka.out[0] = 50.00 TKA
            tka.token_amount_version = V2
            TKA.token_amount_version = V2

            nc_init.nc_id = "{self.blueprint_id_v1.hex()}"
            nc_init.nc_method = initialize()

            tka.out[0] <<< nc_dep
            nc_dep.nc_id = nc_init
            nc_dep.nc_method = nop()
            nc_dep.nc_deposit = 50.00 TKA

            nc_init <-- b11
            b11 < tka
            tka <-- nc_dep
            nc_dep <-- b12
            b12 < b13
        ''')
        artifacts.propagate_with(self.manager)
        tka = artifacts.get_typed_vertex('TKA', Transaction)
        nc_init, nc_dep = artifacts.get_typed_vertices(('nc_init', 'nc_dep'), Transaction)

        # The token was created by a V2 tx, but the depositing tx is V1 and its deposit action is read as V1.
        assert tka.get_token_amount_version() == TokenAmountVersion.V2
        assert nc_dep.get_token_amount_version() == TokenAmountVersion.V1
        deposit_action = nc_dep.get_nano_header().nc_actions[0]
        assert deposit_action.amount.is_v1()

        # No cross-version error: the V1 tx over the V1 contract executes successfully.
        assert nc_dep.get_metadata().voided_by is None
        assert nc_dep.get_metadata().nc_execution == NCExecutionState.SUCCESS

        tka_key = BalanceKey(nc_id=nc_init.hash, token_uid=tka.hash)
        balances = self.manager.get_best_block_nc_storage(nc_init.hash).get_all_balances()
        assert balances == {
            tka_key: Balance(value=UnsignedAmount.from_v1(5000).to_signed(), can_mint=False, can_melt=False),
        }
