#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import re
import textwrap

import pytest

from hathor import Blueprint, Context, public
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.nanocontracts import NC_EXECUTION_FAIL_ID
from hathor.nanocontracts.nc_exec_logs import NCLogConfig
from hathor.transaction import Block, Transaction
from hathor.transaction.headers.nano_header import NanoHeaderAction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathor_tests.nanocontracts.utils import assert_nc_failure_reason
from hathorlib.conf.settings import FeatureSetting
from hathorlib.nanocontracts.exception import NCFail
from hathorlib.nanocontracts.types import (
    BlueprintId,
    ContractId,
    NCActionType,
    NCDepositAction,
    NCWithdrawalAction,
    TokenUid,
)
from hathorlib.nanocontracts.versions import BlueprintVersion

TOKEN_UID1 = TokenUid(b'\x01')
TOKEN_UID2 = TokenUid(b'\x02')
ACTION_11 = NCDepositAction(token_uid=TOKEN_UID1, amount=100)
ACTION_12 = NCWithdrawalAction(token_uid=TOKEN_UID1, amount=100)
ACTION_21 = NCDepositAction(token_uid=TOKEN_UID2, amount=100)


class MyBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def get_blueprint_version(self, ctx: Context) -> None:
        assert ctx.blueprint_version == BlueprintVersion.V2

    @public(allow_deposit=True, allow_withdrawal=True)
    def get_actions(self, ctx: Context) -> None:
        assert ctx.actions == {
            TOKEN_UID1: (ACTION_11, ACTION_12),
            TOKEN_UID2: (ACTION_21,),
        }

    @public(allow_deposit=True, allow_withdrawal=True)
    def get_actions_by_token(self, ctx: Context, is_v2: bool) -> None:
        assert ctx.actions_by_token == {
            TOKEN_UID1: (ACTION_11, ACTION_12),
            TOKEN_UID2: (ACTION_21,),
        }
        if is_v2:
            for action in ctx.all_actions:
                ctx.authorize(action)

    @public(allow_deposit=True, allow_withdrawal=True)
    def get_actions_list(self, ctx: Context) -> None:
        assert ctx.actions_list == (ACTION_11, ACTION_12, ACTION_21)

    @public(allow_deposit=True, allow_withdrawal=True)
    def get_all_actions(self, ctx: Context, is_v2: bool) -> None:
        assert ctx.all_actions == (ACTION_11, ACTION_12, ACTION_21)
        if is_v2:
            for action in ctx.all_actions:
                ctx.authorize(action)

    @public(allow_deposit=True, allow_withdrawal=True)
    def get_single_action(self, ctx: Context, is_v2: bool) -> None:
        ctx.get_single_action(TOKEN_UID1)
        if is_v2:
            for action in ctx.all_actions:
                ctx.authorize(action)

    @public(allow_deposit=True, allow_withdrawal=True)
    def get_token_single_action(self, ctx: Context, is_v2: bool) -> None:
        ctx.get_token_single_action(TOKEN_UID1)
        if is_v2:
            for action in ctx.all_actions:
                ctx.authorize(action)

    @public(allow_deposit=True, allow_withdrawal=True)
    def try_authorize(self, ctx: Context) -> None:
        ctx.authorize(ctx.actions_list[0])

    @public(allow_deposit=True, allow_withdrawal=True)
    def try_is_authorized(self, ctx: Context) -> None:
        ctx.is_authorized(ctx.actions_list[0])

    @public(allow_deposit=True, allow_withdrawal=True)
    def authorize_all(self, ctx: Context) -> None:
        for action in ctx.all_actions:
            ctx.authorize(action)

    @public(allow_deposit=True, allow_withdrawal=True)
    def duplicate_authorize(self, ctx: Context) -> None:
        action = ctx.all_actions[0]
        ctx.authorize(action)
        ctx.authorize(action)

    @public(allow_deposit=True, allow_withdrawal=True)
    def check_is_authorized(self, ctx: Context) -> None:
        action = ctx.all_actions[0]
        assert not ctx.is_authorized(action)
        ctx.authorize(action)
        assert ctx.is_authorized(action)
        for action in ctx.all_actions[1:]:
            ctx.authorize(action)

    @public(allow_deposit=True, allow_withdrawal=True)
    def no_authorize(self, ctx: Context) -> None:
        pass

    @public(allow_deposit=True, allow_withdrawal=True)
    def partial_authorize(self, ctx: Context) -> None:
        assert len(ctx.all_actions) > 1
        ctx.authorize(ctx.all_actions[0])

    @public(allow_deposit=True, allow_withdrawal=True)
    def call_another_no_no(self, ctx: Context, other_id: ContractId) -> None:
        contract = self.syscall.get_contract(other_id, blueprint_id=self.syscall.get_blueprint_id())
        contract.public(*ctx.all_actions).no_authorize()

    @public(allow_deposit=True, allow_withdrawal=True)
    def call_another_no_all(self, ctx: Context, other_id: ContractId) -> None:
        contract = self.syscall.get_contract(other_id, blueprint_id=self.syscall.get_blueprint_id())
        contract.public(*ctx.all_actions).authorize_all()

    @public(allow_deposit=True, allow_withdrawal=True)
    def call_another_all_no(self, ctx: Context, other_id: ContractId) -> None:
        contract = self.syscall.get_contract(other_id, blueprint_id=self.syscall.get_blueprint_id())
        self.authorize_all(ctx)
        contract.public(*ctx.all_actions).no_authorize()

    @public(allow_deposit=True, allow_withdrawal=True)
    def call_another_all_all(self, ctx: Context, other_id: ContractId) -> None:
        contract = self.syscall.get_contract(other_id, blueprint_id=self.syscall.get_blueprint_id())
        self.authorize_all(ctx)
        contract.public(*ctx.all_actions).authorize_all()


class TestBlueprintV2(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.contract_id = self.gen_random_contract_id()

    def _create_contract_v1(self) -> None:
        blueprint_id = self._register_blueprint_class(MyBlueprint, blueprint_version=BlueprintVersion.V1)
        self.runner.create_contract(self.contract_id, blueprint_id, self.create_context())

    def _create_contract_v2(self) -> BlueprintId:
        blueprint_id = self._register_blueprint_class(MyBlueprint, blueprint_version=BlueprintVersion.V2)
        self.runner.create_contract(self.contract_id, blueprint_id, self.create_context())
        return blueprint_id

    def test_get_blueprint_version_v1(self) -> None:
        self._create_contract_v1()
        with pytest.raises(NCFail, match='`Context.blueprint_version` is not supported yet.'):
            self.runner.call_public_method(self.contract_id, 'get_blueprint_version', self.create_context())

    def test_get_blueprint_version_v2(self) -> None:
        self._create_contract_v2()
        self.runner.call_public_method(self.contract_id, 'get_blueprint_version', self.create_context())

    def test_get_actions_v1(self) -> None:
        self._create_contract_v1()
        ctx = self.create_context(actions=[ACTION_11, ACTION_12, ACTION_21])
        self.runner.call_public_method(self.contract_id, 'get_actions', ctx)

    def test_get_actions_v2(self) -> None:
        self._create_contract_v2()
        msg = '`Context.actions` has been deprecated. Use `Context.actions_by_token` instead.'
        with pytest.raises(NCFail, match=msg):
            self.runner.call_public_method(self.contract_id, 'get_actions', self.create_context())

    def test_get_actions_by_token_v1(self) -> None:
        self._create_contract_v1()
        with pytest.raises(NCFail, match='`Context.actions_by_token` is not supported yet.'):
            self.runner.call_public_method(
                self.contract_id, 'get_actions_by_token', self.create_context(), is_v2=False
            )

    def test_get_actions_by_token_v2(self) -> None:
        self._create_contract_v2()
        ctx = self.create_context(actions=[ACTION_11, ACTION_12, ACTION_21])
        self.runner.call_public_method(self.contract_id, 'get_actions_by_token', ctx, is_v2=True)

    def test_get_actions_list_v1(self) -> None:
        self._create_contract_v1()
        ctx = self.create_context(actions=[ACTION_11, ACTION_12, ACTION_21])
        self.runner.call_public_method(self.contract_id, 'get_actions_list', ctx)

    def test_get_actions_list_v2(self) -> None:
        self._create_contract_v2()
        msg = '`Context.actions_list` has been deprecated. Use `Context.all_actions` instead.'
        with pytest.raises(NCFail, match=msg):
            self.runner.call_public_method(self.contract_id, 'get_actions_list', self.create_context())

    def test_get_all_actions_v1(self) -> None:
        self._create_contract_v1()
        with pytest.raises(NCFail, match='`Context.all_actions` is not supported yet.'):
            self.runner.call_public_method(self.contract_id, 'get_all_actions', self.create_context(), is_v2=False)

    def test_get_all_actions_v2(self) -> None:
        self._create_contract_v2()
        ctx = self.create_context(actions=[ACTION_11, ACTION_12, ACTION_21])
        self.runner.call_public_method(self.contract_id, 'get_all_actions', ctx, is_v2=True)

    def test_get_single_action_v1(self) -> None:
        self._create_contract_v1()

        # no actions
        with pytest.raises(NCFail, match='expected exactly 1 action for token 01'):
            self.runner.call_public_method(self.contract_id, 'get_single_action', self.create_context(), is_v2=False)

        # multiple actions on one token
        ctx = self.create_context(actions=[ACTION_11, ACTION_12])
        with pytest.raises(NCFail, match='expected exactly 1 action for token 01'):
            self.runner.call_public_method(self.contract_id, 'get_single_action', ctx, is_v2=False)

        # single action on one token
        # this passes, which is the behavior that is changed in V2 (see `test_get_single_action_v2` below)
        ctx = self.create_context(actions=[ACTION_11, ACTION_21])
        self.runner.call_public_method(self.contract_id, 'get_single_action', ctx, is_v2=False)

        # single action on whole context
        ctx = self.create_context(actions=[ACTION_11])
        self.runner.call_public_method(self.contract_id, 'get_single_action', ctx, is_v2=False)

    def test_get_single_action_v2(self) -> None:
        self._create_contract_v2()

        # no actions
        with pytest.raises(NCFail, match='expected exactly 1 action in the whole Context, for token 01'):
            self.runner.call_public_method(self.contract_id, 'get_single_action', self.create_context(), is_v2=True)

        # multiple actions on one token
        ctx = self.create_context(actions=[ACTION_11, ACTION_12])
        with pytest.raises(NCFail, match='expected exactly 1 action in the whole Context, for token 01'):
            self.runner.call_public_method(self.contract_id, 'get_single_action', ctx, is_v2=True)

        # single action on one token
        ctx = self.create_context(actions=[ACTION_11, ACTION_21])
        with pytest.raises(NCFail, match='expected exactly 1 action in the whole Context, for token 01'):
            self.runner.call_public_method(self.contract_id, 'get_single_action', ctx, is_v2=True)

        # single action on whole context
        ctx = self.create_context(actions=[ACTION_11])
        self.runner.call_public_method(self.contract_id, 'get_single_action', ctx, is_v2=True)

    def test_get_token_single_action_v1(self) -> None:
        self._create_contract_v1()
        with pytest.raises(NCFail, match='`Context.get_token_single_action` is not supported yet.'):
            self.runner.call_public_method(
                self.contract_id, 'get_token_single_action', self.create_context(), is_v2=False
            )

    def test_get_token_single_action_v2(self) -> None:
        self._create_contract_v2()

        # no actions
        with pytest.raises(NCFail, match='expected exactly 1 action for token 01'):
            self.runner.call_public_method(
                self.contract_id, 'get_token_single_action', self.create_context(), is_v2=True
            )

        # multiple actions on one token
        ctx = self.create_context(actions=[ACTION_11, ACTION_12])
        with pytest.raises(NCFail, match='expected exactly 1 action for token 01'):
            self.runner.call_public_method(self.contract_id, 'get_token_single_action', ctx, is_v2=True)

        # single action on one token
        # this passes, which mimics the legacy behavior (V1) of `get_single_action`
        ctx = self.create_context(actions=[ACTION_11, ACTION_21])
        self.runner.call_public_method(self.contract_id, 'get_token_single_action', ctx, is_v2=True)

        # single action on whole context
        ctx = self.create_context(actions=[ACTION_11])
        self.runner.call_public_method(self.contract_id, 'get_token_single_action', ctx, is_v2=True)

    def test_action_authorization_v1(self) -> None:
        self._create_contract_v1()

        # test `authorize()` is not supported
        ctx = self.create_context(actions=[ACTION_11])
        with pytest.raises(NCFail, match=re.escape('`Context.authorize` is not supported yet.')):
            self.runner.call_public_method(self.contract_id, 'try_authorize', ctx)

        # test `is_authorized()` is not supported
        ctx = self.create_context(actions=[ACTION_11])
        with pytest.raises(NCFail, match=re.escape('`Context.is_authorized` is not supported yet.')):
            self.runner.call_public_method(self.contract_id, 'try_is_authorized', ctx)

        # test that V1 doesn't need authorization
        ctx = self.create_context(actions=[ACTION_11])
        self.runner.call_public_method(self.contract_id, 'no_authorize', ctx)

    def test_action_authorization_v2(self) -> None:
        self._create_contract_v2()

        # test duplicate authorization
        ctx = self.create_context(actions=[ACTION_11])
        msg = re.escape("action is already authorized: NCDepositAction(token_uid=b'\\x01', amount=100)")
        with pytest.raises(NCFail, match=msg):
            self.runner.call_public_method(self.contract_id, 'duplicate_authorize', ctx)

        # test `is_authorized()` returns correct values before and after authorizing
        ctx = self.create_context(actions=[ACTION_11, ACTION_21])
        self.runner.call_public_method(self.contract_id, 'check_is_authorized', ctx)

        # test that unauthorized actions don't succeed
        ctx = self.create_context(actions=[ACTION_11])
        msg = re.escape("unauthorized action: NCDepositAction(token_uid=b'\\x01', amount=100)")
        with pytest.raises(NCFail, match=msg):
            self.runner.call_public_method(self.contract_id, 'no_authorize', ctx)

        # test that partially authorized actions don't succeed
        ctx = self.create_context(actions=[ACTION_11, ACTION_12])
        msg = re.escape("unauthorized action: NCWithdrawalAction(token_uid=b'\\x01', amount=100)")
        with pytest.raises(NCFail, match=msg):
            self.runner.call_public_method(self.contract_id, 'partial_authorize', ctx)

    def test_action_authorization_on_another_v2(self) -> None:
        blueprint_id = self._create_contract_v2()
        other_id = self.gen_random_contract_id()
        self.runner.create_contract(other_id, blueprint_id, self.create_context())
        self.create_token(token_uid=TOKEN_UID1, token_name='Token1', token_symbol='TK1')
        self.create_token(token_uid=TOKEN_UID2, token_name='Token2', token_symbol='TK2')

        ctx = self.create_context(actions=[ACTION_11, ACTION_12, ACTION_21])

        msg = re.escape("unauthorized action: NCDepositAction(token_uid=b'\\x01', amount=100)")
        with pytest.raises(NCFail, match=msg):
            self.runner.call_public_method(self.contract_id, 'call_another_no_no', ctx, other_id)

        with pytest.raises(NCFail, match=msg):
            self.runner.call_public_method(self.contract_id, 'call_another_no_all', ctx, other_id)

        with pytest.raises(NCFail, match=msg):
            self.runner.call_public_method(self.contract_id, 'call_another_all_no', ctx, other_id)

        self.runner.call_public_method(self.contract_id, 'call_another_all_all', ctx, other_id)

    def test_activation(self) -> None:
        feature_settings = FeatureSettings(
            evaluation_interval=4,
            default_threshold=3,
            features={
                Feature.BLUEPRINT_V2: Criteria(
                    bit=0,
                    start_height=4,
                    timeout_height=12,
                    version='0.0.0'
                )
            }
        )
        settings = self._settings.copy(update=dict(
            ENABLE_BLUEPRINT_V2=FeatureSetting.FEATURE_ACTIVATION,
            FEATURE_ACTIVATION=feature_settings,
        ))

        self.manager = self.create_peer('unittests', nc_log_config=NCLogConfig.FAILED, settings=settings)
        feature_service = self.manager.feature_service

        ocb_code = textwrap.dedent('''
            from hathor import Blueprint, Context, export, public, HATHOR_TOKEN_UID
            @export
            class MyBlueprint(Blueprint):
                @public(allow_deposit=True, allow_withdrawal=True)
                def initialize(self, ctx: Context) -> None:
                    ctx.get_single_action(HATHOR_TOKEN_UID)
        ''')
        ocb_code = ocb_code.encode().hex()

        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..13]
            b10 < dummy

            b5.signal_bits = 1
            b6.signal_bits = 1
            b7.signal_bits = 1

            ocb1.ocb_private_key = "{private_key}"
            ocb1.ocb_password = "{password}"

            ocb2.ocb_private_key = "{private_key}"
            ocb2.ocb_password = "{password}"

            ocb1 <-- b12
            ocb2 <-- b13

            nc1.nc_id = ocb1
            nc1.nc_method = initialize()
            nc1.nc_deposit = 100 HTR
            nc1.nc_deposit = 100 TKA

            nc2.nc_id = ocb2
            nc2.nc_method = initialize()
            nc2.nc_deposit = 100 HTR
            nc2.nc_deposit = 100 TKA

            # Even though both nano txs are executed by the same block, their result
            # is different because the OCBs were confirmed by different blocks
            nc1 <-- nc2 <-- b13

            ocb1.ocb_code = "{ocb_code}"
            ocb2.ocb_code = "{ocb_code}"
        ''')
        artifacts.propagate_with(self.manager)

        b5, b6, b7, b11, b12, b13 = artifacts.get_typed_vertices(('b5', 'b6', 'b7', 'b11', 'b12', 'b13'), Block)
        ocb1, ocb2, nc1, nc2 = artifacts.get_typed_vertices(('ocb1', 'ocb2', 'nc1', 'nc2'), Transaction)

        assert feature_service.get_state(block=b7, feature=Feature.BLUEPRINT_V2) == FeatureState.STARTED
        assert feature_service.get_state(block=b11, feature=Feature.BLUEPRINT_V2) == FeatureState.LOCKED_IN
        assert feature_service.get_state(block=b12, feature=Feature.BLUEPRINT_V2) == FeatureState.ACTIVE

        assert ocb1.get_metadata().voided_by is None
        assert ocb2.get_metadata().voided_by is None

        # Blueprint V2 activation uses the first_block's parent state
        assert ocb1.get_metadata().first_block == b12.hash
        assert ocb2.get_metadata().first_block == b13.hash

        actions = [
            NanoHeaderAction(type=NCActionType.DEPOSIT, token_index=0, amount=100),
            NanoHeaderAction(type=NCActionType.DEPOSIT, token_index=1, amount=100),
        ]
        assert nc1.get_nano_header().nc_actions == actions
        assert nc2.get_nano_header().nc_actions == actions

        assert nc1.get_metadata().voided_by is None
        assert nc1.get_metadata().nc_execution == NCExecutionState.SUCCESS

        assert nc2.get_metadata().voided_by == {NC_EXECUTION_FAIL_ID, nc2.hash}
        assert nc2.get_metadata().nc_execution == NCExecutionState.FAILURE
        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=nc2.hash,
            block_id=b13.hash,
            reason='expected exactly 1 action in the whole Context, for token 00',
        )
