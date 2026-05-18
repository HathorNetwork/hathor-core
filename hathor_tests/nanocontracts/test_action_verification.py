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

import pytest

from hathor import HATHOR_TOKEN_UID, Blueprint, Context, public
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathorlib.nanocontracts.exception import NCInvalidAction
from hathorlib.nanocontracts.types import (
    ContractId,
    NCAcquireAuthorityAction,
    NCAction,
    NCDepositAction,
    NCGrantAuthorityAction,
    NCWithdrawalAction,
    TokenUid,
)
from hathorlib.nanocontracts.verification import MAX_ACTIONS_LEN, verify_action_list

TOKEN_UID_1 = TokenUid(b'1')
TOKEN_UID_2 = TokenUid(b'2')

# Actions for TOKEN_UID_1
DEPOSIT_1 = NCDepositAction(token_uid=TOKEN_UID_1, amount=100)
WITHDRAWAL_1 = NCWithdrawalAction(token_uid=TOKEN_UID_1, amount=100)

# Actions for TOKEN_UID_2
DEPOSIT_2 = NCDepositAction(token_uid=TOKEN_UID_2, amount=100)
WITHDRAWAL_2 = NCWithdrawalAction(token_uid=TOKEN_UID_2, amount=100)
GRANT_2 = NCGrantAuthorityAction(token_uid=TOKEN_UID_2, mint=True, melt=True)
ACQUIRE_2 = NCAcquireAuthorityAction(token_uid=TOKEN_UID_2, mint=True, melt=True)


@pytest.mark.parametrize(
    ['actions', 'restrict_dup_actions'],
    [
        # Empty list
        ([], True),
        ([], False),
        # Single actions
        ([DEPOSIT_1], True),
        ([WITHDRAWAL_1], True),
        ([GRANT_2], True),
        ([ACQUIRE_2], True),
        ([DEPOSIT_1], False),
        ([WITHDRAWAL_1], False),
        ([GRANT_2], False),
        ([ACQUIRE_2], False),
        # Allowed pairs (same token)
        ([DEPOSIT_2, GRANT_2], True),
        ([DEPOSIT_2, ACQUIRE_2], True),
        ([WITHDRAWAL_2, GRANT_2], True),
        ([WITHDRAWAL_2, ACQUIRE_2], True),
        ([DEPOSIT_2, GRANT_2], False),
        ([DEPOSIT_2, ACQUIRE_2], False),
        ([WITHDRAWAL_2, GRANT_2], False),
        ([WITHDRAWAL_2, ACQUIRE_2], False),
        # Different tokens: each token has a valid action set independently
        ([DEPOSIT_1, DEPOSIT_2], True),
        ([DEPOSIT_1, WITHDRAWAL_2], True),
        ([WITHDRAWAL_1, DEPOSIT_2], True),
        ([WITHDRAWAL_1, WITHDRAWAL_2], True),
        ([DEPOSIT_1, GRANT_2], True),
        ([DEPOSIT_1, ACQUIRE_2], True),
        ([WITHDRAWAL_1, GRANT_2], True),
        ([WITHDRAWAL_1, ACQUIRE_2], True),
        # Multiple tokens with allowed pairs
        ([DEPOSIT_1, DEPOSIT_2, GRANT_2], True),
        ([DEPOSIT_1, WITHDRAWAL_2, ACQUIRE_2], True),
        ([WITHDRAWAL_1, DEPOSIT_2, ACQUIRE_2], True),
        # Duplicate action types allowed when restrict_dup_actions=False
        ([DEPOSIT_1, DEPOSIT_1], False),
        ([WITHDRAWAL_1, WITHDRAWAL_1], False),
        ([GRANT_2, GRANT_2], False),
        ([ACQUIRE_2, ACQUIRE_2], False),
        # Duplicates within an allowed pair allowed when restrict_dup_actions=False
        ([DEPOSIT_2, DEPOSIT_2, GRANT_2], False),
        ([DEPOSIT_2, GRANT_2, GRANT_2], False),
        ([DEPOSIT_2, DEPOSIT_2, ACQUIRE_2], False),
        ([DEPOSIT_2, ACQUIRE_2, ACQUIRE_2], False),
        ([WITHDRAWAL_2, WITHDRAWAL_2, GRANT_2], False),
        ([WITHDRAWAL_2, GRANT_2, GRANT_2], False),
        ([WITHDRAWAL_2, WITHDRAWAL_2, ACQUIRE_2], False),
        ([WITHDRAWAL_2, ACQUIRE_2, ACQUIRE_2], False),
    ]
)
def test_verify_action_list_success(actions: list[NCAction], restrict_dup_actions: bool) -> None:
    verify_action_list(actions, restrict_dup_actions=restrict_dup_actions)


@pytest.mark.parametrize(
    ['actions', 'restrict_dup_actions'],
    [
        # Conflicting pairs (same token) — fails regardless of restrict_dup_actions
        ([DEPOSIT_1, WITHDRAWAL_1], True),
        ([WITHDRAWAL_1, DEPOSIT_1], True),
        ([GRANT_2, ACQUIRE_2], True),
        ([ACQUIRE_2, GRANT_2], True),
        ([DEPOSIT_1, WITHDRAWAL_1], False),
        ([WITHDRAWAL_1, DEPOSIT_1], False),
        ([GRANT_2, ACQUIRE_2], False),
        ([ACQUIRE_2, GRANT_2], False),
        # Three distinct action types on the same token — fails regardless of restrict_dup_actions
        ([DEPOSIT_2, GRANT_2, ACQUIRE_2], True),
        ([WITHDRAWAL_2, GRANT_2, ACQUIRE_2], True),
        ([DEPOSIT_2, WITHDRAWAL_2, GRANT_2], True),
        ([DEPOSIT_2, WITHDRAWAL_2, ACQUIRE_2], True),
        ([DEPOSIT_2, GRANT_2, ACQUIRE_2], False),
        ([WITHDRAWAL_2, GRANT_2, ACQUIRE_2], False),
        ([DEPOSIT_2, WITHDRAWAL_2, GRANT_2], False),
        ([DEPOSIT_2, WITHDRAWAL_2, ACQUIRE_2], False),
        # All four action types on the same token — fails regardless of restrict_dup_actions
        ([DEPOSIT_2, WITHDRAWAL_2, GRANT_2, ACQUIRE_2], True),
        ([DEPOSIT_2, WITHDRAWAL_2, GRANT_2, ACQUIRE_2], False),
        # Valid on one token but conflicting on another — fails regardless of restrict_dup_actions
        ([DEPOSIT_1, DEPOSIT_2, WITHDRAWAL_2], True),
        ([DEPOSIT_1, DEPOSIT_2, WITHDRAWAL_2], False),
    ]
)
def test_verify_action_list_conflicting_error(actions: list[NCAction], restrict_dup_actions: bool) -> None:
    with pytest.raises(NCInvalidAction, match='conflicting actions for token'):
        verify_action_list(actions, restrict_dup_actions=restrict_dup_actions)


@pytest.mark.parametrize(
    'actions',
    [
        # Duplicate action types (same token)
        [DEPOSIT_1, DEPOSIT_1],
        [WITHDRAWAL_1, WITHDRAWAL_1],
        [GRANT_2, GRANT_2],
        [ACQUIRE_2, ACQUIRE_2],
        # Duplicates within an allowed pair (type set is allowed, but repeated actions)
        [DEPOSIT_2, DEPOSIT_2, GRANT_2],
        [DEPOSIT_2, GRANT_2, GRANT_2],
        [DEPOSIT_2, DEPOSIT_2, ACQUIRE_2],
        [DEPOSIT_2, ACQUIRE_2, ACQUIRE_2],
        [WITHDRAWAL_2, WITHDRAWAL_2, GRANT_2],
        [WITHDRAWAL_2, GRANT_2, GRANT_2],
        [WITHDRAWAL_2, WITHDRAWAL_2, ACQUIRE_2],
        [WITHDRAWAL_2, ACQUIRE_2, ACQUIRE_2],
    ]
)
def test_verify_action_list_duplicate_error(actions: list[NCAction]) -> None:
    with pytest.raises(NCInvalidAction, match='duplicate actions for token'):
        verify_action_list(actions, restrict_dup_actions=True)


def test_verify_action_list_max_actions_boundary() -> None:
    actions = [NCDepositAction(token_uid=TokenUid(i.to_bytes(1, 'big')), amount=1) for i in range(MAX_ACTIONS_LEN)]
    verify_action_list(actions, restrict_dup_actions=True)


def test_verify_action_list_too_many_actions() -> None:
    actions = [NCDepositAction(token_uid=TokenUid(i.to_bytes(1, 'big')), amount=1) for i in range(MAX_ACTIONS_LEN + 1)]
    with pytest.raises(NCInvalidAction, match='more actions than the max allowed'):
        verify_action_list(actions, restrict_dup_actions=True)


class MyBlueprint(Blueprint):
    @public(allow_deposit=True)
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def call_another_conflicting_actions(self, ctx: Context, other_id: ContractId) -> None:
        contract = self.syscall.get_contract(other_id, blueprint_id=self.syscall.get_blueprint_id())
        deposit = NCDepositAction(token_uid=HATHOR_TOKEN_UID, amount=100)
        withdrawal = NCWithdrawalAction(token_uid=HATHOR_TOKEN_UID, amount=100)
        contract.public(deposit, withdrawal).nop()

    @public
    def call_another_duplicate_actions(self, ctx: Context, other_id: ContractId) -> None:
        contract = self.syscall.get_contract(other_id, blueprint_id=self.syscall.get_blueprint_id())
        deposit = NCDepositAction(token_uid=HATHOR_TOKEN_UID, amount=100)
        contract.public(deposit, deposit).nop()

    @public(allow_deposit=True, allow_withdrawal=True)
    def nop(self, ctx: Context) -> None:
        pass


class TestInterContractVerification(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.blueprint_id = self._register_blueprint_class(MyBlueprint)
        self.contract_id1 = self.gen_random_contract_id()
        self.contract_id2 = self.gen_random_contract_id()

        deposit = NCDepositAction(token_uid=HATHOR_TOKEN_UID, amount=200)
        ctx = self.create_context(actions=[deposit])
        self.runner.create_contract(self.contract_id1, self.blueprint_id, ctx)
        self.runner.create_contract(self.contract_id2, self.blueprint_id, ctx)

    def test_conflicting_actions(self) -> None:
        with pytest.raises(NCInvalidAction, match='conflicting actions for token 00'):
            self.runner.call_public_method(
                self.contract_id1, 'call_another_conflicting_actions', self.create_context(), self.contract_id2
            )

    def test_duplicate_actions(self) -> None:
        with pytest.raises(NCInvalidAction, match='duplicate actions for token 00'):
            self.runner.call_public_method(
                self.contract_id1, 'call_another_duplicate_actions', self.create_context(), self.contract_id2
            )
