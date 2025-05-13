#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from __future__ import annotations

from abc import ABC, abstractmethod

from typing_extensions import assert_never, override

from hathor.conf.settings import HathorSettings
from hathor.nanocontracts.storage import NCChangesTracker
from hathor.nanocontracts.types import NCAction, NCActionType
from hathor.transaction.transaction import TokenInfo
from hathor.types import TokenUid


class BalanceRules(ABC):
    """
    An abstract base class that unifies balance rules for NCActions.

    Requires definitions for a verification-phase rule and a nano contract execution-phase rule,
    which are normally complementary.
    """

    __slots__ = ('settings', 'action')

    def __init__(self, settings: HathorSettings, action: NCAction) -> None:
        self.settings = settings
        self.action = action

    @abstractmethod
    def verification_rule(self, token_dict: dict[TokenUid, TokenInfo]) -> None:
        """
        Define how the respective action interacts with the transaction's
        token_dict during the verification phase, updating it.
        """
        raise NotImplementedError

    @abstractmethod
    def nc_execution_rule(self, changes_tracker: NCChangesTracker) -> None:
        """
        Define how the respective action interacts with the transaction's
        changes tracker during nano contract execution, updating it.
        """
        raise NotImplementedError

    @staticmethod
    def get_rules(settings: HathorSettings, action: NCAction) -> BalanceRules:
        """Get the balance rules instance for the provided action."""
        match action.type:
            case NCActionType.DEPOSIT:
                return _DepositRules(settings, action)
            case NCActionType.WITHDRAWAL:
                return _WithdrawalRules(settings, action)
            case _:
                assert_never(action)


class _DepositRules(BalanceRules):
    """
    Define balance rules for the DEPOSIT action.

    - In the verification-phase, the amount is removed from the tx inputs/outputs balance.
    - In the execution-phase, the amount is added to the nano contract balance.
    """

    @override
    def verification_rule(self, token_dict: dict[TokenUid, TokenInfo]) -> None:
        token_info = token_dict.get(self.action.token_uid, TokenInfo.get_default())
        token_dict[self.action.token_uid] = token_info._replace(
            amount=token_info.amount + self.action.amount,
        )

    @override
    def nc_execution_rule(self, changes_tracker: NCChangesTracker) -> None:
        changes_tracker.add_balance(self.action.token_uid, self.action.amount)


class _WithdrawalRules(BalanceRules):
    """
    Define balance rules for the WITHDRAWAL action.

    - In the verification-phase, the amount is added to the tx inputs/outputs balance.
    - In the execution-phase, the amount is removed from the nano contract balance.
    """

    @override
    def verification_rule(self, token_dict: dict[TokenUid, TokenInfo]) -> None:
        token_info = token_dict.get(self.action.token_uid, TokenInfo.get_default())
        token_dict[self.action.token_uid] = token_info._replace(
            amount=token_info.amount - self.action.amount,
        )

    @override
    def nc_execution_rule(self, changes_tracker: NCChangesTracker) -> None:
        changes_tracker.add_balance(self.action.token_uid, -self.action.amount)
