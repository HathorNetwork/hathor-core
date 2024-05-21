# Copyright 2023 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from typing import Any, Type

from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.exception import (
    NCError,
    NCFail,
    NCInsufficientFunds,
    NCInvalidContext,
    NCMethodNotFound,
    NCPrivateMethodError,
)
from hathor.nanocontracts.storage import NCBaseStorage, NCChangesTracker
from hathor.nanocontracts.types import Context, NCAction, NCActionType


class Runner:
    """This class is used to run a method in a blueprint.
    """

    def __init__(self, blueprint_class: Type[Blueprint], nanocontract_id: bytes, storage: NCBaseStorage) -> None:
        self.blueprint_class = blueprint_class
        self.nanocontract_id = nanocontract_id
        self.storage = storage

    def get_nc_balance(self, token_id: bytes) -> int:
        """Return a Nano Contract balance for a given token."""
        return self.storage.get_balance(token_id)

    def add_nc_balance(self, token_uid: bytes, amount: int) -> None:
        """Add balance to a token. Notice that the amount might be negative."""
        self.storage.add_balance(token_uid, amount)

    def validate_withdrawal(self, action: NCAction) -> None:
        """Validate if the contract has enough funds for the withdrawal requests."""
        assert action.type == NCActionType.WITHDRAWAL
        balance = self.get_nc_balance(action.token_uid)
        if action.amount > balance:
            raise NCInsufficientFunds(f'withdrawal: {action.amount} / balance: {balance}')

    def validate_context(self, ctx: Context) -> None:
        """Validate if the context is valid."""
        for token_uid, action in ctx.actions.items():
            if token_uid != action.token_uid:
                raise NCInvalidContext('token_uid mismatch')
            if action.amount < 0:
                raise NCInvalidContext('amount must be positive')

            if action.type == NCActionType.WITHDRAWAL:
                self.validate_withdrawal(action)
            else:
                # Nothing to do.
                assert action.type == NCActionType.DEPOSIT

    def update_deposits_and_withdrawals(self, ctx: Context) -> None:
        """Update the contract balance according to deposits and withdrawals."""
        for action in ctx.actions.values():
            self.update_balance(action)

    def update_balance(self, action: NCAction) -> None:
        """Update the contract balance according to the given action."""
        if action.type == NCActionType.WITHDRAWAL:
            self.add_nc_balance(action.token_uid, -action.amount)
        else:
            assert action.type == NCActionType.DEPOSIT
            self.add_nc_balance(action.token_uid, action.amount)

    def call_public_method(self, method_name: str, ctx: Context, *args: Any) -> None:
        """Call a contract public method. If it fails, no change is saved."""
        from hathor.nanocontracts.utils import is_nc_public_method
        self.validate_context(ctx)

        storage = NCChangesTracker(self.nanocontract_id, self.storage)
        blueprint = self.blueprint_class(storage)
        method = getattr(blueprint, method_name)
        if method is None:
            raise NCMethodNotFound(method_name)
        if not is_nc_public_method(method):
            raise NCError('not a public method')

        try:
            method(ctx, *args)
        except NCFail:
            raise
        except Exception as e:
            # Convert any other exception to NCFail.
            raise NCFail from e

        # If no exception is raised, update the state.
        self.update_deposits_and_withdrawals(ctx)
        storage.commit()

    def call_private_method(self, method_name: str, *args: Any) -> Any:
        """Call a contract private method. It cannot change the state."""
        from hathor.nanocontracts.utils import is_nc_public_method
        storage = NCChangesTracker(self.nanocontract_id, self.storage)
        blueprint = self.blueprint_class(storage)
        method = getattr(blueprint, method_name)
        if method is None:
            raise NCMethodNotFound(method_name)
        if is_nc_public_method(method):
            raise NCError('not a private method')
        ret = method(*args)
        if not storage.is_empty():
            raise NCPrivateMethodError('private methods cannot change the state')
        return ret
