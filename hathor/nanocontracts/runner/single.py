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

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Type

from hathor.conf.get_settings import get_global_settings
from hathor.nanocontracts.balance_rules import BalanceRules
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.blueprint_env import BlueprintEnvironment
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCError, NCFail, NCInvalidContext, NCMethodNotFound, NCPrivateMethodError
from hathor.nanocontracts.metered_exec import MeteredExecutor, OutOfFuelError, OutOfMemoryError
from hathor.nanocontracts.storage import NCChangesTracker
from hathor.nanocontracts.types import BaseTokenAction
from hathor.nanocontracts.utils import is_nc_public_method, is_nc_view_method

if TYPE_CHECKING:
    from hathor.nanocontracts.nc_exec_logs import NCLogger
    from hathor.nanocontracts.runner.runner import Runner


class _SingleCallRunner:
    """This class is used to run a single method in a blueprint.

    You should not use this class unless you know what you are doing.
    """

    def __init__(
        self,
        runner: Runner,
        blueprint_class: Type[Blueprint],
        nanocontract_id: bytes,
        changes_tracker: NCChangesTracker,
        metered_executor: MeteredExecutor,
        nc_logger: NCLogger,
    ) -> None:
        self.runner = runner
        self.blueprint_class = blueprint_class
        self.nanocontract_id = nanocontract_id
        self.changes_tracker = changes_tracker
        self.metered_executor = metered_executor
        self._nc_logger = nc_logger
        self._has_been_called = False
        self._settings = get_global_settings()

    def validate_context(self, ctx: Context) -> None:
        """Validate if the context is valid."""
        for token_uid, actions in ctx.actions.items():
            for action in actions:
                if token_uid != action.token_uid:
                    raise NCInvalidContext('token_uid mismatch')
                if isinstance(action, BaseTokenAction) and action.amount < 0:
                    raise NCInvalidContext('amount must be positive')

    def _execute_actions(self, ctx: Context) -> None:
        """Update the contract balance according to the context actions."""
        for action in ctx.__all_actions__:
            rules = BalanceRules.get_rules(self._settings, action)
            rules.nc_execution_rule(self.changes_tracker)

    def call_public_method(self, method_name: str, ctx: Context, *args: Any, **kwargs: Any) -> Any:
        """Call a contract public method. If it fails, no change is saved."""

        assert not self._has_been_called, 'only one call to a method per instance'
        self._has_been_called = True

        self.validate_context(ctx)

        blueprint = self._create_blueprint()
        method = getattr(blueprint, method_name)
        if method is None:
            raise NCMethodNotFound(method_name)
        if not is_nc_public_method(method):
            raise NCError('not a public method')

        try:
            # Although the context is immutable, we're passing a copy to the blueprint method as an added precaution.
            # This ensures that, even if the blueprint method attempts to exploit or alter the context, it cannot
            # impact the original context. Since the runner relies on the context for other critical checks, any
            # unauthorized modification would pose a serious security risk.
            ret = self.metered_executor.call(method, ctx.copy(), *args, **kwargs)
        except NCFail:
            raise
        except OutOfFuelError as e:
            raise NCFail from e
        except OutOfMemoryError as e:
            raise NCFail from e
        except Exception as e:
            # Convert any other exception to NCFail.
            raise NCFail from e

        self._execute_actions(ctx)
        return ret

    def call_view_method(self, method_name: str, *args: Any, **kwargs: Any) -> Any:
        """Call a contract view method. It cannot change the state."""
        assert not self._has_been_called, 'only one call to a method per instance'
        self._has_been_called = True
        blueprint = self._create_blueprint()
        method = getattr(blueprint, method_name)
        if method is None:
            raise NCMethodNotFound(method_name)
        if not is_nc_view_method(method):
            raise NCError('not a view method')

        ret = self.metered_executor.call(method, *args, **kwargs)

        if not self.changes_tracker.is_empty():
            raise NCPrivateMethodError('view methods cannot change the state')

        return ret

    def _create_blueprint(self) -> Blueprint:
        """Create a new blueprint instance."""
        env = BlueprintEnvironment(self.runner, self.changes_tracker, self._nc_logger)
        return self.blueprint_class(env)
