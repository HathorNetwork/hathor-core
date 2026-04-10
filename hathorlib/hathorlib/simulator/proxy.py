# Copyright 2026 Hathor Labs
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

"""ContractProxy — object-oriented wrapper for interacting with deployed contracts."""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Any

from hathorlib.nanocontracts.types import Address, ContractId, NCAction
from hathorlib.nanocontracts.utils import is_nc_public_method, is_nc_view_method

if TYPE_CHECKING:
    from hathorlib.nanocontracts import Blueprint
    from hathorlib.simulator.result import TxResult
    from hathorlib.simulator.simulator import Simulator


class ContractProxy:
    """Wraps a deployed contract and exposes its blueprint methods as regular Python methods.

    Public methods require ``caller`` as a keyword argument and return ``TxResult``.
    View methods take only positional args and return the view's return value directly.
    The ``initialize`` method is excluded from the proxy.
    """

    contract_id: ContractId
    tx_result: TxResult | None

    def __init__(
        self,
        simulator: Simulator,
        contract_id: ContractId,
        blueprint_class: type[Blueprint],
        *,
        tx_result: TxResult | None = None,
    ) -> None:
        self.contract_id = contract_id
        self.tx_result = tx_result
        self._simulator = simulator

        for name, method in inspect.getmembers(blueprint_class, predicate=inspect.isfunction):
            if name == 'initialize':
                continue

            if is_nc_public_method(method):
                setattr(self, name, self._make_public_wrapper(name, method))
            elif is_nc_view_method(method):
                setattr(self, name, self._make_view_wrapper(name, method))

    def __getattr__(self, name: str) -> Any:
        raise AttributeError(f"'{type(self).__name__}' has no method '{name}' (not found on the blueprint)")

    def _make_public_wrapper(self, method_name: str, method: Any) -> Any:
        contract_id = self.contract_id
        sim = self._simulator

        def wrapper(*args: Any, caller: Address, actions: list[NCAction] | None = None) -> TxResult:
            return sim.call_public(
                contract_id, method_name, caller=caller, args=args, actions=actions,
            )

        wrapper.__name__ = method_name
        wrapper.__doc__ = method.__doc__
        return wrapper

    def _make_view_wrapper(self, method_name: str, method: Any) -> Any:
        contract_id = self.contract_id
        sim = self._simulator

        def wrapper(*args: Any) -> Any:
            return sim.call_view(contract_id, method_name, *args)

        wrapper.__name__ = method_name
        wrapper.__doc__ = method.__doc__
        return wrapper
