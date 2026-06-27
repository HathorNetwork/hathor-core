# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""ContractProxy — object-oriented wrapper for interacting with deployed contracts."""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Any

from hathorlib.nanocontracts.types import Address, ContractId, NCAction
from hathorlib.nanocontracts.utils import is_nc_public_method, is_nc_view_method

if TYPE_CHECKING:
    from hathorlib.nanocontracts import Blueprint
    from hathorlib.nanocontracts.simulator.result import NcCallResult
    from hathorlib.nanocontracts.simulator.simulator import NanoSimulator


class ContractProxy:
    """Wraps a deployed contract and exposes its blueprint methods as regular Python methods.

    Public methods require ``caller`` as a keyword argument and return ``NcCallResult``.
    View methods take only positional args and return the view's return value directly.
    The ``initialize`` method is excluded from the proxy.
    """

    contract_id: ContractId
    tx_result: NcCallResult | None

    def __init__(
        self,
        simulator: NanoSimulator,
        contract_id: ContractId,
        blueprint_class: type[Blueprint],
        *,
        tx_result: NcCallResult | None = None,
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

        def wrapper(*args: Any, caller: Address, actions: list[NCAction] | None = None) -> NcCallResult:
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
