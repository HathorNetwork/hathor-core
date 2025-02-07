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

from typing import TYPE_CHECKING, Any, Optional, final

from structlog import get_logger

from hathor.nanocontracts.fields import get_field_for_attr
from hathor.nanocontracts.storage import NCStorage
from hathor.nanocontracts.types import ContractId, NCAction, TokenUid

if TYPE_CHECKING:
    from hathor.nanocontracts.runner import Runner

logger = get_logger()


class _BlueprintBase(type):
    """Metaclass for blueprints.

    This metaclass will modify the attributes and set Fields to them according to their types.
    """

    FORBIDDEN_NAMES = {
        'get_nanocontract_id',
        'get_balance',
        'call_public_method',
        'call_view_method',
    }

    def __new__(cls, name, bases, attrs, **kwargs):
        # Initialize only subclasses of Blueprint.
        parents = [b for b in bases if isinstance(b, _BlueprintBase)]
        if not parents:
            return super().__new__(cls, name, bases, attrs, **kwargs)

        # Create the `_fields` attribute with the type for each field.
        attrs['_fields'] = attrs.get('__annotations__', {})
        new_class = super().__new__(cls, name, bases, attrs, **kwargs)

        # Check for forbidden names.
        # Note: This verification must be done AFTER calling super().__new__().
        for name in attrs.keys():
            if name in cls.FORBIDDEN_NAMES:
                raise SyntaxError(f'Attempt to have a forbidden name: {name}')

        # Create the Field instance according to each type.
        for name, _type in attrs['_fields'].items():
            if name.startswith('_'):
                raise SyntaxError('cannot start with _')
            value = getattr(new_class, name, None)
            if value is None:
                # This is the case when a type is specified but not a value.
                # Example:
                #     name: str
                #     age: int
                field = get_field_for_attr(name, _type)
                setattr(new_class, name, field)
            else:
                # This is the case when a value is specified.
                # Example:
                #     name: str = StrField()
                #
                # This was not implemented yet and will be extended later.
                raise NotImplementedError

        return new_class


class Blueprint(metaclass=_BlueprintBase):
    """Base class for all blueprints.

    Example:

        class MyBlueprint(Blueprint):
            name: str
            age: int
    """

    def __init__(self, runner: Runner, storage: NCStorage):
        self.log = logger.new()
        self._runner = runner
        self._storage = storage
        self._cache: dict[str, Any] = {}

    @final
    def get_nanocontract_id(self) -> ContractId:
        """Return the current contract id."""
        assert self._runner is not None
        return self._runner.get_current_nanocontract_id()

    @final
    def get_balance(self,
                    token_uid: Optional[TokenUid] = None,
                    *,
                    nanocontract_id: Optional[ContractId] = None) -> int:
        """Return the balance for a given token without considering the current transaction.

        For instance, if a contract has 50 HTR and a transaction is requesting to withdraw 3 HTR,
        then this method will return 50 HTR."""
        assert self._runner is not None
        return self._runner.get_balance(nanocontract_id, token_uid)

    @final
    def call_public_method(self,
                           nc_id: ContractId,
                           method_name: str,
                           actions: list[NCAction],
                           *args: Any,
                           **kwargs: Any) -> Any:
        """Call a public method of another contract."""
        assert self._runner is not None
        return self._runner.call_another_contract_public_method(nc_id, method_name, actions, *args, **kwargs)

    @final
    def call_view_method(self, nc_id: ContractId, method_name: str, *args: Any, **kwargs: Any) -> Any:
        """Call a view method of another contract."""
        assert self._runner is not None
        return self._runner.call_view_method(nc_id, method_name, *args, **kwargs)
