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

import inspect
from dataclasses import dataclass
from enum import Enum, unique
from typing import Any, Callable, Generic, NewType, TypeAlias, TypeVar

from typing_extensions import override

from hathor.nanocontracts.blueprint_syntax_validation import (
    validate_has_ctx_arg,
    validate_has_not_ctx_arg,
    validate_has_self_arg,
    validate_method_types,
)
from hathor.nanocontracts.exception import BlueprintSyntaxError
from hathor.transaction.util import bytes_to_int, int_to_bytes
from hathor.utils.typing import InnerTypeMixin

# Types to be used by blueprints.
Address = NewType('Address', bytes)
Amount = NewType('Amount', int)
Timestamp = NewType('Timestamp', int)
TokenUid = NewType('TokenUid', bytes)
TxOutputScript = NewType('TxOutputScript', bytes)
VertexId = NewType('VertexId', bytes)
BlueprintId = NewType('BlueprintId', VertexId)
ContractId = NewType('ContractId', VertexId)

T = TypeVar('T')

NC_INITIALIZE_METHOD: str = 'initialize'
NC_FALLBACK_METHOD: str = 'fallback'

NC_ALLOWED_ACTIONS_ATTR = '__nc_allowed_actions'
NC_METHOD_TYPE_ATTR: str = '__nc_method_type'


class NCMethodType(Enum):
    PUBLIC = 'public'
    VIEW = 'view'
    FALLBACK = 'fallback'


def blueprint_id_from_bytes(data: bytes) -> BlueprintId:
    """Create a BlueprintId from a bytes object."""
    return BlueprintId(VertexId(data))


class RawSignedData(InnerTypeMixin[T], Generic[T]):
    """A wrapper class to sign data.

    T must be serializable.
    """

    def __init__(self, data: T, script_input: bytes) -> None:
        from hathor.nanocontracts.nc_types import make_nc_type_for_type_extended
        self.data = data
        self.script_input = script_input
        self.__nc_type = make_nc_type_for_type_extended(self.__inner_type__)

    def __eq__(self, other):
        if not isinstance(other, RawSignedData):
            return False
        if self.data != other.data:
            return False
        if self.script_input != other.script_input:
            return False
        return True

    def get_data_bytes(self) -> bytes:
        """Return the serialized data."""
        return self.__nc_type.to_bytes(self.data)

    def get_sighash_all_data(self) -> bytes:
        """Workaround to be able to pass `self` for ScriptExtras. See the method `checksig`."""
        return self.get_data_bytes()

    def checksig(self, script: bytes) -> bool:
        """Check if `self.script_input` satisfies the provided script."""
        from hathor.transaction.exceptions import ScriptError
        from hathor.transaction.scripts import ScriptExtras
        from hathor.transaction.scripts.execute import execute_eval
        full_data = self.script_input + script
        log: list[str] = []
        extras = ScriptExtras(tx=self)  # type: ignore[arg-type]
        try:
            execute_eval(full_data, log, extras)
        except ScriptError:
            return False
        else:
            return True


class SignedData(InnerTypeMixin[T], Generic[T]):
    def __init__(self, data: T, script_input: bytes) -> None:
        self.data = data
        self.script_input = script_input

    def __eq__(self, other):
        if not isinstance(other, SignedData):
            return False
        if self.data != other.data:
            return False
        if self.script_input != other.script_input:
            return False
        return True

    def _get_raw_signed_data(self, contract_id: ContractId) -> RawSignedData:
        # XXX: for some reason mypy doesn't recognize that self.__inner_type__ is defined even though it should
        raw_type: type = tuple[ContractId, self.__inner_type__]  # type: ignore[name-defined]
        raw_data = (contract_id, self.data)
        return RawSignedData[raw_type](raw_data, self.script_input)  # type: ignore[valid-type]

    def get_data_bytes(self, contract_id: ContractId) -> bytes:
        """Return the serialized data."""
        raw_signed_data = self._get_raw_signed_data(contract_id)
        return raw_signed_data.get_data_bytes()

    def checksig(self, contract_id: ContractId, script: bytes) -> bool:
        """Check if script_input satisfies the provided script."""
        raw_signed_data = self._get_raw_signed_data(contract_id)
        return raw_signed_data.checksig(script)


def _set_method_type(fn: Callable, method_type: NCMethodType) -> None:
    if hasattr(fn, NC_METHOD_TYPE_ATTR):
        raise BlueprintSyntaxError(f'method must be annotated with at most one method type: `{fn.__name__}()`')
    setattr(fn, NC_METHOD_TYPE_ATTR, method_type)


def _create_decorator_with_allowed_actions(
    *,
    decorator_body: Callable[[Callable], None],
    maybe_fn: Callable | None,
    allow_deposit: bool | None,
    allow_withdrawal: bool | None,
    allow_grant_authority: bool | None,
    allow_invoke_authority: bool | None,
    allow_actions: list[NCActionType] | None,
) -> Callable:
    """Internal utility to create a decorator that sets allowed actions."""
    flags = {
        NCActionType.DEPOSIT: allow_deposit,
        NCActionType.WITHDRAWAL: allow_withdrawal,
        NCActionType.GRANT_AUTHORITY: allow_grant_authority,
        NCActionType.INVOKE_AUTHORITY: allow_invoke_authority,
    }

    def decorator(fn: Callable) -> Callable:
        if allow_actions is not None and any(flag is not None for flag in flags.values()):
            raise BlueprintSyntaxError(f'use only one of `allow_actions` or per-action flags: `{fn.__name__}()`')

        allowed_actions = set(allow_actions) if allow_actions else set()
        allowed_actions.update(action for action, flag in flags.items() if flag)
        setattr(fn, NC_ALLOWED_ACTIONS_ATTR, allowed_actions)

        decorator_body(fn)
        return fn

    if maybe_fn is not None:
        return decorator(maybe_fn)
    return decorator


def public(
    maybe_fn: Callable | None = None,
    /,
    *,
    allow_deposit: bool | None = None,
    allow_withdrawal: bool | None = None,
    allow_grant_authority: bool | None = None,
    allow_invoke_authority: bool | None = None,
    allow_actions: list[NCActionType] | None = None,
) -> Callable:
    """Decorator to mark a blueprint method as public."""
    def decorator(fn: Callable) -> None:
        annotation_name = 'public'
        forbidden_methods = {NC_FALLBACK_METHOD}
        _set_method_type(fn, NCMethodType.PUBLIC)

        if fn.__name__ in forbidden_methods:
            raise BlueprintSyntaxError(f'`{fn.__name__}` method cannot be annotated with @{annotation_name}')

        validate_has_self_arg(fn, annotation_name)
        validate_method_types(fn)
        validate_has_ctx_arg(fn, annotation_name)

    return _create_decorator_with_allowed_actions(
        decorator_body=decorator,
        maybe_fn=maybe_fn,
        allow_deposit=allow_deposit,
        allow_withdrawal=allow_withdrawal,
        allow_grant_authority=allow_grant_authority,
        allow_invoke_authority=allow_invoke_authority,
        allow_actions=allow_actions,
    )


def view(fn: Callable) -> Callable:
    """Decorator to mark a blueprint method as view (read-only)."""
    annotation_name = 'view'
    forbidden_methods = {NC_INITIALIZE_METHOD, NC_FALLBACK_METHOD}
    _set_method_type(fn, NCMethodType.VIEW)

    if fn.__name__ in forbidden_methods:
        raise BlueprintSyntaxError(f'`{fn.__name__}` method cannot be annotated with @{annotation_name}')

    validate_has_self_arg(fn, annotation_name)
    validate_has_not_ctx_arg(fn, annotation_name)
    validate_method_types(fn)
    return fn


def fallback(
    maybe_fn: Callable | None = None,
    /,
    *,
    allow_deposit: bool | None = None,
    allow_withdrawal: bool | None = None,
    allow_grant_authority: bool | None = None,
    allow_invoke_authority: bool | None = None,
    allow_actions: list[NCActionType] | None = None,
) -> Callable:
    """Decorator to mark a blueprint method as fallback. The method must also be called `fallback`."""
    def decorator(fn: Callable) -> None:
        annotation_name = 'fallback'
        _set_method_type(fn, NCMethodType.FALLBACK)

        if fn.__name__ != NC_FALLBACK_METHOD:
            raise BlueprintSyntaxError(f'@{annotation_name} method must be called `fallback`: `{fn.__name__}()`')

        validate_has_self_arg(fn, annotation_name)
        validate_method_types(fn)
        validate_has_ctx_arg(fn, annotation_name)

        arg_spec = inspect.getfullargspec(fn)
        msg = f'@{annotation_name} method must have these args: `ctx: Context, method_name: str, nc_args: NCArgs`'

        if len(arg_spec.args) < 4:
            raise BlueprintSyntaxError(msg)

        third_arg = arg_spec.args[2]
        fourth_arg = arg_spec.args[3]

        from hathor.nanocontracts.runner.types import NCArgs
        if arg_spec.annotations[third_arg] is not str or arg_spec.annotations[fourth_arg] is not NCArgs:
            raise BlueprintSyntaxError(msg)

    return _create_decorator_with_allowed_actions(
        decorator_body=decorator,
        maybe_fn=maybe_fn,
        allow_deposit=allow_deposit,
        allow_withdrawal=allow_withdrawal,
        allow_grant_authority=allow_grant_authority,
        allow_invoke_authority=allow_invoke_authority,
        allow_actions=allow_actions,
    )


@unique
class NCActionType(Enum):
    """
    Types of interactions a transaction might have with a contract.
    Check the respective dataclasses below for more info.
    """
    DEPOSIT = 1
    WITHDRAWAL = 2
    GRANT_AUTHORITY = 3
    INVOKE_AUTHORITY = 4

    def __str__(self) -> str:
        return self.name

    def to_bytes(self) -> bytes:
        return int_to_bytes(number=self.value, size=1)

    @staticmethod
    def from_bytes(data: bytes) -> NCActionType:
        return NCActionType(bytes_to_int(data))


@dataclass(slots=True, frozen=True, kw_only=True)
class BaseAction:
    """The base dataclass for all NC actions. Shouldn't be instantiated directly."""
    token_uid: TokenUid

    @property
    def type(self) -> NCActionType:
        """The respective NCActionType for each NCAction."""
        action_types: dict[type[BaseAction], NCActionType] = {
            NCDepositAction: NCActionType.DEPOSIT,
            NCWithdrawalAction: NCActionType.WITHDRAWAL,
            NCGrantAuthorityAction: NCActionType.GRANT_AUTHORITY,
            NCInvokeAuthorityAction: NCActionType.INVOKE_AUTHORITY,
        }

        if action_type := action_types.get(type(self)):
            return action_type

        raise NotImplementedError(f'unknown action type {type(self)}')

    @property
    def name(self) -> str:
        """The action name."""
        return str(self.type)

    def to_json(self) -> dict[str, Any]:
        """
        Convert this action to a json dict.

        >>> NCDepositAction(token_uid=TokenUid(b'\x01'), amount=123).to_json()
        {'type': 'deposit', 'token_uid': '01', 'amount': 123}
        >>> NCWithdrawalAction(token_uid=TokenUid(b'\x01'), amount=123).to_json()
        {'type': 'withdrawal', 'token_uid': '01', 'amount': 123}
        >>> NCGrantAuthorityAction(token_uid=TokenUid(b'\x01'), mint=True, melt=False).to_json()
        {'type': 'grant_authority', 'token_uid': '01', 'mint': True, 'melt': False}
        >>> NCInvokeAuthorityAction(token_uid=TokenUid(b'\x01'), mint=False, melt=True).to_json()
        {'type': 'invoke_authority', 'token_uid': '01', 'mint': False, 'melt': True}
        """
        return dict(
            type=self.name.lower(),
            token_uid=self.token_uid.hex(),
        )


@dataclass(slots=True, frozen=True, kw_only=True)
class BaseTokenAction(BaseAction):
    """The base dataclass for all token-related NC actions. Shouldn't be instantiated directly."""
    amount: int

    @override
    def to_json(self) -> dict[str, Any]:
        json_dict = super(BaseTokenAction, self).to_json()
        return dict(
            **json_dict,
            amount=self.amount,
        )


@dataclass(slots=True, frozen=True, kw_only=True)
class BaseAuthorityAction(BaseAction):
    """The base dataclass for all authority-related NC actions. Shouldn't be instantiated directly."""
    mint: bool
    melt: bool

    def __post_init__(self) -> None:
        """Validate the token uid."""
        from hathor.conf.settings import HATHOR_TOKEN_UID
        from hathor.nanocontracts.exception import NCInvalidAction
        if self.token_uid == HATHOR_TOKEN_UID:
            raise NCInvalidAction(f'{self.name} action cannot be executed on HTR token')

    @override
    def to_json(self) -> dict[str, Any]:
        json_dict = super(BaseAuthorityAction, self).to_json()
        return dict(
            **json_dict,
            mint=self.mint,
            melt=self.melt,
        )


@dataclass(slots=True, frozen=True, kw_only=True)
class NCDepositAction(BaseTokenAction):
    """Deposit tokens into the contract."""


@dataclass(slots=True, frozen=True, kw_only=True)
class NCWithdrawalAction(BaseTokenAction):
    """Withdraw tokens from the contract."""


@dataclass(slots=True, frozen=True, kw_only=True)
class NCGrantAuthorityAction(BaseAuthorityAction):
    """Grant an authority to the contract."""


@dataclass(slots=True, frozen=True, kw_only=True)
class NCInvokeAuthorityAction(BaseAuthorityAction):
    """
    Invoke an authority stored in a contract to create authority outputs or mint/melt tokens in the tx,
    or to copy the authority to a caller contract.
    """


"""A sum type representing all possible nano contract actions."""
NCAction: TypeAlias = (
    NCDepositAction
    | NCWithdrawalAction
    | NCGrantAuthorityAction
    | NCInvokeAuthorityAction
)
