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

from dataclasses import dataclass
from enum import Enum, unique
from typing import Any, Callable, Generic, NewType, TypeAlias, TypeGuard, TypeVar

from hathor.nanocontracts.blueprint_syntax_validation import (
    validate_has_ctx_arg,
    validate_has_not_ctx_arg,
    validate_has_self_arg,
    validate_method_types,
)
from hathor.nanocontracts.exception import BlueprintSyntaxError
from hathor.transaction.headers import NC_INITIALIZE_METHOD

# Types to be used by blueprints.
VertexId = NewType('VertexId', bytes)
Amount = NewType('Amount', int)
Address = NewType('Address', bytes)
TxOutputScript = NewType('TxOutputScript', bytes)
TokenUid = NewType('TokenUid', bytes)
Timestamp = NewType('Timestamp', int)
ContractId = NewType('ContractId', VertexId)
BlueprintId = NewType('BlueprintId', VertexId)
VarInt = NewType('VarInt', int)

T = TypeVar('T')

NC_ALLOWED_ACTIONS_ATTR = '__nc_allowed_actions'
NC_METHOD_TYPE_ATTR: str = '__nc_method_type'


class NCMethodType(Enum):
    PUBLIC = 'public'
    VIEW = 'view'


def blueprint_id_from_bytes(data: bytes) -> BlueprintId:
    """Create a BlueprintId from a bytes object."""
    return BlueprintId(VertexId(data))


class RawSignedData(Generic[T]):
    """A wrapper class to sign data.

    T must be serializable.
    """
    def __init__(self, data: T, script_input: bytes) -> None:
        self.data = data
        self.script_input = script_input

    def __eq__(self, other):
        if not isinstance(other, RawSignedData):
            return False
        if self.data != other.data:
            return False
        if self.script_input != other.script_input:
            return False
        return True

    def _get_inner_type(self) -> type[T]:
        if not hasattr(self, '__orig_class__'):
            raise TypeError('You must use RawSignedData[data_type](...)')
        if len(self.__orig_class__.__args__) != 1:
            raise TypeError('You must provide only one type')
        return self.__orig_class__.__args__[0]

    def get_data_bytes(self) -> bytes:
        """Return the serialized data."""
        from hathor.nanocontracts.serializers import Serializer
        serializer = Serializer()
        type_ = self._get_inner_type()
        return serializer.from_type(type_, self.data)

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


class SignedData(Generic[T]):
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

    def _get_inner_type(self) -> type[T]:
        if not hasattr(self, '__orig_class__'):
            raise TypeError('You must use SignedData[data_type](...)')
        if len(self.__orig_class__.__args__) != 1:
            raise TypeError('You must provide only one type')
        return self.__orig_class__.__args__[0]

    def _get_raw_signed_data(self, contract_id: ContractId) -> RawSignedData:
        type_ = self._get_inner_type()
        data = (contract_id, self.data)
        return RawSignedData[tuple[ContractId, type_]](data, self.script_input)  # type: ignore

    def get_data_bytes(self, contract_id: ContractId) -> bytes:
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

        annotation_name = 'public'
        _set_method_type(fn, NCMethodType.PUBLIC)
        validate_has_self_arg(fn, annotation_name)
        validate_method_types(fn)
        validate_has_ctx_arg(fn, annotation_name)
        return fn

    if maybe_fn is not None:
        return decorator(maybe_fn)
    return decorator


def view(fn: Callable) -> Callable:
    """Decorator to mark a blueprint method as view (read-only)."""
    annotation_name = 'view'
    forbidden_methods = [NC_INITIALIZE_METHOD]
    _set_method_type(fn, NCMethodType.VIEW)

    if fn.__name__ in forbidden_methods:
        raise BlueprintSyntaxError(f'`{fn.__name__}` method cannot be annotated with @{annotation_name}')

    validate_has_self_arg(fn, annotation_name)
    validate_has_not_ctx_arg(fn, annotation_name)
    validate_method_types(fn)
    return fn


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
        from hathor.transaction.util import int_to_bytes
        return int_to_bytes(number=self.value, size=1)

    @staticmethod
    def from_bytes(data: bytes) -> NCActionType:
        from hathor.transaction.util import bytes_to_int
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


@dataclass(slots=True, frozen=True, kw_only=True)
class BaseTokenAction(BaseAction):
    """The base dataclass for all token-related NC actions. Shouldn't be instantiated directly."""
    amount: int

    def to_json(self) -> dict[str, Any]:
        return dict(
            type=self.name.lower(),
            token_uid=self.token_uid.hex(),
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

    def to_json(self) -> dict[str, Any]:
        return dict(
            type=self.name,
            token_uid=self.token_uid.hex(),
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
    """Invoke an authority stored in the contract to create authority outputs or mint/melt tokens in the tx."""


"""A sum type representing all possible nano contract actions."""
NCAction: TypeAlias = (
    NCDepositAction
    | NCWithdrawalAction
    | NCGrantAuthorityAction
    | NCInvokeAuthorityAction
)

ActionT = TypeVar('ActionT', bound=BaseAction)


def is_action_type(action: NCAction, action_type: type[ActionT]) -> TypeGuard[ActionT]:
    """
    Check whether the type of this action is the provided type,
    to be used in blueprints (as `isinstance` is not allowed).
    """
    return isinstance(action, action_type)
