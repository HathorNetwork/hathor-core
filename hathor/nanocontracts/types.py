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
from typing import Any, Callable, Generic, NewType, TypeAlias, TypeVar

from typing_extensions import override

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
        raise NotImplementedError('temporarily removed during nano merge')


class SignedData(InnerTypeMixin[T], Generic[T]):
    def __init__(self, data: T, script_input: bytes) -> None:
        raise NotImplementedError('temporarily removed during nano merge')


def _create_decorator_with_allowed_actions(
    *,
    decorator_body: Callable[[Callable], None],
    maybe_fn: Callable | None,
    allow_deposit: bool | None,
    allow_withdrawal: bool | None,
    allow_grant_authority: bool | None,
    allow_acquire_authority: bool | None,
    allow_actions: list[NCActionType] | None,
) -> Callable:
    """Internal utility to create a decorator that sets allowed actions."""
    flags = {
        NCActionType.DEPOSIT: allow_deposit,
        NCActionType.WITHDRAWAL: allow_withdrawal,
        NCActionType.GRANT_AUTHORITY: allow_grant_authority,
        NCActionType.ACQUIRE_AUTHORITY: allow_acquire_authority,
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
    allow_acquire_authority: bool | None = None,
    allow_actions: list[NCActionType] | None = None,
) -> Callable:
    """Decorator to mark a blueprint method as public."""
    def decorator(fn: Callable) -> None:
        raise NotImplementedError('temporarily removed during nano merge')

    return _create_decorator_with_allowed_actions(
        decorator_body=decorator,
        maybe_fn=maybe_fn,
        allow_deposit=allow_deposit,
        allow_withdrawal=allow_withdrawal,
        allow_grant_authority=allow_grant_authority,
        allow_acquire_authority=allow_acquire_authority,
        allow_actions=allow_actions,
    )


def view(fn: Callable) -> Callable:
    """Decorator to mark a blueprint method as view (read-only)."""
    raise NotImplementedError('temporarily removed during nano merge')


def fallback(
    maybe_fn: Callable | None = None,
    /,
    *,
    allow_deposit: bool | None = None,
    allow_withdrawal: bool | None = None,
    allow_grant_authority: bool | None = None,
    allow_acquire_authority: bool | None = None,
    allow_actions: list[NCActionType] | None = None,
) -> Callable:
    """Decorator to mark a blueprint method as fallback. The method must also be called `fallback`."""
    def decorator(fn: Callable) -> None:
        raise NotImplementedError('temporarily removed during nano merge')

    return _create_decorator_with_allowed_actions(
        decorator_body=decorator,
        maybe_fn=maybe_fn,
        allow_deposit=allow_deposit,
        allow_withdrawal=allow_withdrawal,
        allow_grant_authority=allow_grant_authority,
        allow_acquire_authority=allow_acquire_authority,
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
    ACQUIRE_AUTHORITY = 4

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
            NCAcquireAuthorityAction: NCActionType.ACQUIRE_AUTHORITY,
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
        >>> NCAcquireAuthorityAction(token_uid=TokenUid(b'\x01'), mint=False, melt=True).to_json()
        {'type': 'acquire_authority', 'token_uid': '01', 'mint': False, 'melt': True}
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
class NCAcquireAuthorityAction(BaseAuthorityAction):
    """
    Acquire an authority stored in a contract to create authority outputs or mint/melt tokens in the tx,
    or to store and use in a caller contract.
    """


"""A sum type representing all possible nano contract actions."""
NCAction: TypeAlias = (
    NCDepositAction
    | NCWithdrawalAction
    | NCGrantAuthorityAction
    | NCAcquireAuthorityAction
)
