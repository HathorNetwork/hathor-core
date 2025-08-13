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
import types
import typing
from dataclasses import dataclass, field

from typing import NewType, NamedTuple, Optional, TypeAlias, Union

from hathor.nanocontracts import Blueprint
from hathor.nanocontracts.custom_builtins import custom_range
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.faux_immutable import __is_instance_frozen__
from hathor.nanocontracts.types import NCActionType, NCDepositAction, NCWithdrawalAction, NCGrantAuthorityAction, \
    NCAcquireAuthorityAction, SignedData, Address, Amount, BlueprintId, ContractId, Timestamp, TokenUid, \
    TxOutputScript, VertexId, NCRawArgs, NCParsedArgs, fallback, public, view


@dataclass(slots=True, frozen=True, kw_only=True)
class AllowedAccessKind:
    attrs: frozenset[str] = field(default_factory=frozenset)
    methods: frozenset[str] = field(default_factory=frozenset)

    def all(self) -> frozenset[str]:
        return self.attrs | self.methods


@dataclass(slots=True, frozen=True, kw_only=True)
class AllowedAccess:
    type: AllowedAccessKind = field(default_factory=AllowedAccessKind)
    instance: AllowedAccessKind = field(default_factory=AllowedAccessKind)


def get_allowed_access(obj: object) -> AllowedAccessKind | None:
    # TODO: Freezing classes will break inheritance?
    if (
        isinstance(obj, type)
        or isinstance(obj, NewType)
        or isinstance(obj, types.FunctionType)
        or isinstance(obj, typing._SpecialForm)
    ):
        allowed = ALLOWED_ACCESS.get(obj)
        return allowed.type if allowed is not None else None

    allowed = ALLOWED_ACCESS.get(type(obj))
    return allowed.instance if allowed is not None else None


ALLOWED_ACCESS: dict[type, AllowedAccess] = {
    Blueprint: AllowedAccess(
        instance=AllowedAccessKind(
            attrs=frozenset({
                'syscall',
                'log',
            }),
        ),
    ),
    NCActionType: AllowedAccess(
        type=AllowedAccessKind(
            attrs=frozenset({
                'DEPOSIT',
                'WITHDRAWAL',
                'GRANT_AUTHORITY',
                'ACQUIRE_AUTHORITY',
            }),
        ),
    ),
    NCDepositAction: AllowedAccess(
        instance=AllowedAccessKind(
            attrs=frozenset({
                'token_uid',
                'amount',
            }),
        ),
    ),
    NCWithdrawalAction: AllowedAccess(
        instance=AllowedAccessKind(
            attrs=frozenset({
                'token_uid',
                'amount',
            }),
        ),
    ),
    NCGrantAuthorityAction: AllowedAccess(
        instance=AllowedAccessKind(
            attrs=frozenset({
                'token_uid',
                'mint',
                'melt'
            }),
        ),
    ),
    NCAcquireAuthorityAction: AllowedAccess(
        instance=AllowedAccessKind(
            attrs=frozenset({
                'token_uid',
                'mint',
                'melt'
            }),
        ),
    ),
    SignedData: AllowedAccess(
        type=AllowedAccessKind(
            methods=frozenset({
                '__getitem__',
            }),
        ),
        instance=AllowedAccessKind(
            methods=frozenset({
                'checksig',
            }),
        ),
    ),
    Context: AllowedAccess(
        instance=AllowedAccessKind(
            attrs=frozenset({
                'vertex',
                'address',
                'timestamp',
                'actions',
                'actions_list',
            }),
            methods=frozenset({
                'get_single_action',
            }),
        ),
    ),
    NCRawArgs: AllowedAccess(
        instance=AllowedAccessKind(
            attrs=frozenset({
                'args_bytes',
            }),
            methods=frozenset({
                'try_parse_as',
            }),
        ),
    ),
    NCParsedArgs: AllowedAccess(
        instance=AllowedAccessKind(
            attrs=frozenset({
                'args',
                'kwargs',
            }),
        ),
    ),
    NCFail: AllowedAccess(), # TODO: How to deal with wrapped exceptions? We can't raise them
    custom_range: AllowedAccess(),
    Address: AllowedAccess(),
    Amount: AllowedAccess(),
    BlueprintId: AllowedAccess(),
    ContractId: AllowedAccess(),
    Timestamp: AllowedAccess(),
    TokenUid: AllowedAccess(),
    TxOutputScript: AllowedAccess(),
    VertexId: AllowedAccess(),
    __is_instance_frozen__: AllowedAccess(),
    fallback: AllowedAccess(),
    public: AllowedAccess(),
    view: AllowedAccess(),
    NamedTuple: AllowedAccess(),
    Optional: AllowedAccess(),
    TypeAlias: AllowedAccess(),
    Union: AllowedAccess(),
}


