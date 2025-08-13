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

import inspect
import types
import typing
from dataclasses import dataclass, field
from math import ceil

from typing import NewType, NamedTuple, Optional, TypeAlias, Union

from hathor.nanocontracts import Blueprint
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.types import NCActionType, NCDepositAction, NCWithdrawalAction, NCGrantAuthorityAction, \
    NCAcquireAuthorityAction, SignedData, Address, Amount, BlueprintId, ContractId, Timestamp, TokenUid, \
    TxOutputScript, VertexId, NCRawArgs, NCParsedArgs, fallback, public, view
from typing import final

from hathor.nanocontracts.faux_immutable import FauxImmutable, __set_faux_immutable__



@dataclass(slots=True, frozen=True, kw_only=True)
class AllowedAccess:
    attrs: frozenset[str] = field(default_factory=frozenset)
    methods: frozenset[str] = field(default_factory=frozenset)

    def all(self) -> frozenset[str]:
        return self.attrs | self.methods


@dataclass(slots=True, frozen=True, kw_only=True)
class AllowedAccessKind:
    type: AllowedAccess = field(default_factory=AllowedAccess)
    instance: AllowedAccess = field(default_factory=AllowedAccess)


def get_allowed_access(obj: object) -> AllowedAccess:
    if inspect.isfunction(obj) or inspect.isbuiltin(obj):
        return AllowedAccess(methods=frozenset({'__call__'}))

    # TODO: Freezing classes will break inheritance? what about match?
    if (
        isinstance(obj, type)
        or isinstance(obj, NewType)
        or isinstance(obj, typing._SpecialForm)
    ):
        allowed = AAA().get(obj)
        return allowed.type if allowed is not None else AllowedAccess()

    allowed = AAA().get(type(obj))
    return allowed.instance if allowed is not None else AllowedAccess()


def AAA():
    from hathor.nanocontracts.custom_builtins import custom_range
    ALLOWED_ACCESS: dict[type, AllowedAccessKind] = {
        # TODO: Breaks inheritance
        # Blueprint: AllowedAccessKind(
        #     instance=AllowedAccess(
        #         attrs=frozenset({
        #             'syscall',
        #             'log',
        #         }),
        #     ),
        # ),
        NCActionType: AllowedAccessKind(
            type=AllowedAccess(
                attrs=frozenset({
                    'DEPOSIT',
                    'WITHDRAWAL',
                    'GRANT_AUTHORITY',
                    'ACQUIRE_AUTHORITY',
                }),
            ),
        ),
        NCDepositAction: AllowedAccessKind(
            instance=AllowedAccess(
                attrs=frozenset({
                    'token_uid',
                    'amount',
                }),
            ),
        ),
        NCWithdrawalAction: AllowedAccessKind(
            instance=AllowedAccess(
                attrs=frozenset({
                    'token_uid',
                    'amount',
                }),
            ),
        ),
        NCGrantAuthorityAction: AllowedAccessKind(
            instance=AllowedAccess(
                attrs=frozenset({
                    'token_uid',
                    'mint',
                    'melt'
                }),
            ),
        ),
        NCAcquireAuthorityAction: AllowedAccessKind(
            instance=AllowedAccess(
                attrs=frozenset({
                    'token_uid',
                    'mint',
                    'melt'
                }),
            ),
        ),
        SignedData: AllowedAccessKind(
            type=AllowedAccess(
                methods=frozenset({
                    '__getitem__',
                }),
            ),
            instance=AllowedAccess(
                methods=frozenset({
                    'checksig',
                }),
            ),
        ),
        Context: AllowedAccessKind(
            instance=AllowedAccess(
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
        NCRawArgs: AllowedAccessKind(
            instance=AllowedAccess(
                attrs=frozenset({
                    'args_bytes',
                }),
                methods=frozenset({
                    'try_parse_as',
                }),
            ),
        ),
        NCParsedArgs: AllowedAccessKind(
            instance=AllowedAccess(
                attrs=frozenset({
                    'args',
                    'kwargs',
                }),
            ),
        ),
        # NCFail: AllowedAccessKind(), # TODO: How to deal with wrapped exceptions? We can't subclass them
        custom_range: AllowedAccessKind(),
        Address: AllowedAccessKind(),
        Amount: AllowedAccessKind(),
        BlueprintId: AllowedAccessKind(),
        ContractId: AllowedAccessKind(),
        Timestamp: AllowedAccessKind(),
        TokenUid: AllowedAccessKind(),
        TxOutputScript: AllowedAccessKind(),
        VertexId: AllowedAccessKind(),
        NamedTuple: AllowedAccessKind(),
        Optional: AllowedAccessKind(
            type=AllowedAccess(
                methods=frozenset({
                    '__getitem__',
                }),
            ),
        ),
        TypeAlias: AllowedAccessKind(),
        Union: AllowedAccessKind(),
    }
    return ALLOWED_ACCESS


