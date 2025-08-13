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

from dataclasses import dataclass, field

from hathor.nanocontracts.types import NCActionType, NCDepositAction, NCWithdrawalAction, NCGrantAuthorityAction, \
    NCAcquireAuthorityAction, SignedData


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
    if isinstance(obj, type):
        allowed = ALLOWED_ACCESS.get(obj)
        return allowed.type if allowed is not None else None

    allowed = ALLOWED_ACCESS.get(type(obj))
    return allowed.instance if allowed is not None else None


ALLOWED_ACCESS: dict[type, AllowedAccess] = {
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
        )
    ),
    NCWithdrawalAction: AllowedAccess(
        instance=AllowedAccessKind(
            attrs=frozenset({
                'token_uid',
                'amount',
            }),
        )
    ),
    NCGrantAuthorityAction: AllowedAccess(
        instance=AllowedAccessKind(
            attrs=frozenset({
                'token_uid',
                'mint',
                'melt'
            }),
        )
    ),
    NCAcquireAuthorityAction: AllowedAccess(
        instance=AllowedAccessKind(
            attrs=frozenset({
                'token_uid',
                'mint',
                'melt'
            }),
        )
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
        )
    )
}


