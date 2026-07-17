# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import collections
import math
import typing

from hathorlib.conf.settings import HATHOR_TOKEN_UID
from hathorlib.nanocontracts.blueprint import Blueprint
from hathorlib.nanocontracts.context import Context
from hathorlib.nanocontracts.exception import NCFail
from hathorlib.nanocontracts.types import (
    Address,
    Amount,
    BlueprintId,
    CallerId,
    ContractId,
    NCAcquireAuthorityAction,
    NCAction,
    NCActionType,
    NCArgs,
    NCDepositAction,
    NCFee,
    NCGrantAuthorityAction,
    NCParsedArgs,
    NCWithdrawalAction,
    Timestamp,
    TokenUid,
    TxOutputScript,
    VertexId,
    export,
    fallback,
    get_nc_raw_args_class,
    get_signed_data_class,
    public,
    view,
)
from hathorlib.nanocontracts.utils import json_dumps, sha3, verify_ecdsa
from hathorlib.token_amount_version import TokenAmountVersion


def get_allowed_imports(token_amount_version: TokenAmountVersion) -> dict[str, dict[str, object]]:
    """Return what blueprints are allowed to import, checked in the AST and in runtime.

    The `SignedData` and `NCRawArgs` names are bound to the concrete class matching
    `token_amount_version`, so blueprint code transparently uses its own version's serialization.
    All names are identical across versions; only their bindings differ.
    """
    signed_data = get_signed_data_class(token_amount_version)
    nc_raw_args = get_nc_raw_args_class(token_amount_version)
    return {
        # globals
        'math': dict(
            ceil=math.ceil,
            floor=math.floor,
        ),
        'typing': dict(
            Optional=typing.Optional,
            NamedTuple=typing.NamedTuple,
            TypeAlias=typing.TypeAlias,
            Union=typing.Union,
        ),
        'collections': dict(OrderedDict=collections.OrderedDict),
        # hathor
        'hathor': dict(
            Blueprint=Blueprint,
            HATHOR_TOKEN_UID=HATHOR_TOKEN_UID,
            Context=Context,
            NCFail=NCFail,
            NCAction=NCAction,
            NCFee=NCFee,
            NCActionType=NCActionType,
            SignedData=signed_data,
            public=public,
            view=view,
            export=export,
            fallback=fallback,
            Address=Address,
            Amount=Amount,
            Timestamp=Timestamp,
            TokenUid=TokenUid,
            TxOutputScript=TxOutputScript,
            BlueprintId=BlueprintId,
            ContractId=ContractId,
            VertexId=VertexId,
            CallerId=CallerId,
            NCDepositAction=NCDepositAction,
            NCWithdrawalAction=NCWithdrawalAction,
            NCGrantAuthorityAction=NCGrantAuthorityAction,
            NCAcquireAuthorityAction=NCAcquireAuthorityAction,
            NCArgs=NCArgs,
            NCRawArgs=nc_raw_args,
            NCParsedArgs=NCParsedArgs,
            sha3=sha3,
            verify_ecdsa=verify_ecdsa,
            json_dumps=json_dumps,
        ),
    }


# Importable names per module, for static (AST) validation: names are identical across versions,
# only their bindings differ, so name checks do not depend on a token amount version.
ALLOWED_IMPORT_NAMES: dict[str, frozenset[str]] = {
    module: frozenset(names) for module, names in get_allowed_imports(TokenAmountVersion.V2).items()
}
