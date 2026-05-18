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
    NCRawArgs,
    NCWithdrawalAction,
    SignedData,
    Timestamp,
    TokenUid,
    TxOutputScript,
    VertexId,
    export,
    fallback,
    public,
    view,
)
from hathorlib.nanocontracts.utils import json_dumps, sha3, verify_ecdsa

# this is what's allowed to be imported in blueprints, to be checked in the AST and in runtime
ALLOWED_IMPORTS: dict[str, dict[str, object]] = {
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
        SignedData=SignedData,
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
        NCRawArgs=NCRawArgs,
        NCParsedArgs=NCParsedArgs,
        sha3=sha3,
        verify_ecdsa=verify_ecdsa,
        json_dumps=json_dumps,
    ),
}
