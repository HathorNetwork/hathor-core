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

import hathor.nanocontracts as nc

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
    'hathor.nanocontracts': dict(Blueprint=nc.Blueprint),
    'hathor.nanocontracts.blueprint': dict(Blueprint=nc.Blueprint),
    'hathor.nanocontracts.context': dict(Context=nc.Context),
    'hathor.nanocontracts.exception': dict(NCFail=nc.NCFail),
    'hathor.nanocontracts.types': dict(
        NCAction=nc.types.NCAction,
        NCActionType=nc.types.NCActionType,
        SignedData=nc.types.SignedData,
        public=nc.public,
        view=nc.view,
        fallback=nc.fallback,
        Address=nc.types.Address,
        Amount=nc.types.Amount,
        Timestamp=nc.types.Timestamp,
        TokenUid=nc.types.TokenUid,
        TxOutputScript=nc.types.TxOutputScript,
        BlueprintId=nc.types.BlueprintId,
        ContractId=nc.types.ContractId,
        VertexId=nc.types.VertexId,
        NCDepositAction=nc.types.NCDepositAction,
        NCWithdrawalAction=nc.types.NCWithdrawalAction,
        NCGrantAuthorityAction=nc.types.NCGrantAuthorityAction,
        NCAcquireAuthorityAction=nc.types.NCAcquireAuthorityAction,
        NCArgs=nc.types.NCArgs,
        NCRawArgs=nc.types.NCRawArgs,
        NCParsedArgs=nc.types.NCParsedArgs,
    ),
}
