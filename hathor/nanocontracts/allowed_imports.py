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

import hathor

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
        Blueprint=hathor.Blueprint,
        HATHOR_TOKEN_UID=hathor.HATHOR_TOKEN_UID,
        Context=hathor.Context,
        NCFail=hathor.NCFail,
        NCAction=hathor.NCAction,
        NCFee=hathor.NCFee,
        NCActionType=hathor.NCActionType,
        SignedData=hathor.SignedData,
        public=hathor.public,
        view=hathor.view,
        export=hathor.export,
        fallback=hathor.fallback,
        Address=hathor.Address,
        Amount=hathor.Amount,
        Timestamp=hathor.Timestamp,
        TokenUid=hathor.TokenUid,
        TxOutputScript=hathor.TxOutputScript,
        BlueprintId=hathor.BlueprintId,
        ContractId=hathor.ContractId,
        VertexId=hathor.VertexId,
        CallerId=hathor.CallerId,
        NCDepositAction=hathor.NCDepositAction,
        NCWithdrawalAction=hathor.NCWithdrawalAction,
        NCGrantAuthorityAction=hathor.NCGrantAuthorityAction,
        NCAcquireAuthorityAction=hathor.NCAcquireAuthorityAction,
        NCArgs=hathor.NCArgs,
        NCRawArgs=hathor.NCRawArgs,
        NCParsedArgs=hathor.NCParsedArgs,
        sha3=hathor.sha3,
        verify_ecdsa=hathor.verify_ecdsa,
        json_dumps=hathor.json_dumps,
    ),
}
