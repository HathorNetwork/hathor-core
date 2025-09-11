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

from hathor import contracts

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
    'hathor.contracts': dict(
        Blueprint=contracts.Blueprint,
        HATHOR_TOKEN_UID=contracts.HATHOR_TOKEN_UID,
        Context=contracts.Context,
        NCFail=contracts.NCFail,
        NCAction=contracts.NCAction,
        NCActionType=contracts.NCActionType,
        SignedData=contracts.SignedData,
        public=contracts.public,
        view=contracts.view,
        export=contracts.export,
        fallback=contracts.fallback,
        Address=contracts.Address,
        Amount=contracts.Amount,
        Timestamp=contracts.Timestamp,
        TokenUid=contracts.TokenUid,
        TxOutputScript=contracts.TxOutputScript,
        BlueprintId=contracts.BlueprintId,
        ContractId=contracts.ContractId,
        VertexId=contracts.VertexId,
        CallerId=contracts.CallerId,
        NCDepositAction=contracts.NCDepositAction,
        NCWithdrawalAction=contracts.NCWithdrawalAction,
        NCGrantAuthorityAction=contracts.NCGrantAuthorityAction,
        NCAcquireAuthorityAction=contracts.NCAcquireAuthorityAction,
        NCArgs=contracts.NCArgs,
        NCRawArgs=contracts.NCRawArgs,
        NCParsedArgs=contracts.NCParsedArgs,
    ),
}
