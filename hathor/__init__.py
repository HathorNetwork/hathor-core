# Copyright 2021 Hathor Labs
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

"""
This is module exports all types and functions available to blueprints as the main exposed API.
"""

from hathor.nanocontracts import HATHOR_TOKEN_UID, Blueprint, Context, NCFail, export, fallback, public, view
from hathor.nanocontracts.types import (
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
)
from hathor.nanocontracts.utils import json_dumps, sha3, verify_ecdsa
from hathor.version import __version__

__all__ = [
    'HATHOR_TOKEN_UID',
    'Blueprint',
    'Context',
    'NCFail',
    'export',
    'fallback',
    'public',
    'view',
    'Address',
    'Amount',
    'BlueprintId',
    'CallerId',
    'ContractId',
    'NCAcquireAuthorityAction',
    'NCAction',
    'NCActionType',
    'NCArgs',
    'NCDepositAction',
    'NCFee',
    'NCGrantAuthorityAction',
    'NCParsedArgs',
    'NCRawArgs',
    'NCWithdrawalAction',
    'SignedData',
    'Timestamp',
    'TokenUid',
    'TxOutputScript',
    'VertexId',
    'sha3',
    'verify_ecdsa',
    'json_dumps',
    '__version__',
]
