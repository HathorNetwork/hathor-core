# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""
This is module exports all types and functions available to blueprints as the main exposed API.
"""

from hathor.nanocontracts import HATHOR_TOKEN_UID, Blueprint, Context, NCFail, export, fallback, public, view

# Python-imported blueprints (built-ins) are always registered with `TokenAmountVersion.V2`, so the
# version-routed names bind to the V2 classes here, mirroring the on-chain import table.
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
    NCRawArgsV2 as NCRawArgs,
    NCWithdrawalAction,
    SignedDataV2 as SignedData,
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
