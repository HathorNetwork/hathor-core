# Copyright 2023 Hathor Labs
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

# Re-export all exceptions from hathorlib for backward compatibility
from hathorlib.exceptions import TxValidationError  # noqa: F401
from hathorlib.nanocontracts.exception import (  # noqa: F401
    BlueprintDoesNotExist,
    BlueprintSyntaxError,
    NanoContractDoesNotExist,
    NCAlreadyInitializedContractError,
    NCAttributeError,
    NCContractCreationAtMempool,
    NCContractCreationNotFound,
    NCContractCreationVoided,
    NCDisabledBuiltinError,
    NCFail,
    NCForbiddenAction,
    NCForbiddenReentrancy,
    NCInsufficientFunds,
    NCInvalidAction,
    NCInvalidContext,
    NCInvalidContractId,
    NCInvalidFee,
    NCInvalidFeePaymentToken,
    NCInvalidInitializeMethodCall,
    NCInvalidMethodCall,
    NCInvalidPubKey,
    NCInvalidPublicMethodCallFromView,
    NCInvalidSeqnum,
    NCInvalidSignature,
    NCInvalidSyscall,
    NCMethodNotFound,
    NCNumberOfCallsExceeded,
    NCRecursionError,
    NCSerializationArgTooLong,
    NCSerializationError,
    NCSerializationTypeError,
    NCTokenAlreadyExists,
    NCTxValidationError,
    NCTypeError,
    NCUninitializedContractError,
    NCViewMethodError,
    OCBBlueprintNotConfirmed,
    OCBInvalidBlueprintVertexType,
    OCBInvalidScript,
    OCBOutOfFuelDuringLoading,
    OCBOutOfMemoryDuringLoading,
    OCBPubKeyNotAllowed,
    UnknownFieldType,
)
