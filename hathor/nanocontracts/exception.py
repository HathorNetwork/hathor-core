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
    NCInvalidContractId,
    NCInvalidContext,
    NCInvalidFee,
    NCInvalidFeePaymentToken,
    NCInvalidInitializeMethodCall,
    NCInvalidPublicMethodCallFromView,
    NCInvalidSyscall,
    NCNumberOfCallsExceeded,
    NCRecursionError,
    NCSerializationArgTooLong,
    NCSerializationError,
    NCSerializationTypeError,
    NCTokenAlreadyExists,
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

from hathor.transaction.exceptions import TxValidationError

# hathor-specific exceptions that depend on TxValidationError


class NCTxValidationError(TxValidationError, NCFail):
    pass


class NCInvalidSignature(NCTxValidationError, NCFail):
    pass


class NCInvalidPubKey(NCTxValidationError, NCFail):
    pass


class NCInvalidSeqnum(NCTxValidationError, NCFail):
    pass


class NCMethodNotFound(NCTxValidationError):
    """Raised when a method is not found in a nano contract."""
    pass


class NCInvalidMethodCall(NCTxValidationError):
    """Raised when a contract calls another contract's invalid method."""
