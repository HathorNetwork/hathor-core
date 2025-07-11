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

from typing import TypeAlias

from hathor.exception import HathorError
from hathor.transaction.exceptions import TxValidationError


class BlueprintSyntaxError(SyntaxError):
    """Raised when a blueprint contains invalid syntax."""
    pass


class NCError(HathorError):
    """Base exception for nano contract's exceptions."""
    pass


class NCTxValidationError(TxValidationError):
    pass


class NCInvalidSignature(NCTxValidationError):
    pass


class NCInvalidPubKey(NCTxValidationError):
    pass


class NanoContractDoesNotExist(NCError):
    pass


class BlueprintDoesNotExist(NCError):
    pass


class NCSerializationError(NCError):
    pass


class NCSerializationArgTooLong(NCSerializationError):
    pass


class NCViewMethodError(NCError):
    """Raised when a view method changes the state of the contract."""
    pass


class NCMethodNotFound(NCError):
    """Raised when a method is not found in a nano contract."""
    pass


class NCInsufficientFunds(NCError):
    """Raised when there is not enough funds to withdrawal from a nano contract."""
    pass


class NCAttributeError(NCError):
    pass


class NCInvalidContext(NCError):
    """Raised when trying to run a method with an invalid context."""
    pass


class NCRecursionError(NCError):
    """Raised when recursion gets too deep."""


class NCNumberOfCallsExceeded(NCError):
    """Raised when the total number of calls have been exceeded."""


class NCInvalidContractId(NCError):
    """Raised when a contract call is invalid."""


class NCInvalidMethodCall(NCError):
    """Raised when a contract calls another contract's invalid method."""


class NCInvalidInitializeMethodCall(NCError):
    """Raised when a contract calls another contract's initialize method."""


class NCInvalidPublicMethodCallFromView(NCError):
    """Raised when a contract calls another contract's initialize method."""


class NCAlreadyInitializedContractError(NCError):
    """Raised when one tries to initialize a contract that has already been initialized."""


class NCUninitializedContractError(NCError):
    """Raised when a contract calls a method from an uninitialized contract."""


class NCInvalidAction(NCError):
    """Raised when an action is invalid."""
    pass


class NCInvalidSyscall(NCError):
    """Raised when a syscall is invalid."""
    pass


class NCTokenAlreadyExists(NCError):
    """Raised when one tries to create a duplicated token."""


class NCForbiddenAction(NCError):
    """Raised when an action is forbidden on a method."""
    pass


class UnknownFieldType(NCError):
    """Raised when there is no field available for a given type."""
    pass


class NCContractCreationNotFound(NCError):
    """Raised when a nano contract creation transaction is not found.

    This error might also happen when the transaction is at the mempool or when it fails execution."""
    pass


class NCContractCreationAtMempool(NCContractCreationNotFound):
    """Raised when a nano contract creation transaction is at the mempool, so it has not been
    executed yet."""
    pass


class NCContractCreationVoided(NCContractCreationNotFound):
    """Raised when a nano contract creation transaction is voided.

    The two most common reasons to have a voided transaction is because it was voided by
    another transaction (e.g., double spending) or it has failed execution."""
    pass


class OCBInvalidScript(NCError):
    """Raised when an On-Chain Blueprint script does not pass our script restrictions check.
    """
    pass


class OCBInvalidBlueprintVertexType(NCError):
    """Raised when a vertex that is not an OnChainBlueprint is used as a blueprint-id.
    """
    pass


class OCBBlueprintNotConfirmed(NCError):
    """Raised when trying to use an OnChainBlueprint that is not confirmed by a block in the current best chain.
    """


class OCBPubKeyNotAllowed(NCError):
    """Raised when an OnChainBlueprint transaction uses a pubkey that is not explicitly allowed in the settings.
    """


class OCBOutOfFuelDuringLoading(NCError):
    """Raised when loading an On-chain Blueprint and the execution exceeds the fuel limit.
    """


class OCBOutOfMemoryDuringLoading(NCError):
    """Raised when loading an On-chain Blueprint and the execution exceeds the memory limit.
    """


class NCDisabledBuiltinError(NCError):
    """Raised when a disabled builtin is used during creation or execution of a nanocontract.
    """


class NCUnhandledUserException(Exception):
    """
    Raised to signal an unhandled exception was raised by blueprint code during execution of a nano contract method.

    ATTENTION: This shouldn't be used anywhere but in the `MeteredExecutor.call()` method.
    """

"""
ATTENTION: DO NOT subclass or raise this exception in internal code.
We may allow blueprints to catch them at some point.
"""
class NCFail(NCError):
    """
    Raised by Blueprint methods to fail execution.
    May be subclassed in blueprints for custom exceptions.
    """

NCInternalFailure: TypeAlias = (
    NanoContractDoesNotExist
    | BlueprintDoesNotExist
    | NCSerializationError
    | NCViewMethodError
    | NCMethodNotFound
    | NCInsufficientFunds
    | NCAttributeError
    | NCInvalidContext
    | NCRecursionError
    | NCNumberOfCallsExceeded
    | NCInvalidContractId
    | NCInvalidMethodCall
    | NCInvalidInitializeMethodCall
    | NCInvalidPublicMethodCallFromView
    | NCAlreadyInitializedContractError
    | NCUninitializedContractError
    | NCInvalidAction
    | NCInvalidSyscall
    | NCTokenAlreadyExists
    | NCForbiddenAction
)

"""
A type that represents all possible errors that can happen during a nano contract method execution,
which can either be a specific internal exception, an NCFail raised explicitly by blueprint code,
or an unhandled exception raised by blueprint code (NCUnhandledUserException).
For internal use only, should NOT be used by blueprints.
"""
NCFailure: TypeAlias = NCInternalFailure | NCFail | NCUnhandledUserException
