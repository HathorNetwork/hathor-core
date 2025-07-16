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

from hathor.nanocontracts.error_handling import NCInternalException, NCUserException

"""
This module contains exceptions related to Nano Contracts.

IMPORTANT: Exception handling during contract execution is critical. It's essential to choose the right type when
subclassing an NC-related exception. Read the error_handling module for more information.

Exceptions that are raised during Nano Contract execution will either:

- Fail the transaction and become part of the blockchain state when they inherit from NCInternalException.
- Be considered a bug and crash the full node when they do not inherit from NCInternalException.

When they are raised outside contract execution, such as during verification, they must either inherit from
HathorError or be an __NCTransactionFail__ to make sure the transaction fails verification.
"""


class BlueprintSyntaxError(NCInternalException):
    """Raised when a blueprint contains invalid syntax."""
    pass


class NCInvalidSignature(NCInternalException):
    pass


class NCInvalidPubKey(NCInternalException):
    pass


class NanoContractDoesNotExist(NCInternalException):
    pass


class BlueprintDoesNotExist(NCInternalException):
    pass


class NCSerializationError(NCInternalException):
    pass


class NCSerializationArgTooLong(NCSerializationError):
    pass


class NCViewMethodError(NCInternalException):
    """Raised when a view method changes the state of the contract."""
    pass


class NCMethodNotFound(NCInternalException):
    """Raised when a method is not found in a nano contract."""
    pass


class NCInsufficientFunds(NCInternalException):
    """Raised when there is not enough funds to withdrawal from a nano contract."""
    pass


class NCAttributeError(NCInternalException):
    pass


class NCInvalidContext(NCInternalException):
    """Raised when trying to run a method with an invalid context."""
    pass


class NCRecursionError(NCInternalException):
    """Raised when recursion gets too deep."""


class NCNumberOfCallsExceeded(NCInternalException):
    """Raised when the total number of calls have been exceeded."""


class NCInvalidContractId(NCInternalException):
    """Raised when a contract call is invalid."""


class NCInvalidMethodCall(NCInternalException):
    """Raised when a contract calls another contract's invalid method."""


class NCInvalidInitializeMethodCall(NCInternalException):
    """Raised when a contract calls another contract's initialize method."""


class NCInvalidPublicMethodCallFromView(NCInternalException):
    """Raised when a contract calls another contract's initialize method."""


class NCAlreadyInitializedContractError(NCInternalException):
    """Raised when one tries to initialize a contract that has already been initialized."""


class NCUninitializedContractError(NCInternalException):
    """Raised when a contract calls a method from an uninitialized contract."""


class NCInvalidAction(NCInternalException):
    """Raised when an action is invalid."""
    pass


class NCInvalidSyscall(NCInternalException):
    """Raised when a syscall is invalid."""
    pass


class NCTokenAlreadyExists(NCInternalException):
    """Raised when one tries to create a duplicated token."""


class NCForbiddenAction(NCInternalException):
    """Raised when an action is forbidden on a method."""
    pass


class UnknownFieldType(NCInternalException):
    """Raised when there is no field available for a given type."""
    pass


class NCContractCreationNotFound(NCInternalException):
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


class OCBInvalidScript(NCInternalException):
    """Raised when an On-Chain Blueprint script does not pass our script restrictions check.
    """
    pass


class OCBInvalidBlueprintVertexType(NCInternalException):
    """Raised when a vertex that is not an OnChainBlueprint is used as a blueprint-id.
    """
    pass


class OCBBlueprintNotConfirmed(NCInternalException):
    """Raised when trying to use an OnChainBlueprint that is not confirmed by a block in the current best chain.
    """


class OCBPubKeyNotAllowed(NCInternalException):
    """Raised when an OnChainBlueprint transaction uses a pubkey that is not explicitly allowed in the settings.
    """


class OCBOutOfFuelDuringLoading(NCInternalException):
    """Raised when loading an On-chain Blueprint and the execution exceeds the fuel limit.
    """


class OCBOutOfMemoryDuringLoading(NCInternalException):
    """Raised when loading an On-chain Blueprint and the execution exceeds the memory limit.
    """


class NCDisabledBuiltinError(NCInternalException):
    """Raised when a disabled builtin is used during creation or execution of a nanocontract.
    """


"""
Just a type alias for compatibility. Represents an exception that may only be raised from user code in blueprints.
"""
NCFail: TypeAlias = NCUserException
