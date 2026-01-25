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

from hathor.exception import HathorError
from hathor.transaction.exceptions import TxValidationError

"""
All exceptions in this module MUST inherit from NCFail so they're
correctly caught by the block consensus to fail NC transactions.
"""


class NCFail(HathorError):
    """Raised by Blueprint's methods to fail execution."""


class BlueprintSyntaxError(SyntaxError, NCFail):
    """Raised when a blueprint contains invalid syntax."""
    pass


class NCTxValidationError(TxValidationError, NCFail):
    pass


class NCInvalidSignature(NCTxValidationError, NCFail):
    pass


class NCInvalidPubKey(NCTxValidationError, NCFail):
    pass


class NCInvalidSeqnum(NCTxValidationError, NCFail):
    pass


class NanoContractDoesNotExist(NCFail):
    pass


class BlueprintDoesNotExist(NCFail):
    pass


class NCSerializationError(NCFail):
    pass


class NCSerializationArgTooLong(NCSerializationError):
    pass


class NCSerializationTypeError(NCSerializationError):
    pass


class NCViewMethodError(NCFail):
    """Raised when a view method changes the state of the contract."""
    pass


class NCMethodNotFound(NCTxValidationError):
    """Raised when a method is not found in a nano contract."""
    pass


class NCInsufficientFunds(NCFail):
    """Raised when there is not enough funds to withdrawal from a nano contract."""
    pass


class NCAttributeError(NCFail):
    pass


class NCInvalidContext(NCFail):
    """Raised when trying to run a method with an invalid context."""
    pass


class NCRecursionError(NCFail):
    """Raised when recursion gets too deep."""


class NCNumberOfCallsExceeded(NCFail):
    """Raised when the total number of calls have been exceeded."""


class NCInvalidContractId(NCFail):
    """Raised when a contract call is invalid."""


class NCInvalidMethodCall(NCTxValidationError):
    """Raised when a contract calls another contract's invalid method."""


class NCInvalidFeePaymentToken(NCFail):
    """Raised when a payment token is invalid."""


class NCInvalidInitializeMethodCall(NCFail):
    """Raised when a contract calls another contract's initialize method."""


class NCInvalidPublicMethodCallFromView(NCFail):
    """Raised when a contract calls another contract's initialize method."""


class NCAlreadyInitializedContractError(NCFail):
    """Raised when one tries to initialize a contract that has already been initialized."""


class NCUninitializedContractError(NCFail):
    """Raised when a contract calls a method from an uninitialized contract."""


class NCInvalidAction(NCFail):
    """Raised when an action is invalid."""
    pass


class NCInvalidFee(NCFail):
    """Raised when a fee is invalid."""
    pass


class NCInvalidSyscall(NCFail):
    """Raised when a syscall is invalid."""
    pass


class NCTokenAlreadyExists(NCFail):
    """Raised when one tries to create a duplicated token."""


class NCForbiddenAction(NCFail):
    """Raised when an action is forbidden on a method."""
    pass


class NCForbiddenReentrancy(NCFail):
    """Raised when a reentrancy is forbidden on a method."""
    pass


class NCTypeError(NCFail):
    """Raised when a wrong type is used."""
    pass


class UnknownFieldType(NCFail):
    """Raised when there is no field available for a given type."""
    pass


class NCContractCreationNotFound(NCFail):
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


class OCBInvalidScript(NCFail):
    """Raised when an On-Chain Blueprint script does not pass our script restrictions check.
    """
    pass


class OCBInvalidBlueprintVertexType(NCFail):
    """Raised when a vertex that is not an OnChainBlueprint is used as a blueprint-id.
    """
    pass


class OCBBlueprintNotConfirmed(NCFail):
    """Raised when trying to use an OnChainBlueprint that is not confirmed by a block in the current best chain.
    """


class OCBPubKeyNotAllowed(NCFail):
    """Raised when an OnChainBlueprint transaction uses a pubkey that is not explicitly allowed in the settings.
    """


class OCBOutOfFuelDuringLoading(NCFail):
    """Raised when loading an On-chain Blueprint and the execution exceeds the fuel limit.
    """


class OCBOutOfMemoryDuringLoading(NCFail):
    """Raised when loading an On-chain Blueprint and the execution exceeds the memory limit.
    """


class NCDisabledBuiltinError(NCFail):
    """Raised when a disabled builtin is used during creation or execution of a nanocontract.
    """


class SandboxRequiredButNotAvailable(Exception):
    """Raised when sandbox config is provided but sys.sandbox is not available.

    This error indicates that the code requires a custom Python build with sandbox support.
    The Python version should have the suffix '-sandbox' (e.g., '3.12.0-sandbox').
    """

    def __init__(self) -> None:
        super().__init__(
            "Sandbox is required but not available. "
            "This requires a custom Python build with sandbox support. "
            "Check that `python -V` shows a version with the '-sandbox' suffix "
            "(e.g., 'Python 3.12.0-sandbox')."
        )
