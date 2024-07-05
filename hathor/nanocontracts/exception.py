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


class NCError(HathorError):
    """Base exception for nano contract's exceptions."""
    pass


class NCSerializationError(NCError):
    pass


class NCSerializationArgTooLong(NCSerializationError):
    pass


class NCSerializationTypeError(NCSerializationError):
    pass


class NCTxValidationError(TxValidationError):
    pass


class NCInvalidSignature(NCTxValidationError):
    pass


class NCInvalidPubKey(NCTxValidationError):
    pass


class NCMethodNotFound(NCTxValidationError):
    """Raised when a method is not found in a nano contract."""
    pass


class BlueprintDoesNotExist(NCTxValidationError):
    pass


class NanoContractDoesNotExist(NCTxValidationError):
    pass


class NCPrivateMethodError(NCError):
    """Raised when a private method changes the state of the contract."""


class NCFail(NCError):
    """Raised by Blueprint's methods to fail execution."""
    pass


class NCInsufficientFunds(NCFail):
    """Raised when there is not enough funds to withdrawal from a nano contract."""
    pass


class NCAttributeError(NCFail):
    pass


class NCInvalidContext(NCFail):
    """Raised when trying to run a method with an invalid context."""
    pass


class UnknownFieldType(NCError):
    """Raised when there is no field available for a given type."""
    pass


class NCContractCreationNotFound(NCError):
    pass
