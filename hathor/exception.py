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

from hathorlib.exceptions import HathorError  # noqa: F401


class BuilderError(Exception):
    """Base class for exceptions in builders."""
    pass


class BlockTemplateError(Exception):
    """Base class for exceptions generating block template."""
    pass


class BlockTemplateTimestampError(BlockTemplateError):
    """Raised when there is no timestamp available to prepare a block template."""
    pass


class InvalidNewTransaction(HathorError):
    """Raised when a new received tx/block is not valid.
    """
    pass


class PreInitializationError(HathorError):
    """Raised when there's anything wrong during pre-initialization that should cause it to be aborted.
    """


class InitializationError(HathorError):
    """Raised when there's anything wrong during initialization that should cause it to be aborted.
    """


class DoubleSpendingError(InvalidNewTransaction):
    """Raised when a new received tx/block is not valid because of a double spending.
    """
    pass


class SpendingVoidedError(InvalidNewTransaction):
    """Raised when a new received tx/block is not valid because of an attempt to spend a voided transaction.
    """
    pass


class RewardLockedError(InvalidNewTransaction):
    """Raised when a new received tx/block is not valid because of an attempt to spend a locked reward.
    """
    pass


class NonStandardTxError(InvalidNewTransaction):
    """Raised when a new received tx/block is not accepted because of a standard-tx rule.
    """
    pass
