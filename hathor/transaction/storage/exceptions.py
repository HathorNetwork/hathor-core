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

from hathor.exception import HathorError


class TransactionDoesNotExist(HathorError):
    """You are trying to get a transaction that does not exist"""


class TokenCreationTransactionDoesNotExist(TransactionDoesNotExist):
    """You are trying to get a token creation transaction that does not exist"""


class TransactionMetadataDoesNotExist(HathorError):
    """You are trying to get a metadata (of a transaction) that does not exist"""


class TransactionIsNotABlock(HathorError):
    """You are trying to get a block transaction but it's not a Block type"""


class AttributeDoesNotExist(HathorError):
    """You are trying to get a storage attribute that does not exist"""


class WrongNetworkError(HathorError):
    """You are trying to use a database for a different network"""


class PartialMigrationError(HathorError):
    """You are trying to run a migration that did not run until the end, the database could be unusable"""


class OutOfOrderMigrationError(HathorError):
    """A migration was run before another that was before it"""


class TransactionNotInAllowedScopeError(TransactionDoesNotExist):
    """You are trying to get a transaction that is not allowed in the current scope, treated as non-existent"""
