# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor.exception import HathorError
from hathorlib.exceptions import TransactionDoesNotExist


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
