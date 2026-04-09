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

from contextlib import contextmanager
from enum import Flag, auto
from typing import TYPE_CHECKING, Generator

from hathor.transaction.base_transaction import BaseTransaction

if TYPE_CHECKING:
    from hathor.transaction.storage import TransactionStorage  # noqa: F401


class TxAllowScope(Flag):
    """ This enum is used internally to mark which "type" of transactions to allow the database to read/write

    In this context "type" it means validation level, the supported "types" are enumerated in this class and for the
    purpose of filtering it can be any combination of the supported types.
    """
    VALID = auto()
    PARTIAL = auto()
    INVALID = auto()
    ALL = VALID | PARTIAL | INVALID

    def is_allowed(self, tx: BaseTransaction) -> bool:
        """True means it is allowed to be used in the storage (as argument or as return), False means not allowed."""
        tx_meta = tx.get_metadata()
        # XXX: partial/invalid/fully_connected never overlap and cover all possible validation states
        #      see hathor.transaction.transaction_metadata.ValidationState for more details
        validation = tx_meta.validation
        if validation.is_partial() and TxAllowScope.PARTIAL not in self:
            return False
        if validation.is_invalid() and TxAllowScope.INVALID not in self:
            return False
        # XXX: not allowing valid transactions is really specific, should we allow it?
        if validation.is_fully_connected() and TxAllowScope.VALID not in self:
            return False
        return True


@contextmanager
def tx_allow_context(tx_storage: 'TransactionStorage', *, allow_scope: TxAllowScope) -> Generator[None, None, None]:
    """This is used to wrap the storage with a temporary allow-scope that is reverted when the context exits"""
    from hathor.transaction.storage import TransactionStorage
    assert isinstance(tx_storage, TransactionStorage)
    previous_allow_scope = tx_storage.get_allow_scope()
    try:
        tx_storage.set_allow_scope(allow_scope)
        yield
    finally:
        tx_storage.set_allow_scope(previous_allow_scope)
