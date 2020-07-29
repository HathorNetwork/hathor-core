from typing import Dict, Iterator, Optional, TypeVar

from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.storage.transaction_storage import BaseTransactionStorage, TransactionStorageAsyncFromSync
from hathor.transaction.transaction import BaseTransaction
from hathor.transaction.transaction_metadata import TransactionMetadata

_Clonable = TypeVar('_Clonable', BaseTransaction, TransactionMetadata)


class TransactionMemoryStorage(BaseTransactionStorage, TransactionStorageAsyncFromSync):
    def __init__(self, with_index: bool = True, *, _clone_if_needed: bool = False) -> None:
        """
        :param _clone_if_needed: *private parameter*, defaults to True, controls whether to clone
                                 transaction/blocks/metadata when returning those objects.
        :type _clone_if_needed: bool
        """
        self.transactions: Dict[bytes, BaseTransaction] = {}
        self.metadata: Dict[bytes, TransactionMetadata] = {}
        # Store custom key/value attributes
        self.attributes: Dict[str, Any] = {}
        self._clone_if_needed = _clone_if_needed
        super().__init__(with_index=with_index)

    def _clone(self, x: _Clonable) -> _Clonable:
        if self._clone_if_needed:
            return x.clone()
        else:
            return x

    def remove_transaction(self, tx: BaseTransaction) -> None:
        assert tx.hash is not None
        super().remove_transaction(tx)
        self.transactions.pop(tx.hash, None)
        self.metadata.pop(tx.hash, None)

    def save_transaction(self, tx: BaseTransaction, *, only_metadata: bool = False) -> None:
        super().save_transaction(tx, only_metadata=only_metadata)
        self._save_transaction(tx, only_metadata=only_metadata)

    def _save_transaction(self, tx: BaseTransaction, *, only_metadata: bool = False) -> None:
        assert tx.hash is not None
        if not only_metadata:
            self.transactions[tx.hash] = self._clone(tx)
        meta = getattr(tx, '_metadata', None)
        if meta:
            self.metadata[tx.hash] = self._clone(meta)

    def transaction_exists(self, hash_bytes: bytes) -> bool:
        return hash_bytes in self.transactions

    def _get_transaction(self, hash_bytes: bytes) -> BaseTransaction:
        if hash_bytes in self.transactions:
            tx = self._clone(self.transactions[hash_bytes])
            if hash_bytes in self.metadata:
                tx._metadata = self._clone(self.metadata[hash_bytes])
            return tx
        else:
            raise TransactionDoesNotExist(hash_bytes.hex())

    def get_all_transactions(self) -> Iterator[BaseTransaction]:
        for tx in self.transactions.values():
            tx = self._clone(tx)
            if tx.hash in self.metadata:
                tx._metadata = self._clone(self.metadata[tx.hash])
            yield tx

    def get_count_tx_blocks(self) -> int:
        return len(self.transactions)

    def add_value(self, key: str, value: str) -> None:
        self.attributes[key] = value

    def remove_value(self, key: str) -> None:
        self.attributes.pop(key, None)

    def get_value(self, key: str) -> Optional[str]:
        return self.attributes.get(key)
