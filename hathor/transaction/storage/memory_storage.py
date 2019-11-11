from typing import Dict, Iterator, TypeVar

from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.storage.transaction_storage import BaseTransactionStorage, TransactionStorageAsyncFromSync
from hathor.transaction.transaction import BaseTransaction
from hathor.transaction.transaction_metadata import TransactionMetadata
from hathor.util import deprecated, skip_warning

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
        self._clone_if_needed = _clone_if_needed
        super().__init__(with_index=with_index)

    def _clone(self, x: _Clonable) -> _Clonable:
        if self._clone_if_needed:
            return x.clone()
        else:
            return x

    @deprecated('Use remove_transaction_deferred instead')
    def remove_transaction(self, tx: BaseTransaction) -> None:
        assert tx.hash is not None
        skip_warning(super().remove_transaction)(tx)
        self.transactions.pop(tx.hash, None)
        self.metadata.pop(tx.hash, None)

    @deprecated('Use save_transaction_deferred instead')
    def save_transaction(self, tx: BaseTransaction, *, only_metadata: bool = False) -> None:
        skip_warning(super().save_transaction)(tx, only_metadata=only_metadata)
        self._save_transaction(tx, only_metadata=only_metadata)

    def _save_transaction(self, tx: BaseTransaction, *, only_metadata: bool = False) -> None:
        assert tx.hash is not None
        if not only_metadata:
            if not tx.is_genesis:
                self.transactions[tx.hash] = self._clone(tx)
        meta = getattr(tx, '_metadata', None)
        if meta:
            self.metadata[tx.hash] = self._clone(meta)

    @deprecated('Use transaction_exists_deferred instead')
    def transaction_exists(self, hash_bytes: bytes) -> bool:
        genesis = self.get_genesis(hash_bytes)
        if genesis:
            return True
        return hash_bytes in self.transactions

    @deprecated('Use get_transaction_deferred instead')
    def get_transaction(self, hash_bytes: bytes) -> BaseTransaction:
        genesis = self.get_genesis(hash_bytes)
        if genesis:
            if hash_bytes in self.metadata:
                genesis._metadata = self._clone(self.metadata[hash_bytes])
            return genesis

        if hash_bytes in self.transactions:
            tx = self._clone(self.transactions[hash_bytes])
            if hash_bytes in self.metadata:
                tx._metadata = self._clone(self.metadata[hash_bytes])
            return tx
        else:
            raise TransactionDoesNotExist(hash_bytes.hex())

    @deprecated('Use get_all_transactions_deferred instead')
    def get_all_transactions(self) -> Iterator[BaseTransaction]:
        for tx in self.get_all_genesis():
            # Genesis metadata is not saved in the storage because they are kept in memory
            # so we don't need to take care of it here
            tx = self._clone(tx)
            yield tx
        for tx in self.transactions.values():
            tx = self._clone(tx)
            if tx.hash in self.metadata:
                tx._metadata = self._clone(self.metadata[tx.hash])
            yield tx

    @deprecated('Use get_count_tx_blocks_deferred instead')
    def get_count_tx_blocks(self) -> int:
        genesis_len = len(self.get_all_genesis())
        return len(self.transactions) + genesis_len
