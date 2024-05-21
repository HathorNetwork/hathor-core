
from hathor.nanocontracts.runner import Runner
from hathor.nanocontracts.storage import NCStorageFactory
from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
from hathor.transaction.storage import TransactionStorage


class TestRunner(Runner):
    __test__ = False

    def __init__(self,
                 tx_storage: TransactionStorage,
                 storage_factory: NCStorageFactory,
                 block_trie: PatriciaTrie,
                 *,
                 seed: bytes | None = None) -> None:
        if seed is None:
            seed = b'x' * 32
        super().__init__(tx_storage, storage_factory, block_trie, seed=seed)
