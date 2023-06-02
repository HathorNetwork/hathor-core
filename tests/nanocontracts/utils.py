from typing import Type

from hathor.nanocontracts import Blueprint
from hathor.nanocontracts.runner import Runner
from hathor.nanocontracts.storage import NCStorageFactory
from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
from hathor.nanocontracts.types import ContractId
from hathor.transaction.storage import TransactionStorage


class TestRunner(Runner):
    __test__ = False

    def __init__(self,
                 tx_storage: TransactionStorage,
                 storage_factory: NCStorageFactory,
                 block_trie: PatriciaTrie) -> None:
        super().__init__(tx_storage, storage_factory, block_trie)
        self._contracts: dict[ContractId, Type[Blueprint]] = {}

    def register_contract(self, blueprint_class: Type[Blueprint], nanocontract_id: ContractId) -> None:
        if nanocontract_id in self._contracts:
            raise KeyError('contract already registered')
        self._contracts[nanocontract_id] = blueprint_class

    def get_blueprint_class(self, nanocontract_id: ContractId) -> Type[Blueprint]:
        return self._contracts[nanocontract_id]
