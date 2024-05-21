from enum import Enum
from typing import NamedTuple, Optional

from hathor.nanocontracts.storage.contract_storage import NCContractStorage
from hathor.nanocontracts.storage.patricia_trie import NodeId, PatriciaTrie
from hathor.nanocontracts.types import ContractId


class _Tag(Enum):
    CONTRACT = b'\0'


class ContractKey(NamedTuple):
    nc_id: bytes

    def __bytes__(self):
        return _Tag.CONTRACT.value + self.nc_id


class NCBlockStorage:
    """This is the storage used by NanoContracts.

    This implementation works for both memory and rocksdb backends."""

    def __init__(self, block_trie: PatriciaTrie) -> None:
        self._block_trie: PatriciaTrie = block_trie

    def has_contract(self, contract_id: ContractId) -> bool:
        try:
            self.get_contract_root_id(contract_id)
        except KeyError:
            return False
        else:
            return True

    def get_contract_root_id(self, contract_id: ContractId) -> bytes:
        """Return the root id of a contract's storage."""
        key = ContractKey(contract_id)
        return self._block_trie.get(bytes(key))

    def update_contract_trie(self, nc_id: ContractId, root_id: bytes) -> None:
        key = ContractKey(nc_id)
        self._block_trie.update(bytes(key), root_id)

    def commit(self) -> None:
        """Flush all local changes to the storage."""
        self._block_trie.commit()

    def get_root_id(self) -> bytes:
        """Return the current merkle root id of the trie."""
        return self._block_trie.root.id

    @staticmethod
    def bytes_to_node_id(node_id: Optional[bytes]) -> Optional[NodeId]:
        if node_id is None:
            return node_id
        return NodeId(node_id)

    def _get_trie(self, root_id: Optional[bytes]) -> 'PatriciaTrie':
        """Return a PatriciaTrie object with a given root."""
        from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
        store = self._block_trie.get_store()
        trie = PatriciaTrie(store, root_id=self.bytes_to_node_id(root_id))
        return trie

    def get_contract_storage(self, contract_id: ContractId) -> NCContractStorage:
        nc_root_id = self.get_contract_root_id(contract_id)
        trie = self._get_trie(nc_root_id)
        return NCContractStorage(trie=trie, nc_id=contract_id)
