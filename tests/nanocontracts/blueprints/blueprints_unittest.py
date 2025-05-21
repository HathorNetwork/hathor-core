from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.manager import HathorManager
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.storage import NCBlockStorage, NCMemoryStorageFactory
from hathor.nanocontracts.storage.backends import MemoryNodeTrieStore
from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
from hathor.nanocontracts.types import Address, BlueprintId, ContractId, TokenUid, VertexId
from hathor.transaction import Transaction
from hathor.util import not_none
from hathor.wallet import KeyPair
from tests import unittest
from tests.nanocontracts.utils import TestRunner

settings = HathorSettings()


class BlueprintTestCase(unittest.TestCase):
    use_memory_storage = True

    def setUp(self):
        super().setUp()
        self.manager = self.build_manager()
        self.rng = self.manager.rng
        self.wallet = self.manager.wallet
        self.reactor = self.manager.reactor
        self.nc_catalog = self.manager.tx_storage.nc_catalog

        self.htr_token_uid = settings.HATHOR_TOKEN_UID
        self.runner = self.build_runner()
        self.now = int(self.reactor.seconds())

        self._token_index = 1

    def build_manager(self) -> HathorManager:
        """Create a HathorManager instance."""
        return self.create_peer('testnet', nc_indices=True)

    def register_blueprint_class(self, blueprint_id: BlueprintId, blueprint_class: type[Blueprint]) -> None:
        """Register a blueprint class with a given id, allowing contracts to be created from it."""
        assert blueprint_id not in self.nc_catalog.blueprints
        self.nc_catalog.blueprints[blueprint_id] = blueprint_class

    def build_runner(self) -> TestRunner:
        """Create a Runner instance."""
        nc_storage_factory = NCMemoryStorageFactory()
        store = MemoryNodeTrieStore()
        block_trie = PatriciaTrie(store)
        block_storage = NCBlockStorage(block_trie)
        return TestRunner(
            self.manager.tx_storage, nc_storage_factory, block_storage, settings=self._settings, reactor=self.reactor
        )

    def gen_random_token_uid(self) -> TokenUid:
        """Generate a random token UID (32 bytes)."""
        token = self._token_index.to_bytes(32, byteorder='big', signed=False)
        self._token_index += 1
        return TokenUid(token)

    def gen_random_address(self) -> Address:
        """Generate a random wallet address."""
        address, _ = self.gen_random_address_with_key()
        return address

    def gen_random_address_with_key(self) -> tuple[Address, KeyPair]:
        """Generate a random wallet address with its key."""
        password = self.rng.randbytes(12)
        key = KeyPair.create(password)
        address_b58 = key.address
        address_bytes = decode_address(not_none(address_b58))
        return Address(address_bytes), key

    def gen_random_nanocontract_id(self) -> ContractId:
        """Generate a random contract id."""
        return ContractId(VertexId(self.rng.randbytes(32)))

    def gen_random_blueprint_id(self) -> BlueprintId:
        """Generate a random contract id."""
        return BlueprintId(self.rng.randbytes(32))

    def get_genesis_tx(self):
        """Return a genesis transaction."""
        genesis = self.manager.tx_storage.get_all_genesis()
        tx = list(tx for tx in genesis if isinstance(tx, Transaction))[0]
        return tx
