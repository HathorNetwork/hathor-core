from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.manager import HathorManager
from hathor.nanocontracts.storage import NCMemoryStorageFactory
from hathor.nanocontracts.storage.backends import MemoryNodeTrieStore
from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
from hathor.nanocontracts.types import ContractId
from hathor.transaction import Transaction
from hathor.types import Address, TokenUid
from hathor.util import not_none
from hathor.wallet import KeyPair
from tests import unittest
from tests.nanocontracts.utils import TestRunner

settings = HathorSettings()


class BlueprintTestCase(unittest.TestCase):
    _enable_sync_v1 = True
    _enable_sync_v2 = True
    use_memory_storage = True

    def setUp(self):
        super().setUp()
        self.manager = self.build_manager()
        self.rng = self.manager.rng
        self.wallet = self.manager.wallet
        self.reactor = self.manager.reactor

        self.htr_token_uid = settings.HATHOR_TOKEN_UID

        nc_storage_factory = NCMemoryStorageFactory()
        store = MemoryNodeTrieStore()
        block_trie = PatriciaTrie(store)
        self.runner = TestRunner(self.manager.tx_storage, nc_storage_factory, block_trie)

        self.now = int(self.reactor.seconds())

        self._token_index = 1

    def build_manager(self) -> HathorManager:
        return self.create_peer('testnet', use_memory_storage=True)

    def gen_random_token_uid(self) -> TokenUid:
        """Generate a random token UID (32 bytes)."""
        token = self._token_index.to_bytes(32, byteorder='big', signed=False)
        self._token_index += 1
        return token

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
        return address_bytes, key

    def gen_random_nanocontract_id(self) -> ContractId:
        """Generate a random contract id."""
        return ContractId(self.rng.randbytes(32))

    def get_genesis_tx(self):
        """Return a genesis transaction."""
        genesis = self.manager.tx_storage.get_all_genesis()
        tx = list(tx for tx in genesis if isinstance(tx, Transaction))[0]
        return tx
