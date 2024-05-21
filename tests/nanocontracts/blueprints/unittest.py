from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.runner import Runner
from hathor.nanocontracts.storage import NCMemoryStorage
from hathor.transaction import Transaction
from hathor.types import Address, TokenUid
from hathor.util import not_none
from hathor.wallet import KeyPair
from tests import unittest

settings = HathorSettings()


class BlueprintTestCase(unittest.TestCase):
    _enable_sync_v1 = True
    _enable_sync_v2 = True
    use_memory_storage = True

    def setUp(self):
        super().setUp()
        self.manager = self.create_peer('testnet')
        self.rng = self.manager.rng
        self.wallet = self.manager.wallet
        self.reactor = self.manager.reactor

        self.htr_token_uid = settings.HATHOR_TOKEN_UID
        self.nc_storage = NCMemoryStorage()
        self.now = int(self.reactor.seconds())

        self._token_index = 1

    def create_runner(self, blueprint: type[Blueprint]) -> Runner:
        """Create an NCRunner."""
        return Runner(blueprint, b'', self.nc_storage)

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

    def get_genesis_tx(self):
        """Return a genesis transaction."""
        genesis = self.manager.tx_storage.get_all_genesis()
        tx = list(tx for tx in genesis if isinstance(tx, Transaction))[0]
        return tx
