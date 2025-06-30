from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.manager import HathorManager
from hathor.nanocontracts import Context
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.blueprint_env import BlueprintEnvironment
from hathor.nanocontracts.nc_exec_logs import NCLogConfig
from hathor.nanocontracts.storage import NCBlockStorage, NCMemoryStorageFactory
from hathor.nanocontracts.storage.backends import MemoryNodeTrieStore
from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
from hathor.nanocontracts.types import Address, BlueprintId, ContractId, NCAction, TokenUid, VertexId
from hathor.nanocontracts.vertex_data import VertexData
from hathor.transaction import BaseTransaction, Transaction
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
        return self.create_peer('testnet', nc_indexes=True, nc_log_config=NCLogConfig.FAILED, wallet_index=True)

    def get_readonly_contract(self, contract_id: ContractId) -> Blueprint:
        """ Returns a read-only instance of a given contract to help testing it.

        The returned instance cannot be used for writing, use `get_readwrite_contract` if you need to test writing.
        """
        return self._get_contract_instance(contract_id, locked=True)

    def get_readwrite_contract(self, contract_id: ContractId) -> Blueprint:
        """ Returns a read-write instance of a given contract to help testing it.

        The returned instance can be used to write attributes, if you don't need to write anything it is recommended to
        use `get_readonly_contract` instead to avoid accidental writes.
        """
        return self._get_contract_instance(contract_id, locked=False)

    def _get_contract_instance(self, contract_id: ContractId, *, locked: bool) -> Blueprint:
        """ Implementation of `get_readonly_contract` and `get_readwrite_contract`, only difference is `locked`
        """
        from hathor.nanocontracts.nc_exec_logs import NCLogger
        runner = self.runner
        contract_storage = runner.get_storage(contract_id)
        if locked:
            contract_storage.lock()
        else:
            contract_storage.unlock()
        nc_logger = NCLogger(__reactor__=runner.reactor, __nc_id__=contract_id)
        env = BlueprintEnvironment(runner, nc_logger, contract_storage, disable_cache=True)
        blueprint_id = runner.get_blueprint_id(contract_id)
        blueprint_class = runner.tx_storage.get_blueprint_class(blueprint_id)
        contract = blueprint_class(env)
        return contract

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

    def gen_random_contract_id(self) -> ContractId:
        """Generate a random contract id."""
        return ContractId(VertexId(self.rng.randbytes(32)))

    def gen_random_blueprint_id(self) -> BlueprintId:
        """Generate a random contract id."""
        return BlueprintId(self.rng.randbytes(32))

    def get_genesis_tx(self) -> Transaction:
        """Return a genesis transaction."""
        genesis = self.manager.tx_storage.get_all_genesis()
        tx = list(tx for tx in genesis if isinstance(tx, Transaction))[0]
        return tx

    def create_context(
        self,
        actions: list[NCAction] | None = None,
        vertex: BaseTransaction | VertexData | None = None,
        address: Address | None = None,
        timestamp: int | None = None,
    ) -> Context:
        """Create a Context instance with optional values or defaults."""
        return Context(
            actions=actions if actions is not None else [],
            vertex=vertex or self.get_genesis_tx(),
            address=address or self.gen_random_address(),
            timestamp=timestamp or self.now,
        )
