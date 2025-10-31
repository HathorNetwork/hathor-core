from io import TextIOWrapper
from typing import Sequence

from hathor.crypto.util import decode_address
from hathor.manager import HathorManager
from hathor.nanocontracts import HATHOR_TOKEN_UID, Context
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.blueprint_env import BlueprintEnvironment
from hathor.nanocontracts.nc_exec_logs import NCLogConfig
from hathor.nanocontracts.on_chain_blueprint import Code, OnChainBlueprint
from hathor.nanocontracts.types import Address, BlueprintId, ContractId, NCAction, TokenUid, VertexId
from hathor.nanocontracts.vertex_data import BlockData, VertexData
from hathor.transaction import Transaction, Vertex
from hathor.transaction.token_info import TokenVersion
from hathor.util import not_none
from hathor.verification.on_chain_blueprint_verifier import OnChainBlueprintVerifier
from hathor.wallet import KeyPair
from hathor_tests import unittest
from hathor_tests.nanocontracts.utils import TestRunner


class BlueprintTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.manager = self.build_manager()
        self.rng = self.manager.rng
        self.wallet = self.manager.wallet
        self.reactor = self.manager.reactor
        self.nc_catalog = self.manager.tx_storage.nc_catalog

        self.htr_token_uid = HATHOR_TOKEN_UID
        self.runner = self.build_runner()
        self.now = int(self.reactor.seconds())

        self._token_index = 1

    def build_manager(self) -> HathorManager:
        """Create a HathorManager instance."""
        return self.create_peer('unittests', nc_indexes=True, nc_log_config=NCLogConfig.FAILED, wallet_index=True)

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

    def _register_blueprint_class(
        self,
        blueprint_class: type[Blueprint],
        blueprint_id: BlueprintId | None = None,
    ) -> BlueprintId:
        """Register a blueprint class with an optional id, allowing contracts to be created from it."""
        if blueprint_id is None:
            blueprint_id = self.gen_random_blueprint_id()

        assert blueprint_id not in self.nc_catalog.blueprints
        self.nc_catalog.blueprints[blueprint_id] = blueprint_class
        return blueprint_id

    def register_blueprint_file(self, path: str, blueprint_id: BlueprintId | None = None) -> BlueprintId:
        """Register a blueprint file with an optional id, allowing contracts to be created from it."""
        with open(path, 'r') as f:
            return self._register_blueprint_contents(f, blueprint_id)

    def _register_blueprint_contents(
        self,
        contents: TextIOWrapper,
        blueprint_id: BlueprintId | None = None,
        *,
        skip_verification: bool = False,
        inject_in_class: dict[str, object] | None = None,
    ) -> BlueprintId:
        """
        Register blueprint contents with an optional id, allowing contracts to be created from it.

        Args:
            contents: the blueprint source code, usually a file or StringIO
            blueprint_id: optional ID for the blueprint
            skip_verification: skip verifying the blueprint with restrictions such as AST verification
            inject_in_class: objects to inject in the blueprint class, accessible in contract runtime

        Returns: the blueprint_id
        """
        code = Code.from_python_code(contents.read(), self._settings)
        ocb = OnChainBlueprint(hash=b'', code=code)

        if not skip_verification:
            verifier = OnChainBlueprintVerifier(settings=self._settings)
            verifier.verify_code(ocb)

        blueprint_class = ocb.get_blueprint_class()
        if inject_in_class is not None:
            for key, value in inject_in_class.items():
                setattr(blueprint_class, key, value)

        return self._register_blueprint_class(blueprint_class, blueprint_id)

    def build_runner(self) -> TestRunner:
        """Create a Runner instance."""
        return TestRunner(
            tx_storage=self.manager.tx_storage,
            settings=self._settings,
            reactor=self.reactor,
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
        tx = self.manager.tx_storage.get_genesis(self._settings.GENESIS_TX1_HASH)
        assert isinstance(tx, Transaction)
        return tx

    def create_context(
        self,
        actions: Sequence[NCAction] | None = None,
        vertex: Vertex | None = None,
        caller_id: Address | None = None,
        timestamp: int | None = None,
    ) -> Context:
        """Create a Context instance with optional values or defaults."""
        return Context(
            caller_id=caller_id or self.gen_random_address(),
            vertex_data=VertexData.create_from_vertex(vertex or self.get_genesis_tx()),
            block_data=BlockData(hash=VertexId(b''), timestamp=timestamp or 0, height=0),
            actions=Context.__group_actions__(actions or ()),
        )

    def create_token(
        self,
        token_uid: TokenUid,
        token_name: str,
        token_symbol:
        str,
        token_version: TokenVersion
    ) -> None:
        """Create a token in the runner block storage"""
        self.runner.block_storage.create_token(
            token_id=token_uid,
            token_name=token_name,
            token_symbol=token_symbol,
            token_version=token_version
        )
