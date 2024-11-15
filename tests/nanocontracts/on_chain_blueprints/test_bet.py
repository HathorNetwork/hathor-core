import hashlib
import os
from typing import NamedTuple, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address, get_public_key_bytes_compressed
from hathor.nanocontracts import NanoContract, OnChainBlueprint
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.types import Address, ContractId, NCAction, NCActionType, SignedData
from hathor.simulator.utils import add_new_blocks
from hathor.transaction.scripts import P2PKH
from hathor.util import not_none
from hathor.wallet import KeyPair
from tests import unittest

settings = HathorSettings()


def _load_nc_code(filename: str) -> bytes:
    cur_dir = os.path.dirname(__file__)
    filepath = os.path.join(cur_dir, filename)
    code_bytes = bytearray()
    with open(filepath, 'rb') as nc_file:
        for line in nc_file.readlines():
            code_bytes.extend(line)
    return bytes(code_bytes)


ON_CHAIN_BET_NC_CODE: bytes = _load_nc_code('bet.py')


class OnChainBet(NamedTuple):
    Bet: type[Blueprint]
    DepositNotAllowed: type[NCFail]
    InsufficientBalance: type[NCFail]
    InvalidOracleSignature: type[NCFail]
    InvalidToken: type[NCFail]
    # Result: type[str]
    ResultAlreadySet: type[NCFail]
    ResultNotAvailable: type[NCFail]
    TooLate: type[NCFail]
    WithdrawalNotAllowed: type[NCFail]


class BetInfo(NamedTuple):
    key: KeyPair
    address: Address
    amount: int
    score: str


class OnChainBetBlueprintTestCase(unittest.TestCase):
    _enable_sync_v1 = True
    _enable_sync_v2 = True
    use_memory_storage = True
    on_chain_bet: OnChainBet

    def setUp(self):
        super().setUp()
        self.manager = self.create_peer('testnet')
        self.wallet = self.get_wallet()
        self.token_uid = settings.HATHOR_TOKEN_UID
        self.initialize_contract()  # will set self.on_chain_bet, self.nc_id, self.runner, self.nc_storage

    def _get_any_tx(self):
        genesis = self.manager.tx_storage.get_all_genesis()
        tx = list(genesis)[0]
        return tx

    def _get_any_address(self):
        password = os.urandom(12)
        key = KeyPair.create(password)
        address_b58 = key.address
        address_bytes = decode_address(not_none(address_b58))
        return address_bytes, key

    def get_current_timestamp(self):
        return int(self.clock.seconds())

    def _make_a_bet(self, amount: int, score: str, *, timestamp: Optional[int] = None) -> BetInfo:
        (address_bytes, key) = self._get_any_address()
        tx = self._get_any_tx()
        action = NCAction(NCActionType.DEPOSIT, self.token_uid, amount)
        if timestamp is None:
            timestamp = self.get_current_timestamp()
        context = Context([action], tx, address_bytes, timestamp=timestamp)
        self.runner.call_public_method(self.nc_id, 'bet', context, address_bytes, score)
        return BetInfo(key=key, address=address_bytes, amount=amount, score=score)

    def _set_result(self, result: str, oracle_key: Optional[KeyPair] = None) -> None:
        signed_result: SignedData[str] = SignedData(result, b'')

        if oracle_key is None:
            oracle_key = self.oracle_key

        signed_result.script_input = oracle_key.p2pkh_create_input_data(b'123', signed_result.get_data_bytes())

        tx = self._get_any_tx()
        context = Context([], tx, Address(b''), timestamp=self.get_current_timestamp())
        self.runner.call_public_method(self.nc_id, 'set_result', context, signed_result)
        self.assertEqual(self.nc_storage.get('final_result'), '2x2')

    def _withdraw(self, address: Address, amount: int) -> None:
        tx = self._get_any_tx()
        action = NCAction(NCActionType.WITHDRAWAL, self.token_uid, amount)
        context = Context([action], tx, address, timestamp=self.get_current_timestamp())
        self.runner.call_public_method(self.nc_id, 'withdraw', context)

    def _ocb_sign(self, blueprint: OnChainBlueprint) -> None:
        key = KeyPair(unittest.OCB_TEST_PRIVKEY)
        privkey = key.get_private_key(unittest.OCB_TEST_PASSWORD)
        pubkey = privkey.public_key()
        blueprint.nc_pubkey = get_public_key_bytes_compressed(pubkey)
        data = blueprint.get_sighash_all_data()
        blueprint.nc_signature = privkey.sign(data, ec.ECDSA(hashes.SHA256()))

    def _ocb_mine(self, blueprint: OnChainBlueprint) -> None:
        self.manager.cpu_mining_service.resolve(blueprint)
        self.manager.reactor.advance(2)

    def _create_on_chain_blueprint(self, nc_code: bytes) -> OnChainBlueprint:
        from hathor.nanocontracts.on_chain_blueprint import Code, CodeKind
        code = Code(CodeKind.PYTHON_GZIP, nc_code)
        timestamp = self.manager.tx_storage.latest_timestamp + 1
        parents = self.manager.get_new_tx_parents(timestamp)
        blueprint = OnChainBlueprint(
            weight=1,
            inputs=[],
            outputs=[],
            parents=parents,
            storage=self.manager.tx_storage,
            timestamp=timestamp,
            code=code,
        )
        blueprint.weight = self.manager.daa.minimum_tx_weight(blueprint)
        self._ocb_sign(blueprint)
        self._ocb_mine(blueprint)
        return blueprint

    def _gen_nc_initialize_tx(self, blueprint, nc_args):
        from hathor.nanocontracts.nanocontract import NC_INITIALIZE_METHOD

        method_parser = blueprint.get_method_parser(NC_INITIALIZE_METHOD)
        timestamp = int(self.manager.reactor.seconds())
        parents = self.manager.get_new_tx_parents()

        nc = NanoContract(timestamp=timestamp, parents=parents)
        nc.nc_id = blueprint.blueprint_id()
        nc.nc_method = NC_INITIALIZE_METHOD
        nc.nc_args_bytes = method_parser.serialize_args(nc_args)

        # sign
        # import pudb; pu.db
        address = self.wallet.get_unused_address()
        # private_key = self.wallet.get_private_key(address)
        # nc.nc_pubkey = private_key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        private_key = self.wallet.get_private_key(address)
        nc.nc_pubkey = private_key.sec()
        data = nc.get_sighash_all()
        data_hash = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        # nc.nc_signature = private_key.sign(data, ec.ECDSA(hashes.SHA256()))
        nc.nc_signature = private_key.sign(data_hash)

        # mine
        nc.weight = self.manager.daa.minimum_tx_weight(nc)
        self.manager.cpu_mining_service.resolve(nc)

        # advance
        self.manager.reactor.advance(2)
        return nc

    def initialize_contract(self):
        # create on-chain Bet nanocontract
        blueprint = self._create_on_chain_blueprint(ON_CHAIN_BET_NC_CODE)
        assert self.manager.vertex_handler.on_new_vertex(blueprint, fails_silently=False)
        add_new_blocks(self.manager, 1, advance_clock=30)  # confirm the on-chain blueprint vertex
        assert blueprint.get_metadata().first_block is not None

        # load our `on_chain_bet` so we can use it for testing
        blueprint_class, blueprint_env = blueprint._load_blueprint_code()
        self.on_chain_bet = OnChainBet(**{k: v for k, v in blueprint_env.items() if k in OnChainBet._fields})

        self.oracle_key = KeyPair.create(b'123')
        assert self.oracle_key.address is not None
        p2pkh = P2PKH(self.oracle_key.address)
        self.oracle_script = p2pkh.get_script()
        self.date_last_bet = self.get_current_timestamp() + 3600 * 24

        # initialize an on-chain Bet nanocontract
        nc_init_tx = self._gen_nc_initialize_tx(blueprint, [self.oracle_script, self.token_uid, self.date_last_bet])
        assert self.manager.vertex_handler.on_new_vertex(nc_init_tx)
        block, = add_new_blocks(self.manager, 1, advance_clock=30)  # confirm the initialization nc transaction
        assert nc_init_tx.get_metadata().first_block is not None

        # set expected self objects:
        self.nc_id = ContractId(nc_init_tx.hash)
        self.runner = self.manager.get_nc_runner(block)
        self.nc_storage = self.runner.get_storage(self.nc_id)

    def test_on_chain_blueprint_initialization(self) -> None:
        # if initialization was correct we should be able to observe these in the nc_storage:
        self.assertEqual(self.nc_storage.get('oracle_script'), self.oracle_script)
        self.assertEqual(self.nc_storage.get('token_uid'), self.token_uid)
        self.assertEqual(self.nc_storage.get('date_last_bet'), self.date_last_bet)

    def test_basic_flow(self) -> None:
        runner = self.runner

        tx = self._get_any_tx()

        ###
        # Make some bets.
        ###
        self._make_a_bet(100, '1x1')
        self._make_a_bet(200, '1x1')
        self._make_a_bet(300, '1x1')
        bet1 = self._make_a_bet(500, '2x2')

        ###
        # Set the final result.
        ###
        self._set_result('2x2')

        ###
        # Single winner withdraws all funds.
        ###
        self.assertEqual(1100, runner.call_view_method(self.nc_id, 'get_max_withdrawal', bet1.address))

        self._withdraw(bet1.address, 100)
        self.assertEqual(1000, runner.call_view_method(self.nc_id, 'get_max_withdrawal', bet1.address))

        self._withdraw(bet1.address, 1000)
        self.assertEqual(0, runner.call_view_method(self.nc_id, 'get_max_withdrawal', bet1.address))

        # Out of funds! Any withdrawal must fail from now on...
        amount = 1
        action = NCAction(NCActionType.WITHDRAWAL, self.token_uid, amount)
        context = Context([action], tx, bet1.address, timestamp=self.get_current_timestamp())
        with self.assertRaises(self.on_chain_bet.InsufficientBalance):
            runner.call_public_method(self.nc_id, 'withdraw', context)

    def test_make_a_bet_with_withdrawal(self):
        self._make_a_bet(100, '1x1')

        (address_bytes, _) = self._get_any_address()
        tx = self._get_any_tx()
        action = NCAction(NCActionType.WITHDRAWAL, self.token_uid, 1)
        context = Context([action], tx, address_bytes, timestamp=self.get_current_timestamp())
        score = '1x1'
        with self.assertRaises(self.on_chain_bet.WithdrawalNotAllowed):
            self.runner.call_public_method(self.nc_id, 'bet', context, address_bytes, score)

    def test_make_a_bet_after_result(self):
        self._make_a_bet(100, '1x1')
        self._set_result('2x2')
        with self.assertRaises(self.on_chain_bet.ResultAlreadySet):
            self._make_a_bet(100, '1x1')

    def test_make_a_bet_after_date_last_bet(self):
        with self.assertRaises(self.on_chain_bet.TooLate):
            self._make_a_bet(100, '1x1', timestamp=self.date_last_bet + 1)

    def test_set_results_two_times(self):
        self._set_result('2x2')
        with self.assertRaises(self.on_chain_bet.ResultAlreadySet):
            self._set_result('5x1')

    def test_set_results_wrong_signature(self):
        wrong_oracle_key = KeyPair.create(b'123')
        with self.assertRaises(self.on_chain_bet.InvalidOracleSignature):
            self._set_result('3x2', oracle_key=wrong_oracle_key)

    def test_withdraw_before_result(self):
        bet1 = self._make_a_bet(100, '1x1')
        with self.assertRaises(self.on_chain_bet.ResultNotAvailable):
            self._withdraw(bet1.address, 100)

    def test_withdraw_with_deposits(self):
        (address_bytes, _) = self._get_any_address()
        tx = self._get_any_tx()
        action = NCAction(NCActionType.DEPOSIT, self.token_uid, 1)
        context = Context([action], tx, address_bytes, timestamp=self.get_current_timestamp())
        with self.assertRaises(self.on_chain_bet.DepositNotAllowed):
            self.runner.call_public_method(self.nc_id, 'withdraw', context)

    def test_make_a_bet_wrong_token(self):

        (address_bytes, _) = self._get_any_address()
        tx = self._get_any_tx()
        token_uid = b'xxx'
        self.assertNotEqual(token_uid, self.token_uid)
        action = NCAction(NCActionType.DEPOSIT, token_uid, 1)
        context = Context([action], tx, address_bytes, timestamp=self.get_current_timestamp())
        score = '1x1'
        with self.assertRaises(self.on_chain_bet.InvalidToken):
            self.runner.call_public_method(self.nc_id, 'bet', context, address_bytes, score)

    def test_withdraw_wrong_token(self):
        bet1 = self._make_a_bet(100, '1x1')

        tx = self._get_any_tx()
        token_uid = b'xxx'
        self.assertNotEqual(token_uid, self.token_uid)
        action = NCAction(NCActionType.WITHDRAWAL, token_uid, 1)
        context = Context([action], tx, bet1.address, timestamp=self.get_current_timestamp())
        with self.assertRaises(self.on_chain_bet.InvalidToken):
            self.runner.call_public_method(self.nc_id, 'withdraw', context)