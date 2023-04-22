from typing import Dict, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from hathor.crypto.util import get_address_b58_from_public_key_bytes, get_public_key_bytes_compressed
from hathor.exception import InvalidNewTransaction
from hathor.nanocontracts.blueprint import Blueprint
from hathor.nanocontracts.catalog import Catalog
from hathor.nanocontracts.exception import NCInvalidPubKey, NCInvalidSignature, NCMethodNotFound, NCSerializationError
from hathor.nanocontracts.method_parser import NCMethodParser
from hathor.nanocontracts.nanocontract import NanoContract
from hathor.nanocontracts.storage import NCMemoryStorage
from hathor.nanocontracts.types import Context, NCActionType, public
from hathor.p2p.peer_id import PeerId
from hathor.simulator import Simulator
from hathor.simulator.trigger import StopAfterNMinedBlocks, StopAfterMinimumBalance
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.exceptions import TokenAuthorityNotAllowed
from hathor.wallet import KeyPair
from tests import unittest
from tests.utils import gen_new_tx


Address = bytes
Amount = int
TokenUid = bytes


class MyBlueprint(Blueprint):
    balance: Dict[Tuple[Address, TokenUid], Amount]

    @public
    def initialize(self, ctx: Context) -> None:
        self.balance = {}

    @public
    def run(self, ctx: Context) -> None:
        for action in ctx.actions:
            key = (ctx.address, action.token_uid)
            if action.type == ActionType.DEPOSIT:
                if key not in self.balance:
                    self.balance[key] = action.amount
                else:
                    self.balance[key] += action.amount
            else:
                assert action.type == ActionType.WITHDRAWAL
                if key not in self.balance:
                    raise NCFail('zero balance')
                if action.amount > self.balance[key]:
                    raise NCFail('no balance available')


class NCNanoContractTestCase(unittest.TestCase):
    _enable_sync_v1 = True
    _enable_sync_v2 = False

    def setUp(self):
        super().setUp()

        self.myblueprint_id = b'x' * 32
        self.catalog = Catalog({
            self.myblueprint_id: MyBlueprint
        })

        self.peer = self.create_peer('testnet')

    def test_deposits_and_withdrawals(self):
        simulator = Simulator()
        simulator.start()

        peer_id = PeerId()
        manager = simulator.create_peer(peer_id=peer_id)
        manager.allow_mining_without_peers()

        wallet = manager.wallet

        miner = simulator.create_miner(manager, hashpower=1e6)
        miner.start()

        trigger = StopAfterMinimumBalance(wallet, simulator.settings.HATHOR_TOKEN_UID, 10_00)
        self.assertTrue(simulator.run(600, trigger=trigger))

        for _ in range(10):
            print('')
        print('blocks found:', miner.blocks_found)
        print('balance', wallet.balance)
        for _ in range(10):
            print('')

        address = manager.wallet.get_unused_address(mark_as_used=False)
        tx = gen_new_tx(manager, address, 1_00)
        self.assertTrue(manager.propagate_tx(tx))

        raise Exception()
