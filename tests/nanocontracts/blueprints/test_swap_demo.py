import os

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.nanocontracts.blueprints.swap_demo import InvalidActions, InvalidRatio, InvalidTokens, SwapDemo
from hathor.nanocontracts.exception import NCInsufficientFunds
from hathor.nanocontracts.runner import Runner
from hathor.nanocontracts.storage import NCMemoryStorageFactory
from hathor.nanocontracts.types import Context, NCAction, NCActionType
from hathor.types import TokenUid
from hathor.util import not_none
from hathor.wallet import KeyPair
from tests import unittest

settings = HathorSettings()


class NCSwapDemoBlueprintTestCase(unittest.TestCase):
    _enable_sync_v1 = True
    _enable_sync_v2 = True
    use_memory_storage = True

    def setUp(self):
        super().setUp()
        self.manager = self.create_peer('testnet')
        self.token_uid = settings.HATHOR_TOKEN_UID
        nc_storage_factory = NCMemoryStorageFactory()
        self.nc_storage = nc_storage_factory(b'', None)
        self.runner = Runner(SwapDemo, b'', self.nc_storage)

        self.token_a = b'0' * 32
        self.token_b = b'1' * 32
        self.token_c = b'2' * 32

        self.dummy_address = b'0' * 12
        self.dummy_tx = self._get_any_address()
        self.now = self.manager.reactor.seconds()

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

    def _initialize(self, amount_a: int, amount_b: int, multiplier_a: int, multiplier_b: int) -> None:
        """Initialize a contract."""
        deposit_a = NCAction(NCActionType.DEPOSIT, self.token_a, amount_a)
        deposit_b = NCAction(NCActionType.DEPOSIT, self.token_b, amount_b)
        context = Context(
            actions=[deposit_a, deposit_b],
            tx=self.dummy_tx,
            address=self.dummy_address,
            timestamp=int(self.now)
        )
        self.runner.call_public_method('initialize', context, self.token_a, self.token_b, multiplier_a, multiplier_b)
        self.assertEqual(amount_a, self.nc_storage.get_balance(self.token_a))
        self.assertEqual(amount_b, self.nc_storage.get_balance(self.token_b))
        self.assertEqual(0, self.nc_storage.get('swaps_counter'))

    def _get_action_type(self, amount: int) -> NCActionType:
        if amount >= 0:
            return NCActionType.DEPOSIT
        else:
            return NCActionType.WITHDRAWAL

    def _swap(self, amount_a: tuple[int, TokenUid], amount_b: tuple[int, TokenUid]) -> None:
        value_a, token_a = amount_a
        value_b, token_b = amount_b

        swap_a = NCAction(self._get_action_type(value_a), token_a, abs(value_a))
        swap_b = NCAction(self._get_action_type(value_b), token_b, abs(value_b))
        context = Context(
            actions=[swap_a, swap_b],
            tx=self.dummy_tx,
            address=self.dummy_address,
            timestamp=int(self.now),
        )
        self.runner.call_public_method('swap', context)

    def test_basic_flow(self) -> None:
        self._initialize(100_00, 100_00, 1, 1)

        # Valid swap!
        self._swap((20_00, self.token_a), (-20_00, self.token_b))
        self.assertEqual(120_00, self.nc_storage.get_balance(self.token_a))
        self.assertEqual(80_00, self.nc_storage.get_balance(self.token_b))
        self.assertEqual(1, self.nc_storage.get('swaps_counter'))

        # Multiple invalid swaps.
        with self.assertRaises(InvalidRatio):
            self._swap((20_00, self.token_a), (-40_00, self.token_b))

        with self.assertRaises(InvalidActions):
            self._swap((20_00, self.token_a), (40_00, self.token_b))

        with self.assertRaises(NCInsufficientFunds):
            self._swap((100_00, self.token_a), (-100_00, self.token_b))

        with self.assertRaises(InvalidTokens):
            self._swap((-20_00, self.token_a), (20_00, self.token_c))

        # Confirm that nothing has changed.
        self.assertEqual(120_00, self.nc_storage.get_balance(self.token_a))
        self.assertEqual(80_00, self.nc_storage.get_balance(self.token_b))
        self.assertEqual(1, self.nc_storage.get('swaps_counter'))

        # Valid swap again!
        self._swap((-60_00, self.token_a), (60_00, self.token_b))
        self.assertEqual(60_00, self.nc_storage.get_balance(self.token_a))
        self.assertEqual(140_00, self.nc_storage.get_balance(self.token_b))
        self.assertEqual(2, self.nc_storage.get('swaps_counter'))
