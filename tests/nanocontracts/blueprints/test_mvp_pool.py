import os

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.nanocontracts.blueprints.mvp_pool import MVP_Pool
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.runner import Runner
from hathor.nanocontracts.storage import NCMemoryStorage
from hathor.nanocontracts.storage.memory_storage import NCMemoryStorageFactory
from hathor.nanocontracts.types import Context, NCAction, NCActionType
from hathor.util import not_none
from hathor.wallet import KeyPair
from tests import unittest

settings = HathorSettings()


class MVP_PoolBlueprintTestCase(unittest.TestCase):
    _enable_sync_v1 = True
    _enable_sync_v2 = True
    use_memory_storage = True

    def setUp(self):
        super().setUp()
        self.manager = self.create_peer("testnet")
        nc_storage_factory = NCMemoryStorageFactory()
        self.nc_storage = nc_storage_factory(b"", None)
        self.runner = Runner(MVP_Pool, b"", self.nc_storage)

        self.token_a = b"a" * 32
        self.token_b = b"b" * 32
        # self.lp_token = b"lp" * 16

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

    def _initialize_contract(self, reserve_a, reserve_b):
        tx = self._get_any_tx()
        actions = [
            NCAction(NCActionType.DEPOSIT, self.token_a, reserve_a),
            NCAction(NCActionType.DEPOSIT, self.token_b, reserve_a),
        ]
        context = Context(
            actions, tx, self._get_any_address(), timestamp=self.get_current_timestamp()  # type: ignore
        )
        self.runner.call_public_method(
            "initialize", context, self.token_a, self.token_b, 0
        )

        storage = self.nc_storage
        self.assertEqual(storage.get("token_a"), self.token_a)
        self.assertEqual(storage.get("token_b"), self.token_b)
        self.assertEqual(storage.get("fee_numerator"), 0)
        # self.assertEqual(storage.get("lp_token"), self.lp_token)

    def _prepare_swap_context(self, token_in, amount_in, token_out, amount_out):
        tx = self._get_any_tx()
        actions = [
            NCAction(NCActionType.DEPOSIT, token_in, amount_in),
            NCAction(NCActionType.WITHDRAWAL, token_out, amount_out),
        ]
        return Context(
            actions, tx, self._get_any_address, timestamp=self.get_current_timestamp()  # type: ignore
        )

    def _swap1(self, token_in, amount_in, token_out, amount_out):
        context = self._prepare_swap_context(token_in, amount_in, token_out, amount_out)
        result = self.runner.call_public_method("swap_exact_tokens_for_tokens", context)
        return result, context

    def _swap2(self, token_in, amount_in, token_out, amount_out):
        context = self._prepare_swap_context(token_in, amount_in, token_out, amount_out)
        result = self.runner.call_public_method("swap_tokens_for_exact_tokens", context)
        return result, context

    def assertBalanceReserve(self, storage):
        reserve_a = storage.get("reserve_a")
        balance_a = storage.get("balance_a")
        self.assertEqual(storage.get_balance(self.token_a), reserve_a + balance_a)

        reserve_b = storage.get("reserve_b")
        balance_b = storage.get("balance_b")
        self.assertEqual(storage.get_balance(self.token_b), reserve_b + balance_b)

    def test_swap1_no_change(self) -> None:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 1_000_00)

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_in = 20_00
        amount_out = self.runner.call_private_method(
            "get_amount_out", amount_in, reserve_a, reserve_b
        )

        _, context = self._swap1(self.token_a, amount_in, self.token_b, amount_out)

        self.assertEqual(reserve_a + amount_in, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b - amount_out, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_in, reserve_b - amount_out)
        self.assertEqual(reserve_after, self.runner.call_private_method("get_reserves"))

        self.assertEqual(0, storage.get("balance_a"))
        self.assertEqual(0, storage.get("balance_b"))

        self.assertEqual(
            (0, 0), self.runner.call_private_method("balance_of", context.address)
        )
        self.assertBalanceReserve(storage)

    def test_swap1_with_change(self) -> None:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 1_000_00)

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        change = 1
        amount_in = 20_00
        amount_out = self.runner.call_private_method(
            "get_amount_out", amount_in, reserve_a, reserve_b
        )
        amount_out -= change

        _, context = self._swap1(self.token_a, amount_in, self.token_b, amount_out)

        self.assertEqual(reserve_a + amount_in, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b - amount_out, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_in, reserve_b - amount_out - change)
        self.assertEqual(reserve_after, self.runner.call_private_method("get_reserves"))

        self.assertEqual(0, storage.get("balance_a"))
        self.assertEqual(1, storage.get("balance_b"))

        self.assertEqual(
            (0, change), self.runner.call_private_method("balance_of", context.address)
        )
        self.assertBalanceReserve(storage)

    def test_swap1_amount_out_too_high(self) -> None:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 1_000_00)

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_in = 20_00
        amount_out = self.runner.call_private_method(
            "get_amount_out", amount_in, reserve_a, reserve_b
        )

        with self.assertRaises(NCFail):
            self._swap1(self.token_a, amount_in, self.token_b, amount_out + 1)

    def test_swap1_multiple_swaps(self) -> None:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 2_500_00)

        last_result = None

        for _ in range(100):
            reserve_a = storage.get_balance(self.token_a)
            reserve_b = storage.get_balance(self.token_b)

            amount_in = 20_00
            amount_out = self.runner.call_private_method(
                "get_amount_out", amount_in, reserve_a, reserve_b
            )

            result, _ = self._swap1(self.token_a, amount_in, self.token_b, amount_out)
            if last_result is not None:
                self.assertLess(result.amount_out, last_result.amount_out)  # type: ignore
            last_result = result

    def test_swap2_no_change(self) -> None:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 1_000_00)

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_out = 20_00
        amount_in = self.runner.call_private_method(
            "get_amount_in", amount_out, reserve_a, reserve_b
        )

        _, context = self._swap2(self.token_a, amount_in, self.token_b, amount_out)

        self.assertEqual(reserve_a + amount_in, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b - amount_out, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_in, reserve_b - amount_out)
        self.assertEqual(reserve_after, self.runner.call_private_method("get_reserves"))

        self.assertEqual(0, storage.get("balance_a"))
        self.assertEqual(0, storage.get("balance_b"))

        self.assertEqual(
            (0, 0), self.runner.call_private_method("balance_of", context.address)
        )
        self.assertBalanceReserve(storage)

    def test_swap2_with_change(self) -> None:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 1_000_00)

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        change = 1
        amount_out = 20_00
        amount_in = self.runner.call_private_method(
            "get_amount_in", amount_out, reserve_a, reserve_b
        )
        amount_in += change

        _, context = self._swap2(self.token_a, amount_in, self.token_b, amount_out)

        self.assertEqual(reserve_a + amount_in, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b - amount_out, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_in - change, reserve_b - amount_out)
        self.assertEqual(reserve_after, self.runner.call_private_method("get_reserves"))

        self.assertEqual(1, storage.get("balance_a"))
        self.assertEqual(0, storage.get("balance_b"))

        self.assertEqual(
            (change, 0), self.runner.call_private_method("balance_of", context.address)
        )
        self.assertBalanceReserve(storage)

    def test_swap2_amount_in_too_low(self) -> None:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 1_000_00)

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_out = 20_00
        amount_in = self.runner.call_private_method(
            "get_amount_in", amount_out, reserve_a, reserve_b
        )

        with self.assertRaises(NCFail):
            self._swap2(self.token_a, amount_in - 1, self.token_b, amount_out)

    def test_amount_in_out(self) -> None:
        self._initialize_contract(1, 1)
        self.assertEqual(
            19_60,
            self.runner.call_private_method(
                "get_amount_out", 20_00, 1_000_00, 1_000_00
            ),
        )
        self.assertEqual(
            20_40,
            self.runner.call_private_method("get_amount_in", 20_00, 1_000_00, 1_000_00),
        )

    def _prepare_add_liquidity_context(self, amount_a, amount_b):
        actions = [
            NCAction(NCActionType.DEPOSIT, self.token_a, amount_a),
            NCAction(NCActionType.DEPOSIT, self.token_b, amount_b),
        ]
        return Context(
            actions,
            self._get_any_tx(),
            self._get_any_address(),  # type: ignore
            timestamp=self.get_current_timestamp(),
        )

    def test_add_liquidity_no_change(self) -> None:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 500_000)

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a = 100_00
        amount_b = self.runner.call_private_method(
            "quote", amount_a, reserve_a, reserve_b
        )

        ctx = self._prepare_add_liquidity_context(amount_a, amount_b)
        self.runner.call_public_method(
            "add_liquidity", ctx, amount_a, amount_b, ctx.address
        )

        self.assertEqual(reserve_a + amount_a, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b + amount_b, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_a, reserve_b + amount_b)
        self.assertEqual(reserve_after, self.runner.call_private_method("get_reserves"))

    def test_add_liquidity_change_a(self) -> None:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 500_000)

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a = 100_00
        amount_b = self.runner.call_private_method(
            "quote", amount_a, reserve_a, reserve_b
        )
        change = 1

        amount_a_min = amount_a
        amount_b_min = amount_b

        amount_a += change

        ctx = self._prepare_add_liquidity_context(amount_a, amount_b)
        self.runner.call_public_method(
            "add_liquidity", ctx, amount_a_min, amount_b_min, ctx.address
        )

        self.assertEqual(reserve_a + amount_a, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b + amount_b, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_a - change, reserve_b + amount_b)
        self.assertEqual(reserve_after, self.runner.call_private_method("get_reserves"))

        self.assertEqual(change, storage.get("balance_a"))
        self.assertEqual(0, storage.get("balance_b"))

        self.assertEqual(
            (change, 0), self.runner.call_private_method("balance_of", ctx.address)
        )
        self.assertBalanceReserve(storage)

    def test_add_liquidity_change_b(self) -> None:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 500_000)

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a = 100_00
        amount_b = self.runner.call_private_method(
            "quote", amount_a, reserve_a, reserve_b
        )
        change = 1

        amount_a_min = amount_a
        amount_b_min = amount_b

        amount_b += change

        ctx = self._prepare_add_liquidity_context(amount_a, amount_b)
        self.runner.call_public_method(
            "add_liquidity", ctx, amount_a_min, amount_b_min, ctx.address
        )

        self.assertEqual(reserve_a + amount_a, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b + amount_b, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_a, reserve_b + amount_b - change)
        self.assertEqual(reserve_after, self.runner.call_private_method("get_reserves"))

        self.assertEqual(0, storage.get("balance_a"))
        self.assertEqual(change, storage.get("balance_b"))

        self.assertEqual(
            (0, change), self.runner.call_private_method("balance_of", ctx.address)
        )
        self.assertBalanceReserve(storage)
