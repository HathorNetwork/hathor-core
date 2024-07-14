PRECISION = 10**20
import os

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address, get_address_b58_from_bytes
from hathor.nanocontracts.blueprints.dozer_pool import Dozer_Pool
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.runner import Runner
from hathor.nanocontracts.storage import NCMemoryStorage
from hathor.nanocontracts.storage.memory_storage import NCMemoryStorageFactory
from hathor.nanocontracts.types import Context, NCAction, NCActionType
from hathor.types import Amount
from hathor.util import not_none
from hathor.wallet import KeyPair
from tests import unittest
from logging import getLogger

settings = HathorSettings()

logger = getLogger(__name__)


class MVP_PoolBlueprintTestCase(unittest.TestCase):
    _enable_sync_v1 = True
    _enable_sync_v2 = True
    use_memory_storage = True

    def setUp(self):
        super().setUp()
        self.manager = self.create_peer("testnet")
        nc_storage_factory = NCMemoryStorageFactory()
        self.nc_storage = nc_storage_factory(b"", None)
        self.runner = Runner(Dozer_Pool, b"", self.nc_storage)

        self.token_a = b"a" * 32
        self.token_b = b"b" * 32

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

    def _initialize_contract(self, reserve_a, reserve_b, fee=0):
        tx = self._get_any_tx()
        actions = [
            NCAction(NCActionType.DEPOSIT, self.token_a, reserve_a),
            NCAction(NCActionType.DEPOSIT, self.token_b, reserve_b),
        ]
        context = Context(
            actions, tx, self._get_any_address()[0], timestamp=self.get_current_timestamp()  # type: ignore
        )
        self.runner.call_public_method(
            "initialize", context, self.token_a, self.token_b, fee
        )

        storage = self.nc_storage
        self.assertEqual(storage.get("token_a"), self.token_a)
        self.assertEqual(storage.get("token_b"), self.token_b)
        self.assertEqual(storage.get("fee_numerator"), fee)

    def _prepare_swap_context(self, token_in, amount_in, token_out, amount_out):
        tx = self._get_any_tx()
        actions = [
            NCAction(NCActionType.DEPOSIT, token_in, amount_in),
            NCAction(NCActionType.WITHDRAWAL, token_out, amount_out),
        ]
        address_bytes, _ = self._get_any_address()
        return Context(
            actions, tx, address_bytes, timestamp=self.get_current_timestamp()  # type: ignore
        )

    def _swap1(self, token_in, amount_in, token_out, amount_out):
        context = self._prepare_swap_context(token_in, amount_in, token_out, amount_out)
        result = self.runner.call_public_method("swap_exact_tokens_for_tokens", context)
        return result, context

    def _swap2(self, token_in, amount_in, token_out, amount_out):
        context = self._prepare_swap_context(token_in, amount_in, token_out, amount_out)
        result = self.runner.call_public_method("swap_tokens_for_exact_tokens", context)
        return result, context

    def assertBalanceReserve(self, storage: NCMemoryStorage) -> None:
        reserve_a = storage.get("reserve_a")
        total_balance_a = storage.get("total_balance_a")
        self.assertEqual(storage.get_balance(self.token_a), reserve_a + total_balance_a)

        reserve_b = storage.get("reserve_b")
        total_balance_b = storage.get("total_balance_b")
        self.assertEqual(storage.get_balance(self.token_b), reserve_b + total_balance_b)

    def test_swap1_no_change(self) -> None:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 1_000_00)

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_in = 20_00
        amount_out = self.runner.call_private_method(
            "get_amount_out", amount_in, reserve_a, reserve_b
        )

        _, ctx = self._swap1(self.token_a, amount_in, self.token_b, amount_out)

        self.assertEqual(reserve_a + amount_in, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b - amount_out, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_in, reserve_b - amount_out)
        self.assertEqual(reserve_after, self.runner.call_private_method("get_reserves"))

        self.assertEqual(
            (0, 0),
            self.runner.call_private_method("balance_of", ctx.address),
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

        _, ctx = self._swap1(self.token_a, amount_in, self.token_b, amount_out)

        self.assertEqual(reserve_a + amount_in, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b - amount_out, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_in, reserve_b - amount_out - change)
        self.assertEqual(reserve_after, self.runner.call_private_method("get_reserves"))

        self.assertEqual(
            (0, change), self.runner.call_private_method("balance_of", ctx.address)
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

        _, ctx = self._swap2(self.token_a, amount_in, self.token_b, amount_out)

        self.assertEqual(reserve_a + amount_in, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b - amount_out, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_in, reserve_b - amount_out)
        self.assertEqual(reserve_after, self.runner.call_private_method("get_reserves"))

        self.assertEqual(
            (0, 0), self.runner.call_private_method("balance_of", ctx.address)
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

        _, ctx = self._swap2(self.token_a, amount_in, self.token_b, amount_out)

        self.assertEqual(reserve_a + amount_in, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b - amount_out, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_in - change, reserve_b - amount_out)
        self.assertEqual(reserve_after, self.runner.call_private_method("get_reserves"))

        self.assertEqual(
            (change, 0), self.runner.call_private_method("balance_of", ctx.address)
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
        address, _ = self._get_any_address()
        return Context(
            actions,
            self._get_any_tx(),
            address,  # type: ignore
            timestamp=self.get_current_timestamp(),
        )

    def _prepare_remove_liquidity_context(self, amount_a, amount_b):
        actions = [
            NCAction(NCActionType.WITHDRAWAL, self.token_a, amount_a),
            NCAction(NCActionType.WITHDRAWAL, self.token_b, amount_b),
        ]
        address, _ = self._get_any_address()
        return Context(
            actions,
            self._get_any_tx(),
            address,  # type: ignore
            timestamp=self.get_current_timestamp(),
        )

    def test_add_liquidity_no_change(self) -> Context:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 500_000)

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a = 100_00
        amount_b = self.runner.call_private_method(
            "quote", amount_a, reserve_a, reserve_b
        )

        reserve_a = storage.get("reserve_a")
        total_liquidity = storage.get("total_liquidity")

        ctx = self._prepare_add_liquidity_context(amount_a, amount_b)
        self.runner.call_public_method("add_liquidity", ctx)

        self.assertEqual(reserve_a + amount_a, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b + amount_b, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_a, reserve_b + amount_b)
        self.assertEqual(reserve_after, self.runner.call_private_method("get_reserves"))

        liquidity_increase = (total_liquidity / PRECISION) * amount_a / reserve_a
        get_liquidity = int(PRECISION * liquidity_increase)

        self.assertEqual(
            get_liquidity, self.runner.call_private_method("liquidity_of", ctx.address)
        )

        return ctx

    def test_add_liquidity_change_a(self) -> Context:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 500_000)

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a = 100_00
        amount_b = self.runner.call_private_method(
            "quote", amount_a, reserve_a, reserve_b
        )
        change = 1

        amount_a += change

        reserve_a = storage.get("reserve_a")
        total_liquidity = storage.get("total_liquidity")

        ctx = self._prepare_add_liquidity_context(amount_a, amount_b)
        self.runner.call_public_method("add_liquidity", ctx)

        self.assertEqual(reserve_a + amount_a, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b + amount_b, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_a - change, reserve_b + amount_b)
        self.assertEqual(reserve_after, self.runner.call_private_method("get_reserves"))

        self.assertEqual(
            (change, 0), self.runner.call_private_method("balance_of", ctx.address)
        )
        self.assertBalanceReserve(storage)

        liquidity_increase = (
            (total_liquidity / PRECISION) * (amount_a - change) / reserve_a
        )
        get_liquidity = int(PRECISION * liquidity_increase)

        self.assertEqual(
            get_liquidity, self.runner.call_private_method("liquidity_of", ctx.address)
        )
        return ctx

    def test_add_liquidity_change_b(self) -> Context:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 500_000)

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a = 100_00
        amount_b = self.runner.call_private_method(
            "quote", amount_a, reserve_a, reserve_b
        )
        change = 1

        amount_b += change

        reserve_a = storage.get("reserve_a")
        total_liquidity = storage.get("total_liquidity")

        ctx = self._prepare_add_liquidity_context(amount_a, amount_b)
        self.runner.call_public_method("add_liquidity", ctx)

        self.assertEqual(reserve_a + amount_a, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b + amount_b, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_a, reserve_b + amount_b - change)
        self.assertEqual(reserve_after, self.runner.call_private_method("get_reserves"))

        self.assertEqual(
            (0, change), self.runner.call_private_method("balance_of", ctx.address)
        )
        self.assertBalanceReserve(storage)

        liquidity_increase = (total_liquidity / PRECISION) * amount_a / reserve_a
        get_liquidity = int(PRECISION * liquidity_increase)

        self.assertEqual(
            get_liquidity, self.runner.call_private_method("liquidity_of", ctx.address)
        )
        return ctx

    def test_remove_liquidity_no_change(self) -> Context:
        ctx_add = self.test_add_liquidity_no_change()
        storage = self.nc_storage

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a = 10_00
        amount_b = self.runner.call_private_method(
            "quote", amount_a, reserve_a, reserve_b
        )

        reserve_a = storage.get("reserve_a")
        total_liquidity = storage.get("total_liquidity")

        ctx = self._prepare_remove_liquidity_context(amount_a, amount_b)

        ctx.address = ctx_add.address
        user_liquidity = self.runner.call_private_method("liquidity_of", ctx.address)

        self.runner.call_public_method("remove_liquidity", ctx)

        self.assertEqual(reserve_a - amount_a, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b - amount_b, storage.get_balance(self.token_b))

        reserve_after = (reserve_a - amount_a, reserve_b - amount_b)
        self.assertEqual(reserve_after, self.runner.call_private_method("get_reserves"))

        self.assertEqual(
            (0, 0), self.runner.call_private_method("balance_of", ctx.address)
        )
        self.assertBalanceReserve(storage)

        liquidity_decrease = (total_liquidity / PRECISION) * amount_a / reserve_a
        get_liquidity = int(PRECISION * liquidity_decrease)

        user_liquidity_after = user_liquidity - get_liquidity

        self.assertEqual(
            user_liquidity_after,
            self.runner.call_private_method("liquidity_of", ctx.address),
        )
        return ctx

    def test_remove_liquidity_with_change(self) -> Context:
        ctx_add = self.test_add_liquidity_no_change()
        storage = self.nc_storage

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a = 10_00
        amount_b = self.runner.call_private_method(
            "quote", amount_a, reserve_a, reserve_b
        )
        change = 1

        amount_b -= change  # in this case the user is asking for less b tokens than he has right to receive

        reserve_a = storage.get("reserve_a")
        total_liquidity = storage.get("total_liquidity")

        ctx = self._prepare_remove_liquidity_context(amount_a, amount_b)

        ctx.address = ctx_add.address
        user_liquidity = self.runner.call_private_method("liquidity_of", ctx.address)

        self.runner.call_public_method("remove_liquidity", ctx)

        self.assertEqual(reserve_a - amount_a, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b - amount_b, storage.get_balance(self.token_b))

        reserve_after = (reserve_a - amount_a, reserve_b - amount_b - change)
        self.assertEqual(reserve_after, self.runner.call_private_method("get_reserves"))

        self.assertEqual(
            (0, change), self.runner.call_private_method("balance_of", ctx.address)
        )
        self.assertBalanceReserve(storage)

        liquidity_decrease = (total_liquidity / PRECISION) * amount_a / reserve_a
        get_liquidity = int(PRECISION * liquidity_decrease)

        user_liquidity_after = user_liquidity - get_liquidity

        self.assertEqual(
            user_liquidity_after,
            self.runner.call_private_method("liquidity_of", ctx.address),
        )
        return ctx

    def test_remove_liquidity_amount_a_too_high(self) -> None:
        ctx_add = self.test_add_liquidity_no_change()
        storage = self.nc_storage

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a = 2000_00
        amount_b = self.runner.call_private_method(
            "quote", amount_a, reserve_a, reserve_b
        )

        ctx = self._prepare_remove_liquidity_context(amount_a, amount_b)
        ctx.address = ctx_add.address

        with self.assertRaises(NCFail):
            self.runner.call_public_method("remove_liquidity", ctx)

    def test_remove_liquidity_amount_b_too_high(self) -> None:
        ctx_add = self.test_add_liquidity_no_change()
        storage = self.nc_storage

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a = 10_00
        amount_b = self.runner.call_private_method(
            "quote", amount_a, reserve_a, reserve_b
        )
        exceeding_amount = 1

        amount_b += exceeding_amount

        ctx = self._prepare_remove_liquidity_context(amount_a, amount_b)
        ctx.address = ctx_add.address

        with self.assertRaises(NCFail):
            self.runner.call_public_method("remove_liquidity", ctx)

    def test_remove_liquidity_wrong_user(self) -> None:
        ctx_add = self.test_add_liquidity_no_change()
        storage = self.nc_storage

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a = 10_00
        amount_b = self.runner.call_private_method(
            "quote", amount_a, reserve_a, reserve_b
        )

        ctx = self._prepare_remove_liquidity_context(
            amount_a, amount_b
        )  # creating new context without getting the address from add_liquidity

        with self.assertRaises(NCFail):
            self.runner.call_public_method("remove_liquidity", ctx)

    def test_add_swap_remove(self) -> None:
        ctx_add = self.test_add_liquidity_no_change()
        storage = self.nc_storage

        address_user_with_liquidity = ctx_add.address

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a_swap = 20_00
        amount_b_swap = self.runner.call_private_method(
            "get_amount_out", amount_a_swap, reserve_a, reserve_b
        )

        ctx_swap1, result_swap1 = self._swap1(
            self.token_a, amount_a_swap, self.token_b, amount_b_swap
        )

        self.assertEqual(reserve_a + amount_a_swap, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b - amount_b_swap, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_a_swap, reserve_b - amount_b_swap)
        self.assertEqual(reserve_after, self.runner.call_private_method("get_reserves"))

        (reserve_a_after, reserve_b_after) = self.runner.call_private_method(
            "get_reserves"
        )

        amount_a_remove = 50_00
        amount_b_remove = self.runner.call_private_method(
            "quote", amount_a_remove, reserve_a_after, reserve_b_after
        )

        total_liquidity = storage.get("total_liquidity")

        ctx_remove = self._prepare_remove_liquidity_context(
            amount_a_remove, amount_b_remove
        )

        ctx_remove.address = address_user_with_liquidity
        user_liquidity = self.runner.call_private_method(
            "liquidity_of", ctx_remove.address
        )

        self.runner.call_public_method("remove_liquidity", ctx_remove)

        self.assertEqual(
            (0, 0), self.runner.call_private_method("balance_of", ctx_remove.address)
        )
        self.assertBalanceReserve(storage)

        liquidity_decrease = (
            (total_liquidity / PRECISION) * amount_a_remove / reserve_a_after
        )
        get_liquidity = int(PRECISION * liquidity_decrease)

        user_liquidity_after = user_liquidity - get_liquidity

        self.assertEqual(
            user_liquidity_after,
            self.runner.call_private_method("liquidity_of", ctx_remove.address),
        )

        reserve_a_after_remove = reserve_a_after - amount_a_remove
        reserve_b_after_remove = reserve_b_after - amount_b_remove

        self.assertEqual(
            (reserve_a_after_remove, reserve_b_after_remove),
            self.runner.call_private_method("get_reserves"),
        )

    def test_multiple_add_and_remove_liquidity(self) -> None:
        storage = self.nc_storage
        users = 10
        ctx_adds = []
        amounts_a = [
            100_00,
            200_00,
            300_00,
            400_00,
            500_00,
            600_00,
            700_00,
            800_00,
            900_00,
            1000_00,
        ]
        users_liquidity = []
        self._initialize_contract(1_000_00, 500_000)
        total_liquidity = storage.get("total_liquidity")
        reserve_a = storage.get("reserve_a")
        reserve_b = storage.get("reserve_b")
        for i in range(users):
            amount_a = amounts_a[i]
            amount_b = self.runner.call_private_method(
                "quote", amount_a, reserve_a, reserve_b
            )

            ctx = self._prepare_add_liquidity_context(amount_a, amount_b)
            self.runner.call_public_method("add_liquidity", ctx)

            self.assertEqual(reserve_a + amount_a, storage.get("reserve_a"))
            self.assertEqual(reserve_b + amount_b, storage.get("reserve_b"))

            liquidity_increase = (total_liquidity / PRECISION) * amount_a / reserve_a
            user_liquidity = int(PRECISION * liquidity_increase)

            self.assertEqual(
                total_liquidity + user_liquidity, storage.get("total_liquidity")
            )

            users_liquidity.append(user_liquidity)
            ctx_adds.append(ctx)

            reserve_a += amount_a
            reserve_b += amount_b
            total_liquidity += user_liquidity

        for i in range(users):
            self.assertEqual(
                users_liquidity[i],
                self.runner.call_private_method("liquidity_of", ctx_adds[i].address),
            )

        total_liquidity = storage.get("total_liquidity")
        reserve_a = storage.get("reserve_a")
        reserve_b = storage.get("reserve_b")
        for i in range(users):
            amount_a = amounts_a[i]
            amount_b = self.runner.call_private_method(
                "quote", amount_a, reserve_a, reserve_b
            )
            ctx = self._prepare_remove_liquidity_context(amount_a, amount_b)
            ctx.address = ctx_adds[i].address
            self.runner.call_public_method("remove_liquidity", ctx)

            self.assertEqual(reserve_a - amount_a, storage.get("reserve_a"))
            self.assertEqual(reserve_b - amount_b, storage.get("reserve_b"))

            liquidity_decrease = (total_liquidity / PRECISION) * amount_a / reserve_a
            user_liquidity = users_liquidity[i] - int(PRECISION * liquidity_decrease)
            print(
                f"user_liquidity_befor:{users_liquidity[i]}\n user_liquidity_after: {user_liquidity} \n \
                      total_liquidity: {total_liquidity}, amounts_a[i]: {amounts_a[i]}"
            )
            self.assertEqual(
                user_liquidity,
                self.runner.call_private_method("liquidity_of", ctx_adds[i].address),
            )
            self.assertEqual(
                total_liquidity - int(PRECISION * liquidity_decrease),
                storage.get("total_liquidity"),
            )

            reserve_a -= amount_a
            reserve_b -= amount_b
            total_liquidity -= int(PRECISION * liquidity_decrease)

    def test_multiple_add_swap_and_remove_liquidity(self) -> None:
        storage = self.nc_storage
        users = 10
        ctx_adds = []
        amounts_a = [
            100_00,
            200_00,
            300_00,
            400_00,
            500_00,
            600_00,
            700_00,
            800_00,
            900_00,
            1000_00,
        ]

        swaps_amounts_a = [
            10_00,
            20_00,
            30_00,
            40_00,
            50_00,
            60_00,
            70_00,
            80_00,
            90_00,
            100_00,
        ]
        users_liquidity = []
        self._initialize_contract(1_000_00, 500_000, fee=5)
        fee_numerator = storage.get("fee_numerator")
        fee_denominator = storage.get("fee_denominator")
        total_liquidity = storage.get("total_liquidity")
        reserve_a = storage.get("reserve_a")
        reserve_b = storage.get("reserve_b")
        for i in range(users):
            amount_a = amounts_a[i]
            amount_b = self.runner.call_private_method(
                "quote", amount_a, reserve_a, reserve_b
            )

            ctx = self._prepare_add_liquidity_context(amount_a, amount_b)
            self.runner.call_public_method("add_liquidity", ctx)

            self.assertEqual(reserve_a + amount_a, storage.get("reserve_a"))
            self.assertEqual(reserve_b + amount_b, storage.get("reserve_b"))

            liquidity_increase = (total_liquidity / PRECISION) * amount_a / reserve_a
            user_liquidity = int(PRECISION * liquidity_increase)

            self.assertEqual(
                total_liquidity + user_liquidity, storage.get("total_liquidity")
            )

            users_liquidity.append(user_liquidity)
            ctx_adds.append(ctx)

            reserve_a += amount_a
            reserve_b += amount_b
            total_liquidity += user_liquidity

        for i in range(users):
            self.assertEqual(
                users_liquidity[i],
                self.runner.call_private_method("liquidity_of", ctx_adds[i].address),
            )

        fee_accumulated = 0

        for i in range(users):
            amount_a = swaps_amounts_a[i]
            amount_b = self.runner.call_private_method(
                "get_amount_out", amount_a, reserve_a, reserve_b
            )
            a = storage.get("fee_denominator") - storage.get("fee_numerator")
            b = storage.get("fee_denominator")
            amount_out = (reserve_b * amount_a * a) // (reserve_a * b + amount_a * a)

            self.assertEqual(amount_b, amount_out)

            ctx, result = self._swap1(self.token_a, amount_a, self.token_b, amount_b)
            fee_accumulated += amount_a * fee_numerator // fee_denominator
            self.assertEqual(
                fee_accumulated,
                self.runner.call_private_method("accumulated_fee_of", self.token_a),
            )

            reserve_a += amount_a
            reserve_b -= amount_b

        self.assertEqual(
            fee_accumulated,
            self.runner.call_private_method("accumulated_fee_of", self.token_a),
        )

        self.assertEqual(storage.get("reserve_a"), reserve_a)
        self.assertEqual(storage.get("reserve_b"), reserve_b)
        self.assertEqual(storage.get("total_liquidity"), total_liquidity)

        for i in range(users):
            user_liquidity = users_liquidity[i]
            self.assertEqual(
                user_liquidity,
                self.runner.call_private_method("liquidity_of", ctx_adds[i].address),
            )

            print(
                f"user_liquidity: {user_liquidity}, total_liquidity: {total_liquidity}, amounts_a[i]: {amounts_a[i]}"
            )

            remove_amount_a = int(
                (user_liquidity / PRECISION) * reserve_a / (total_liquidity / PRECISION)
            )
            remove_amount_b = self.runner.call_private_method(
                "quote", remove_amount_a, reserve_a, reserve_b
            )

            self.assertGreater(remove_amount_a, amounts_a[i])

            ctx = self._prepare_remove_liquidity_context(
                remove_amount_a, remove_amount_b
            )
            ctx.address = ctx_adds[i].address
            self.runner.call_public_method("remove_liquidity", ctx)

            self.assertEqual(reserve_a - remove_amount_a, storage.get("reserve_a"))
            self.assertEqual(reserve_b - remove_amount_b, storage.get("reserve_b"))

            liquidity_decrease = int(
                PRECISION
                * ((total_liquidity / PRECISION) * remove_amount_a / reserve_a)
            )

            total_liquidity -= liquidity_decrease
            reserve_a -= remove_amount_a
            reserve_b -= remove_amount_b

            self.assertEqual(
                self.runner.call_private_method("liquidity_of", ctx.address),
                user_liquidity - liquidity_decrease,
            )
            ## failing in decimal cases, need to think in a better way to store liquidity
