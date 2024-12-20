import decimal
import os
import random
from logging import getLogger

from hathor.conf import HathorSettings
from hathor.crypto.util import decode_address
from hathor.nanocontracts.blueprints.dozer_pool import Dozer_Pool
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.storage import NCStorage
from hathor.nanocontracts.types import NCAction, NCActionType
from hathor.util import not_none
from hathor.wallet import KeyPair
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase

PRECISION = 10**20

settings = HathorSettings()

logger = getLogger(__name__)


class MVP_PoolBlueprintTestCase(BlueprintTestCase):
    def setUp(self):
        super().setUp()

        self.nc_id = self.gen_random_nanocontract_id()
        self.runner.register_contract(Dozer_Pool, self.nc_id)
        self.nc_storage = self.runner.get_storage(self.nc_id)

        self.token_a = self.gen_random_token_uid()
        self.token_b = self.gen_random_token_uid()

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

    def _initialize_contract(
        self, reserve_a, reserve_b, fee=0, protocol_fee=50
    ) -> Context:
        tx = self._get_any_tx()
        actions = [
            NCAction(NCActionType.DEPOSIT, self.token_a, reserve_a),
            NCAction(NCActionType.DEPOSIT, self.token_b, reserve_b),
        ]
        context = Context(
            actions, tx, self._get_any_address()[0], timestamp=self.get_current_timestamp()  # type: ignore
        )
        self.runner.call_public_method(
            self.nc_id,
            "initialize",
            context,
            self.token_a,
            self.token_b,
            fee,
            protocol_fee,
        )

        storage = self.nc_storage
        self.admin_address = context.address
        self.assertEqual(storage.get("token_a"), self.token_a)
        self.assertEqual(storage.get("token_b"), self.token_b)
        self.assertEqual(storage.get("fee_numerator"), fee)

        return context

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
        result = self.runner.call_public_method(
            self.nc_id, "swap_exact_tokens_for_tokens", context
        )
        return result, context

    def _swap2(self, token_in, amount_in, token_out, amount_out):
        context = self._prepare_swap_context(token_in, amount_in, token_out, amount_out)
        result = self.runner.call_public_method(
            self.nc_id, "swap_tokens_for_exact_tokens", context
        )
        return result, context

    def assertBalanceReserve(self, storage: NCStorage) -> None:
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
        amount_out = self.runner.call_view_method(
            self.nc_id, "get_amount_out", amount_in, reserve_a, reserve_b
        )

        _, ctx = self._swap1(self.token_a, amount_in, self.token_b, amount_out)

        self.assertEqual(reserve_a + amount_in, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b - amount_out, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_in, reserve_b - amount_out)
        self.assertEqual(
            reserve_after, self.runner.call_view_method(self.nc_id, "get_reserves")
        )

        self.assertEqual(
            (0, 0),
            self.runner.call_view_method(self.nc_id, "balance_of", ctx.address),
        )
        self.assertBalanceReserve(storage)

    def test_swap1_with_change(self) -> None:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 1_000_00)

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        change = 1
        amount_in = 20_00
        amount_out = self.runner.call_view_method(
            self.nc_id, "get_amount_out", amount_in, reserve_a, reserve_b
        )
        amount_out -= change

        _, ctx = self._swap1(self.token_a, amount_in, self.token_b, amount_out)

        self.assertEqual(reserve_a + amount_in, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b - amount_out, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_in, reserve_b - amount_out - change)
        self.assertEqual(
            reserve_after, self.runner.call_view_method(self.nc_id, "get_reserves")
        )

        self.assertEqual(
            (0, change),
            self.runner.call_view_method(self.nc_id, "balance_of", ctx.address),
        )
        self.assertBalanceReserve(storage)

    def test_swap1_amount_out_too_high(self) -> None:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 1_000_00)

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_in = 20_00
        amount_out = self.runner.call_view_method(
            self.nc_id, "get_amount_out", amount_in, reserve_a, reserve_b
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
            amount_out = self.runner.call_view_method(
                self.nc_id, "get_amount_out", amount_in, reserve_a, reserve_b
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
        amount_in = self.runner.call_view_method(
            self.nc_id, "get_amount_in", amount_out, reserve_a, reserve_b
        )

        _, ctx = self._swap2(self.token_a, amount_in, self.token_b, amount_out)

        self.assertEqual(reserve_a + amount_in, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b - amount_out, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_in, reserve_b - amount_out)
        self.assertEqual(
            reserve_after, self.runner.call_view_method(self.nc_id, "get_reserves")
        )

        self.assertEqual(
            (0, 0), self.runner.call_view_method(self.nc_id, "balance_of", ctx.address)
        )
        self.assertBalanceReserve(storage)

    def test_swap2_with_change(self) -> None:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 1_000_00)

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        change = 1
        amount_out = 20_00
        amount_in = self.runner.call_view_method(
            self.nc_id, "get_amount_in", amount_out, reserve_a, reserve_b
        )
        amount_in += change

        _, ctx = self._swap2(self.token_a, amount_in, self.token_b, amount_out)

        self.assertEqual(reserve_a + amount_in, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b - amount_out, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_in - change, reserve_b - amount_out)
        self.assertEqual(
            reserve_after, self.runner.call_view_method(self.nc_id, "get_reserves")
        )

        self.assertEqual(
            (change, 0),
            self.runner.call_view_method(self.nc_id, "balance_of", ctx.address),
        )
        self.assertBalanceReserve(storage)

    def test_swap2_amount_in_too_low(self) -> None:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 1_000_00)

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_out = 20_00
        amount_in = self.runner.call_view_method(
            self.nc_id, "get_amount_in", amount_out, reserve_a, reserve_b
        )

        with self.assertRaises(NCFail):
            self._swap2(self.token_a, amount_in - 1, self.token_b, amount_out)

    def test_amount_in_out(self) -> None:
        self._initialize_contract(1, 1)
        self.assertEqual(
            19_60,
            self.runner.call_view_method(
                self.nc_id, "get_amount_out", 20_00, 1_000_00, 1_000_00
            ),
        )
        self.assertEqual(
            20_40,
            self.runner.call_view_method(
                self.nc_id, "get_amount_in", 20_00, 1_000_00, 1_000_00
            ),
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
        amount_b = self.runner.call_view_method(
            self.nc_id, "quote", amount_a, reserve_a, reserve_b
        )

        reserve_a = storage.get("reserve_a")
        total_liquidity = storage.get("total_liquidity")

        ctx = self._prepare_add_liquidity_context(amount_a, amount_b)
        self.runner.call_public_method(self.nc_id, "add_liquidity", ctx)

        self.assertEqual(reserve_a + amount_a, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b + amount_b, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_a, reserve_b + amount_b)
        self.assertEqual(
            reserve_after, self.runner.call_view_method(self.nc_id, "get_reserves")
        )

        liquidity_increase = total_liquidity * amount_a // reserve_a
        get_liquidity = liquidity_increase

        self.assertEqual(
            get_liquidity,
            self.runner.call_view_method(self.nc_id, "liquidity_of", ctx.address),
        )

        return ctx

    def test_add_liquidity_change_a(self) -> Context:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 500_000)

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a = 100_00
        amount_b = self.runner.call_view_method(
            self.nc_id, "quote", amount_a, reserve_a, reserve_b
        )
        change = 1

        amount_a += change

        reserve_a = storage.get("reserve_a")
        total_liquidity = storage.get("total_liquidity")

        ctx = self._prepare_add_liquidity_context(amount_a, amount_b)
        self.runner.call_public_method(self.nc_id, "add_liquidity", ctx)

        self.assertEqual(reserve_a + amount_a, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b + amount_b, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_a - change, reserve_b + amount_b)
        self.assertEqual(
            reserve_after, self.runner.call_view_method(self.nc_id, "get_reserves")
        )

        self.assertEqual(
            (change, 0),
            self.runner.call_view_method(self.nc_id, "balance_of", ctx.address),
        )
        self.assertBalanceReserve(storage)

        liquidity_increase = total_liquidity * (amount_a - change) // reserve_a

        get_liquidity = liquidity_increase

        self.assertEqual(
            get_liquidity,
            self.runner.call_view_method(self.nc_id, "liquidity_of", ctx.address),
        )
        return ctx

    def test_add_liquidity_change_b(self) -> Context:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 500_000)

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a = 100_00
        amount_b = self.runner.call_view_method(
            self.nc_id, "quote", amount_a, reserve_a, reserve_b
        )
        change = 1

        amount_b += change

        reserve_a = storage.get("reserve_a")
        total_liquidity = storage.get("total_liquidity")

        ctx = self._prepare_add_liquidity_context(amount_a, amount_b)
        self.runner.call_public_method(self.nc_id, "add_liquidity", ctx)

        self.assertEqual(reserve_a + amount_a, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b + amount_b, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_a, reserve_b + amount_b - change)
        self.assertEqual(
            reserve_after, self.runner.call_view_method(self.nc_id, "get_reserves")
        )

        self.assertEqual(
            (0, change),
            self.runner.call_view_method(self.nc_id, "balance_of", ctx.address),
        )
        self.assertBalanceReserve(storage)

        liquidity_increase = total_liquidity * amount_a // reserve_a
        get_liquidity = liquidity_increase

        self.assertEqual(
            get_liquidity,
            self.runner.call_view_method(self.nc_id, "liquidity_of", ctx.address),
        )
        return ctx

    def test_dev_remove_all_liquidity(self) -> None:
        ctx_init = self._initialize_contract(100000, 10000)
        storage = self.nc_storage

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a = reserve_a
        amount_b = reserve_b

        actions = [
            NCAction(NCActionType.WITHDRAWAL, self.token_a, amount_a),
            NCAction(NCActionType.WITHDRAWAL, self.token_b, amount_b),
        ]
        ctx = Context(
            actions,
            self._get_any_tx(),
            ctx_init.address,  # type: ignore
            timestamp=self.get_current_timestamp(),
        )
        self.runner.call_public_method(self.nc_id, "remove_liquidity", ctx)

        self.assertEqual(
            (0, 0), self.runner.call_view_method(self.nc_id, "get_reserves")
        )

        pool_data = self.runner.call_view_method(self.nc_id, "pool_data")

        self.assertEqual(0, pool_data["total_liquidity"])

    def test_remove_liquidity_no_change(self) -> Context:
        ctx_add = self.test_add_liquidity_no_change()
        storage = self.nc_storage

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a = 10_00
        amount_b = self.runner.call_view_method(
            self.nc_id, "quote", amount_a, reserve_a, reserve_b
        )

        reserve_a = storage.get("reserve_a")
        total_liquidity = storage.get("total_liquidity")

        ctx = self._prepare_remove_liquidity_context(amount_a, amount_b)

        ctx.address = ctx_add.address
        user_liquidity = self.runner.call_view_method(
            self.nc_id, "liquidity_of", ctx.address
        )

        self.runner.call_public_method(self.nc_id, "remove_liquidity", ctx)

        self.assertEqual(reserve_a - amount_a, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b - amount_b, storage.get_balance(self.token_b))

        reserve_after = (reserve_a - amount_a, reserve_b - amount_b)
        self.assertEqual(
            reserve_after, self.runner.call_view_method(self.nc_id, "get_reserves")
        )

        self.assertEqual(
            (0, 0), self.runner.call_view_method(self.nc_id, "balance_of", ctx.address)
        )
        self.assertBalanceReserve(storage)

        liquidity_decrease = total_liquidity * amount_a // reserve_a

        get_liquidity = liquidity_decrease

        user_liquidity_after = user_liquidity - get_liquidity

        self.assertEqual(
            user_liquidity_after,
            self.runner.call_view_method(self.nc_id, "liquidity_of", ctx.address),
        )
        return ctx

    def test_remove_liquidity_with_change(self) -> Context:
        ctx_add = self.test_add_liquidity_no_change()
        storage = self.nc_storage

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a = 10_00
        amount_b = self.runner.call_view_method(
            self.nc_id, "quote", amount_a, reserve_a, reserve_b
        )
        change = 1

        amount_b -= change  # in this case the user is asking for less b tokens than he has right to receive

        reserve_a = storage.get("reserve_a")
        total_liquidity = storage.get("total_liquidity")

        ctx = self._prepare_remove_liquidity_context(amount_a, amount_b)

        ctx.address = ctx_add.address
        user_liquidity = self.runner.call_view_method(
            self.nc_id, "liquidity_of", ctx.address
        )

        self.runner.call_public_method(self.nc_id, "remove_liquidity", ctx)

        self.assertEqual(reserve_a - amount_a, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b - amount_b, storage.get_balance(self.token_b))

        reserve_after = (reserve_a - amount_a, reserve_b - amount_b - change)
        self.assertEqual(
            reserve_after, self.runner.call_view_method(self.nc_id, "get_reserves")
        )

        self.assertEqual(
            (0, change),
            self.runner.call_view_method(self.nc_id, "balance_of", ctx.address),
        )
        self.assertBalanceReserve(storage)

        liquidity_decrease = total_liquidity * amount_a // reserve_a

        get_liquidity = liquidity_decrease

        user_liquidity_after = user_liquidity - get_liquidity

        self.assertEqual(
            user_liquidity_after,
            self.runner.call_view_method(self.nc_id, "liquidity_of", ctx.address),
        )
        return ctx

    def test_remove_liquidity_amount_a_too_high(self) -> None:
        ctx_add = self.test_add_liquidity_no_change()
        storage = self.nc_storage

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a = 2000_00
        amount_b = self.runner.call_view_method(
            self.nc_id, "quote", amount_a, reserve_a, reserve_b
        )

        ctx = self._prepare_remove_liquidity_context(amount_a, amount_b)
        ctx.address = ctx_add.address

        with self.assertRaises(NCFail):
            self.runner.call_public_method(self.nc_id, "remove_liquidity", ctx)

    def test_remove_liquidity_amount_b_too_high(self) -> None:
        ctx_add = self.test_add_liquidity_no_change()
        storage = self.nc_storage

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a = 10_00
        amount_b = self.runner.call_view_method(
            self.nc_id, "quote", amount_a, reserve_a, reserve_b
        )
        exceeding_amount = 1

        amount_b += exceeding_amount

        ctx = self._prepare_remove_liquidity_context(amount_a, amount_b)
        ctx.address = ctx_add.address

        with self.assertRaises(NCFail):
            self.runner.call_public_method(self.nc_id, "remove_liquidity", ctx)

    def test_remove_liquidity_wrong_user(self) -> None:
        _ = self.test_add_liquidity_no_change()
        storage = self.nc_storage

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a = 10_00
        amount_b = self.runner.call_view_method(
            self.nc_id, "quote", amount_a, reserve_a, reserve_b
        )

        ctx = self._prepare_remove_liquidity_context(
            amount_a, amount_b
        )  # creating new context without getting the address from add_liquidity

        with self.assertRaises(NCFail):
            self.runner.call_public_method(self.nc_id, "remove_liquidity", ctx)

    def test_add_swap_remove(self) -> None:
        ctx_add = self.test_add_liquidity_no_change()
        storage = self.nc_storage

        address_user_with_liquidity = ctx_add.address

        reserve_a = storage.get_balance(self.token_a)
        reserve_b = storage.get_balance(self.token_b)

        amount_a_swap = 20_00
        amount_b_swap = self.runner.call_view_method(
            self.nc_id, "get_amount_out", amount_a_swap, reserve_a, reserve_b
        )

        ctx_swap1, result_swap1 = self._swap1(
            self.token_a, amount_a_swap, self.token_b, amount_b_swap
        )

        self.assertEqual(reserve_a + amount_a_swap, storage.get_balance(self.token_a))
        self.assertEqual(reserve_b - amount_b_swap, storage.get_balance(self.token_b))

        reserve_after = (reserve_a + amount_a_swap, reserve_b - amount_b_swap)
        self.assertEqual(
            reserve_after, self.runner.call_view_method(self.nc_id, "get_reserves")
        )

        (reserve_a_after, reserve_b_after) = self.runner.call_view_method(
            self.nc_id, "get_reserves"
        )

        amount_a_remove = 50_00
        amount_b_remove = self.runner.call_view_method(
            self.nc_id, "quote", amount_a_remove, reserve_a_after, reserve_b_after
        )

        total_liquidity = storage.get("total_liquidity")

        ctx_remove = self._prepare_remove_liquidity_context(
            amount_a_remove, amount_b_remove
        )

        ctx_remove.address = address_user_with_liquidity
        user_liquidity = self.runner.call_view_method(
            self.nc_id, "liquidity_of", ctx_remove.address
        )

        self.runner.call_public_method(self.nc_id, "remove_liquidity", ctx_remove)

        self.assertEqual(
            (0, 0),
            self.runner.call_view_method(self.nc_id, "balance_of", ctx_remove.address),
        )
        self.assertBalanceReserve(storage)

        liquidity_decrease = total_liquidity * amount_a_remove // reserve_a_after

        get_liquidity = liquidity_decrease

        user_liquidity_after = user_liquidity - get_liquidity

        self.assertEqual(
            user_liquidity_after,
            self.runner.call_view_method(
                self.nc_id, "liquidity_of", ctx_remove.address
            ),
        )

        reserve_a_after_remove = reserve_a_after - amount_a_remove
        reserve_b_after_remove = reserve_b_after - amount_b_remove

        self.assertEqual(
            (reserve_a_after_remove, reserve_b_after_remove),
            self.runner.call_view_method(self.nc_id, "get_reserves"),
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
            amount_b = self.runner.call_view_method(
                self.nc_id, "quote", amount_a, reserve_a, reserve_b
            )

            ctx = self._prepare_add_liquidity_context(amount_a, amount_b)
            self.runner.call_public_method(self.nc_id, "add_liquidity", ctx)

            self.assertEqual(reserve_a + amount_a, storage.get("reserve_a"))
            self.assertEqual(reserve_b + amount_b, storage.get("reserve_b"))

            liquidity_increase = total_liquidity * amount_a // reserve_a
            user_liquidity = liquidity_increase

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
                self.runner.call_view_method(
                    self.nc_id, "liquidity_of", ctx_adds[i].address
                ),
            )

        total_liquidity = storage.get("total_liquidity")
        reserve_a = storage.get("reserve_a")
        reserve_b = storage.get("reserve_b")
        for i in range(users):
            amount_a = amounts_a[i]
            amount_b = self.runner.call_view_method(
                self.nc_id, "quote", amount_a, reserve_a, reserve_b
            )
            ctx = self._prepare_remove_liquidity_context(amount_a, amount_b)
            ctx.address = ctx_adds[i].address
            self.runner.call_public_method(self.nc_id, "remove_liquidity", ctx)

            self.assertEqual(reserve_a - amount_a, storage.get("reserve_a"))
            self.assertEqual(reserve_b - amount_b, storage.get("reserve_b"))

            liquidity_decrease = total_liquidity * amount_a // reserve_a

            user_liquidity = users_liquidity[i] - liquidity_decrease
            print(
                f"user_liquidity_before:{users_liquidity[i]}\n user_liquidity_after: {user_liquidity} \n \
                      total_liquidity: {total_liquidity}, amounts_a[i]: {amounts_a[i]}"
            )
            self.assertEqual(
                user_liquidity,
                self.runner.call_view_method(
                    self.nc_id, "liquidity_of", ctx_adds[i].address
                ),
            )
            self.assertEqual(
                total_liquidity - liquidity_decrease,
                storage.get("total_liquidity"),
            )

            reserve_a -= amount_a
            reserve_b -= amount_b
            total_liquidity -= liquidity_decrease

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
        dev_liquidity = self.runner.call_view_method(
            self.nc_id, "liquidity_of", self.admin_address
        )
        fee_numerator = storage.get("fee_numerator")
        fee_denominator = storage.get("fee_denominator")
        protocol_fee = storage.get("protocol_fee")
        total_liquidity = storage.get("total_liquidity")
        reserve_a = storage.get("reserve_a")
        reserve_b = storage.get("reserve_b")
        for i in range(users):
            amount_a = amounts_a[i]
            amount_b = self.runner.call_view_method(
                self.nc_id, "quote", amount_a, reserve_a, reserve_b
            )

            ctx = self._prepare_add_liquidity_context(amount_a, amount_b)
            self.runner.call_public_method(self.nc_id, "add_liquidity", ctx)

            self.assertEqual(reserve_a + amount_a, storage.get("reserve_a"))
            self.assertEqual(reserve_b + amount_b, storage.get("reserve_b"))

            liquidity_increase = total_liquidity * amount_a // reserve_a
            user_liquidity = liquidity_increase

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
                self.runner.call_view_method(
                    self.nc_id, "liquidity_of", ctx_adds[i].address
                ),
            )

        fee_accumulated = 0

        for i in range(users):
            amount_a = swaps_amounts_a[i]
            amount_b = self.runner.call_view_method(
                self.nc_id, "get_amount_out", amount_a, reserve_a, reserve_b
            )
            a = storage.get("fee_denominator") - storage.get("fee_numerator")
            b = storage.get("fee_denominator")
            amount_out = (reserve_b * amount_a * a) // (reserve_a * b + amount_a * a)

            self.assertEqual(amount_b, amount_out)

            fee_amount = amount_a * fee_numerator // fee_denominator
            fee_accumulated += fee_amount
            protocol_fee_amount = fee_amount * protocol_fee // 100
            liquidity_increase = (
                total_liquidity * (protocol_fee_amount) // (reserve_a * 2)
            )

            self.assertEqual(
                liquidity_increase,
                self.runner.call_view_method(
                    self.nc_id,
                    "_get_protocol_liquidity_increase",
                    protocol_fee_amount,
                    self.token_a,
                ),
            )

            ctx, result = self._swap1(self.token_a, amount_a, self.token_b, amount_b)

            dev_liquidity += liquidity_increase
            self.assertEqual(
                dev_liquidity,
                self.runner.call_view_method(
                    self.nc_id, "liquidity_of", self.admin_address
                ),
            )

            self.assertEqual(
                fee_accumulated,
                self.runner.call_view_method(
                    self.nc_id, "accumulated_fee_of", self.token_a
                ),
            )

            total_liquidity += liquidity_increase
            reserve_a += amount_a
            reserve_b -= amount_b

        self.assertEqual(
            fee_accumulated,
            self.runner.call_view_method(
                self.nc_id, "accumulated_fee_of", self.token_a
            ),
        )

        self.assertEqual(storage.get("reserve_a"), reserve_a)
        self.assertEqual(storage.get("reserve_b"), reserve_b)
        self.assertEqual(storage.get("total_liquidity"), total_liquidity)

        for i in range(users):
            user_liquidity = users_liquidity[i]
            self.assertEqual(
                user_liquidity,
                self.runner.call_view_method(
                    self.nc_id, "liquidity_of", ctx_adds[i].address
                ),
            )

            print(
                f"user_liquidity: {user_liquidity}, total_liquidity: {total_liquidity}, amounts_a[i]: {amounts_a[i]}"
            )

            remove_amount_a = user_liquidity * reserve_a // total_liquidity
            remove_amount_b = self.runner.call_view_method(
                self.nc_id, "quote", remove_amount_a, reserve_a, reserve_b
            )

            self.assertGreater(remove_amount_a, amounts_a[i])

            ctx = self._prepare_remove_liquidity_context(
                remove_amount_a, remove_amount_b
            )
            ctx.address = ctx_adds[i].address
            self.runner.call_public_method(self.nc_id, "remove_liquidity", ctx)

            self.assertEqual(reserve_a - remove_amount_a, storage.get("reserve_a"))
            self.assertEqual(reserve_b - remove_amount_b, storage.get("reserve_b"))

            liquidity_decrease = total_liquidity * remove_amount_a // reserve_a

            total_liquidity -= liquidity_decrease
            reserve_a -= remove_amount_a
            reserve_b -= remove_amount_b

            self.assertEqual(
                self.runner.call_view_method(self.nc_id, "liquidity_of", ctx.address),
                user_liquidity - liquidity_decrease,
            )
            # failing in decimal cases, need to think in a better way to store liquidity

    def test_front_end_api_pool(self) -> None:
        self._initialize_contract(1_000_00, 500_000, fee=5)

        # Perform a swap to generate some volume and fees
        amount_in = 50_00
        amount_out = self.runner.call_view_method(
            self.nc_id, "get_amount_out", amount_in, 1_000_00, 500_000
        )
        self._swap1(self.token_a, amount_in, self.token_b, amount_out)

        # Call the front_end_api_pool method
        pool_info = self.runner.call_view_method(self.nc_id, "front_end_api_pool")

        # Assert the returned values
        self.assertIn("reserve0", pool_info)
        self.assertIn("reserve1", pool_info)
        self.assertIn("fee", pool_info)
        self.assertIn("volume", pool_info)
        self.assertIn("fee0", pool_info)
        self.assertIn("fee1", pool_info)
        self.assertIn("dzr_rewards", pool_info)
        self.assertIn("transactions", pool_info)

        # Check specific values
        self.assertEqual(
            pool_info["reserve0"], 1_050_00
        )  # Initial 1_000_00 + 50_00 swapped in
        self.assertEqual(pool_info["reserve1"], 500_000 - amount_out)
        self.assertEqual(pool_info["fee"], 0.005)  # 5/1000
        self.assertEqual(pool_info["volume"], 50_00)
        self.assertGreater(pool_info["fee0"], 0)  # Should have collected some fees
        self.assertEqual(pool_info["fee1"], 0)  # No fees collected for token B
        self.assertEqual(pool_info["dzr_rewards"], 1000)
        self.assertEqual(pool_info["transactions"], 1)

        # Perform another swap
        amount_in = 30_00
        amount_out = self.runner.call_view_method(
            self.nc_id,
            "get_amount_out",
            amount_in,
            pool_info["reserve0"],
            pool_info["reserve1"],
        )
        self._swap1(self.token_a, amount_in, self.token_b, amount_out)

        # Call the front_end_api_pool method again
        updated_pool_info = self.runner.call_view_method(
            self.nc_id, "front_end_api_pool"
        )

        # Check that values have updated correctly
        self.assertEqual(updated_pool_info["reserve0"], 1_080_00)
        self.assertEqual(
            updated_pool_info["reserve1"], pool_info["reserve1"] - amount_out
        )
        self.assertEqual(updated_pool_info["volume"], 80_00)
        self.assertGreater(updated_pool_info["fee0"], pool_info["fee0"])
        self.assertEqual(updated_pool_info["transactions"], 2)

    def test_add_swap_remove_liquidity_random(self) -> None:
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 500_000, fee=5)

        # Helper function to get current reserves
        def get_reserves():
            return self.runner.call_view_method(self.nc_id, "get_reserves")

        # Helper function to calculate expected amount out
        def get_amount_out(amount_in, reserve_in, reserve_out):
            return self.runner.call_view_method(
                self.nc_id, "get_amount_out", amount_in, reserve_in, reserve_out
            )

        # Add liquidity
        add_amount_a = random.randint(100_00, 500_00)
        reserve_a, reserve_b = get_reserves()
        add_amount_b = self.runner.call_view_method(
            self.nc_id, "quote", add_amount_a, reserve_a, reserve_b
        )

        ctx_add = self._prepare_add_liquidity_context(add_amount_a, add_amount_b)
        self.runner.call_public_method(self.nc_id, "add_liquidity", ctx_add)

        new_reserve_a, new_reserve_b = get_reserves()
        self.assertEqual(new_reserve_a, reserve_a + add_amount_a)
        self.assertEqual(new_reserve_b, reserve_b + add_amount_b)

        # Perform swaps
        num_swaps = random.randint(1, 5)
        total_amount_a_swapped = 0
        total_amount_b_swapped = 0

        for _ in range(num_swaps):
            swap_amount_a = random.randint(10_00, 50_00)
            reserve_a, reserve_b = get_reserves()
            expected_amount_b = get_amount_out(swap_amount_a, reserve_a, reserve_b)

            ctx_swap, result_swap = self._swap1(
                self.token_a, swap_amount_a, self.token_b, expected_amount_b
            )

            total_amount_a_swapped += swap_amount_a
            total_amount_b_swapped += expected_amount_b

            new_reserve_a, new_reserve_b = get_reserves()
            self.assertEqual(new_reserve_a, reserve_a + swap_amount_a)
            self.assertEqual(new_reserve_b, reserve_b - expected_amount_b)

        # Check pool info after swaps
        pool_info = self.runner.call_view_method(self.nc_id, "front_end_api_pool")
        self.assertEqual(pool_info["volume"], total_amount_a_swapped)
        self.assertEqual(pool_info["transactions"], num_swaps)

        # Remove liquidity
        reserve_a, reserve_b = get_reserves()
        user_liquidity = self.runner.call_view_method(
            self.nc_id, "liquidity_of", ctx_add.address
        )
        total_liquidity = storage.get("total_liquidity")

        remove_amount_a = user_liquidity * reserve_a // total_liquidity
        remove_amount_b = self.runner.call_view_method(
            self.nc_id, "quote", remove_amount_a, reserve_a, reserve_b
        )

        ctx_remove = self._prepare_remove_liquidity_context(
            remove_amount_a, remove_amount_b
        )
        ctx_remove.address = ctx_add.address
        self.runner.call_public_method(self.nc_id, "remove_liquidity", ctx_remove)

        final_reserve_a, final_reserve_b = get_reserves()
        self.assertEqual(final_reserve_a, reserve_a - remove_amount_a)
        self.assertEqual(final_reserve_b, reserve_b - remove_amount_b)

        # Check final user liquidity
        final_user_liquidity = self.runner.call_view_method(
            self.nc_id, "liquidity_of", ctx_add.address
        )
        # self.assertEqual(
        #     final_user_liquidity // PRECISION, user_liquidity // PRECISION
        # )
        self.assertEqual(final_user_liquidity // PRECISION, 0)

        # Check final pool info
        final_pool_info = self.runner.call_view_method(self.nc_id, "front_end_api_pool")
        self.assertEqual(final_pool_info["reserve0"], final_reserve_a)
        self.assertEqual(final_pool_info["reserve1"], final_reserve_b)
        self.assertEqual(final_pool_info["volume"], total_amount_a_swapped)
        self.assertEqual(final_pool_info["transactions"], num_swaps)

    def test_random_user_interactions(self):
        storage = self.nc_storage
        self._initialize_contract(1_000_00, 500_000, fee=5)

        # Helper functions
        def get_reserves() -> tuple[int, int]:
            return self.runner.call_view_method(self.nc_id, "get_reserves")

        def get_amount_out(amount_in, reserve_in, reserve_out):
            return self.runner.call_view_method(
                self.nc_id, "get_amount_out", amount_in, reserve_in, reserve_out
            )

        users_with_liquidity = set()
        all_users = set()

        # Define possible actions
        actions = ["add_liquidity", "remove_liquidity", "swap_a_to_b", "swap_b_to_a"]

        # Perform random actions
        num_actions = random.randint(20, 40)
        total_volume = 0
        transactions = 0

        # total_liquidity = storage.get("total_liquidity")

        for _ in range(num_actions):
            action = random.choice(actions)
            reserve_a, reserve_b = get_reserves()
            total_liquidity = storage.get("total_liquidity")

            if action == "add_liquidity":
                add_amount_a = random.randint(10_00, 100_00)
                add_amount_b = self.runner.call_view_method(
                    self.nc_id, "quote", add_amount_a, reserve_a, reserve_b
                )

                ctx_add = self._prepare_add_liquidity_context(
                    add_amount_a, add_amount_b
                )
                users_with_liquidity.add(ctx_add.address)
                all_users.add(ctx_add.address)
                self.runner.call_public_method(self.nc_id, "add_liquidity", ctx_add)

                # Assert reserves after adding liquidity
                new_reserve_a, new_reserve_b = get_reserves()
                self.assertEqual(new_reserve_a, reserve_a + add_amount_a)
                self.assertEqual(new_reserve_b, reserve_b + add_amount_b)

                # Check liquidity increase
                new_total_liquidity = storage.get("total_liquidity")
                self.assertGreater(new_total_liquidity, total_liquidity)
                user_liquidity = self.runner.call_view_method(
                    self.nc_id, "liquidity_of", ctx_add.address
                )
                self.assertGreater(user_liquidity, 0)

                # transactions += 1

            elif action == "remove_liquidity" and users_with_liquidity:
                user = random.choice(list(users_with_liquidity))
                user_liquidity = self.runner.call_view_method(
                    self.nc_id, "liquidity_of", user
                )
                percentage_to_remove = random.randint(1, 100)
                if user_liquidity > 0:
                    total_liquidity = storage.get("total_liquidity")
                    new_reserve_a, new_reserve_b = get_reserves()
                    remove_amount_a = (
                        percentage_to_remove
                        * (user_liquidity)
                        * new_reserve_a
                        // (100 * total_liquidity)
                    )
                    remove_amount_b = self.runner.call_view_method(
                        self.nc_id, "quote", remove_amount_a, reserve_a, reserve_b
                    )

                    ctx_remove = self._prepare_remove_liquidity_context(
                        remove_amount_a, remove_amount_b
                    )
                    ctx_remove.address = user
                    self.runner.call_public_method(
                        self.nc_id, "remove_liquidity", ctx_remove
                    )

                    # Assert reserves after removing liquidity
                    new_reserve_a, new_reserve_b = get_reserves()
                    self.assertEqual(new_reserve_a, reserve_a - remove_amount_a)
                    self.assertEqual(new_reserve_b, reserve_b - remove_amount_b)

                    # Check liquidity decrease
                    new_total_liquidity = storage.get("total_liquidity")
                    self.assertLess(new_total_liquidity, total_liquidity)
                    new_user_liquidity = self.runner.call_view_method(
                        self.nc_id, "liquidity_of", user
                    )
                    self.assertLess(new_user_liquidity, user_liquidity)

                    # remove user from user_with_liquidity
                    users_with_liquidity.remove(user)
                    # transactions += 1

            elif action == "swap_a_to_b":
                swap_amount_a = random.randint(1_00, 50_00)
                expected_amount_b = get_amount_out(swap_amount_a, reserve_a, reserve_b)

                _, ctx = self._swap1(
                    self.token_a, swap_amount_a, self.token_b, expected_amount_b
                )
                all_users.add(ctx.address)
                total_volume += swap_amount_a
                transactions += 1

                # Assert reserves after swapping A to B
                new_reserve_a, new_reserve_b = get_reserves()
                self.assertEqual(new_reserve_a, reserve_a + swap_amount_a)
                self.assertEqual(new_reserve_b, reserve_b - expected_amount_b)

                # calculate liquidity change after swap protocol fee
                new_total_liquidity = storage.get("total_liquidity")
                # self.assertEqual(new_total_liquidity, total_liquidity)

            elif action == "swap_b_to_a":
                swap_amount_b = random.randint(1_00, 50_00)
                expected_amount_a = get_amount_out(swap_amount_b, reserve_b, reserve_a)

                _, ctx = self._swap1(
                    self.token_b, swap_amount_b, self.token_a, expected_amount_a
                )
                all_users.add(ctx.address)
                # total_volume += swap_amount_b
                transactions += 1

                # Assert reserves after swapping B to A
                new_reserve_a, new_reserve_b = get_reserves()
                self.assertEqual(new_reserve_a, reserve_a - expected_amount_a)
                self.assertEqual(new_reserve_b, reserve_b + swap_amount_b)

                # Check total liquidity change for protocol fee
                new_total_liquidity = storage.get("total_liquidity")
                # self.assertEqual(new_total_liquidity, total_liquidity)

            # Assert that reserves are always positive after each action
            current_reserve_a, current_reserve_b = get_reserves()
            self.assertGreater(current_reserve_a, 0)
            self.assertGreater(current_reserve_b, 0)

        # Final assertions
        final_reserve_a, final_reserve_b = get_reserves()
        final_total_liquidity = storage.get("total_liquidity")
        pool_info = self.runner.call_view_method(self.nc_id, "front_end_api_pool")

        self.assertEqual(pool_info["reserve0"], final_reserve_a)
        self.assertEqual(pool_info["reserve1"], final_reserve_b)
        self.assertEqual(pool_info["volume"], total_volume)
        self.assertEqual(pool_info["transactions"], transactions)

        # Check that reserves are still positive
        self.assertGreater(final_reserve_a, 0)
        self.assertGreater(final_reserve_b, 0)

        # Check final total liquidity

        # Check that all users have zero or positive liquidity
        for user in all_users:
            user_liquidity = self.runner.call_view_method(
                self.nc_id, "liquidity_of", user
            )
            self.assertGreaterEqual(user_liquidity, 0)

        # Check that the sum of all user liquidities plus admin liquidity equals total liquidity
        total_user_liquidity = sum(
            self.runner.call_view_method(self.nc_id, "liquidity_of", user)
            for user in all_users
        )
        admin_liquidity = self.runner.call_view_method(
            self.nc_id, "liquidity_of", self.admin_address
        )
        print(type(total_user_liquidity))
        print(type(admin_liquidity))
        print(type(final_total_liquidity))
        print("total_user_liquidity:", total_user_liquidity)
        print("admin_liquidity:", admin_liquidity)
        print("final_total_liquidity:", final_total_liquidity)
        self.assertEqual(
            (total_user_liquidity + admin_liquidity),
            final_total_liquidity,
        )
