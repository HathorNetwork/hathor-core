from math import ceil
from pprint import pprint

from hathor import Context, NCDepositAction, NCFail, NCWithdrawalAction
from hathor.conf import HathorSettings
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathor_tests.nanocontracts.test_blueprints.liquidity_pool import LiquidityPool

settings = HathorSettings()


class LiquidityPoolBlueprintTestCase(BlueprintTestCase):
    def setUp(self):
        super().setUp()

        self.blueprint_id = self._register_blueprint_class(LiquidityPool)
        self.nc_id = self.gen_random_contract_id()

        self.token_a = self.gen_random_token_uid()
        self.token_b = self.gen_random_token_uid()
        self.lp_token = self.gen_random_token_uid()

    def _get_any_tx(self):
        return self.get_genesis_tx()

    def _get_any_address(self):
        return self.gen_random_address_with_key()

    def get_current_timestamp(self):
        return int(self.clock.seconds())

    def _initialize_contract(self, reserve_a, reserve_b):
        tx = self._get_any_tx()
        actions = [
            NCDepositAction(token_uid=self.token_a, amount=reserve_a),
            NCDepositAction(token_uid=self.token_b,  amount=reserve_b),
        ]
        context = self.create_context(actions=actions)
        self.runner.create_contract(
            self.nc_id,
            self.blueprint_id,
            context,
            self.token_a,
            self.token_b,
            self.lp_token,
            0
        )

        self.nc_storage = self.runner.get_storage(self.nc_id)
        self.contract = self.get_readonly_contract(self.nc_id)
        self.assertEqual(self.contract.token_a, self.token_a)
        self.assertEqual(self.contract.token_b, self.token_b)
        self.assertEqual(self.contract.lp_token, self.lp_token)

    def _prepare_swap_context(self, token_in, amount_in, token_out, amount_out):
        tx = self._get_any_tx()
        actions = [
            NCDepositAction(token_uid=token_in, amount=amount_in),
            NCWithdrawalAction(token_uid=token_out, amount=amount_out),
        ]
        return self.create_context(actions=actions)

    def _swap1(self, token_in, amount_in, token_out, amount_out):
        context = self._prepare_swap_context(token_in, amount_in, token_out, amount_out)
        result = self.runner.call_public_method(self.nc_id, 'swap_exact_tokens_for_tokens', context, context.caller_id)
        return result, context

    def _swap2(self, token_in, amount_in, token_out, amount_out):
        context = self._prepare_swap_context(token_in, amount_in, token_out, amount_out)
        result = self.runner.call_public_method(self.nc_id, 'swap_tokens_for_exact_tokens', context, context.caller_id)
        return result, context

    def assertBalanceReserve(self, storage):
        reserve_a = self.contract.reserve_a
        total_balance_a = self.contract.total_balance_a
        self.assertEqual(storage.get_balance(self.token_a).value, reserve_a + total_balance_a)

        reserve_b = self.contract.reserve_b
        total_balance_b = self.contract.total_balance_b
        self.assertEqual(storage.get_balance(self.token_b).value, reserve_b + total_balance_b)

    def test_swap1_no_change(self) -> None:
        self._initialize_contract(1_000_00, 1_000_00)
        storage = self.nc_storage

        reserve_a = storage.get_balance(self.token_a).value
        reserve_b = storage.get_balance(self.token_b).value

        amount_in = 20_00
        amount_out = self.runner.call_view_method(self.nc_id, 'get_amount_out', amount_in, reserve_a, reserve_b)

        _, context = self._swap1(self.token_a, amount_in, self.token_b, amount_out)

        self.assertEqual(reserve_a + amount_in, storage.get_balance(self.token_a).value)
        self.assertEqual(reserve_b - amount_out, storage.get_balance(self.token_b).value)

        reserve_after = (reserve_a + amount_in, reserve_b - amount_out)
        self.assertEqual(reserve_after, self.runner.call_view_method(self.nc_id, 'get_reserves'))

        self.assertEqual(0, self.contract.total_balance_a)
        self.assertEqual(0, self.contract.total_balance_b)

        self.assertEqual((0, 0), self.runner.call_view_method(self.nc_id, 'balance_of', context.caller_id))
        self.assertBalanceReserve(storage)

    def test_swap1_with_change(self) -> None:
        self._initialize_contract(1_000_00, 1_000_00)
        storage = self.nc_storage

        reserve_a = storage.get_balance(self.token_a).value
        reserve_b = storage.get_balance(self.token_b).value

        change = 1
        amount_in = 20_00
        amount_out = self.runner.call_view_method(self.nc_id, 'get_amount_out', amount_in, reserve_a, reserve_b)
        amount_out -= change

        _, context = self._swap1(self.token_a, amount_in, self.token_b, amount_out)

        self.assertEqual(reserve_a + amount_in, storage.get_balance(self.token_a).value)
        self.assertEqual(reserve_b - amount_out, storage.get_balance(self.token_b).value)

        reserve_after = (reserve_a + amount_in, reserve_b - amount_out - change)
        self.assertEqual(reserve_after, self.runner.call_view_method(self.nc_id, 'get_reserves'))

        self.assertEqual(0, self.contract.total_balance_a)
        self.assertEqual(1, self.contract.total_balance_b)

        self.assertEqual((0, change), self.runner.call_view_method(self.nc_id, 'balance_of', context.caller_id))
        self.assertBalanceReserve(storage)

    def test_swap1_amount_out_too_high(self) -> None:
        self._initialize_contract(1_000_00, 1_000_00)
        storage = self.nc_storage

        reserve_a = storage.get_balance(self.token_a).value
        reserve_b = storage.get_balance(self.token_b).value

        amount_in = 20_00
        amount_out = self.runner.call_view_method(self.nc_id, 'get_amount_out', amount_in, reserve_a, reserve_b)

        with self.assertRaises(NCFail):
            self._swap1(self.token_a, amount_in, self.token_b, amount_out + 1)

    def test_swap1_multiple_swaps(self) -> None:
        self._initialize_contract(1_000_00, 2_500_00)
        storage = self.nc_storage

        last_result = None

        for _ in range(100):
            reserve_a = storage.get_balance(self.token_a).value
            reserve_b = storage.get_balance(self.token_b).value

            amount_in = 20_00
            amount_out = self.runner.call_view_method(self.nc_id, 'get_amount_out', amount_in, reserve_a, reserve_b)

            result, _ = self._swap1(self.token_a, amount_in, self.token_b, amount_out)
            if last_result is not None:
                self.assertLess(result.amount_out, last_result.amount_out)
            last_result = result

    def test_swap2_no_change(self) -> None:
        self._initialize_contract(1_000_00, 1_000_00)
        storage = self.nc_storage

        reserve_a = storage.get_balance(self.token_a).value
        reserve_b = storage.get_balance(self.token_b).value

        amount_out = 20_00
        amount_in = self.runner.call_view_method(self.nc_id, 'get_amount_in', amount_out, reserve_a, reserve_b)

        _, context = self._swap2(self.token_a, amount_in, self.token_b, amount_out)

        self.assertEqual(reserve_a + amount_in, storage.get_balance(self.token_a).value)
        self.assertEqual(reserve_b - amount_out, storage.get_balance(self.token_b).value)

        reserve_after = (reserve_a + amount_in, reserve_b - amount_out)
        self.assertEqual(reserve_after, self.runner.call_view_method(self.nc_id, 'get_reserves'))

        self.assertEqual(0, self.contract.total_balance_a)
        self.assertEqual(0, self.contract.total_balance_b)

        self.assertEqual((0, 0), self.runner.call_view_method(self.nc_id, 'balance_of', context.caller_id))
        self.assertBalanceReserve(storage)

    def test_swap2_with_change(self) -> None:
        self._initialize_contract(1_000_00, 1_000_00)
        storage = self.nc_storage

        reserve_a = storage.get_balance(self.token_a).value
        reserve_b = storage.get_balance(self.token_b).value

        change = 1
        amount_out = 20_00
        amount_in = self.runner.call_view_method(self.nc_id, 'get_amount_in', amount_out, reserve_a, reserve_b)
        amount_in += change

        _, context = self._swap2(self.token_a, amount_in, self.token_b, amount_out)

        self.assertEqual(reserve_a + amount_in, storage.get_balance(self.token_a).value)
        self.assertEqual(reserve_b - amount_out, storage.get_balance(self.token_b).value)

        reserve_after = (reserve_a + amount_in - change, reserve_b - amount_out)
        self.assertEqual(reserve_after, self.runner.call_view_method(self.nc_id, 'get_reserves'))

        self.assertEqual(1, self.contract.total_balance_a)
        self.assertEqual(0, self.contract.total_balance_b)

        self.assertEqual((change, 0), self.runner.call_view_method(self.nc_id, 'balance_of', context.caller_id))
        self.assertBalanceReserve(storage)

    def test_swap2_amount_in_too_low(self) -> None:
        self._initialize_contract(1_000_00, 1_000_00)
        storage = self.nc_storage

        reserve_a = storage.get_balance(self.token_a).value
        reserve_b = storage.get_balance(self.token_b).value

        amount_out = 20_00
        amount_in = self.runner.call_view_method(self.nc_id, 'get_amount_in', amount_out, reserve_a, reserve_b)

        with self.assertRaises(NCFail):
            self._swap2(self.token_a, amount_in - 1, self.token_b, amount_out)

    def test_amount_in_out(self) -> None:
        self._initialize_contract(1, 1)
        self.assertEqual(19_60, self.runner.call_view_method(self.nc_id,
                                                                'get_amount_out',
                                                                20_00,
                                                                1_000_00,
                                                                1_000_00))
        self.assertEqual(20_40, self.runner.call_view_method(self.nc_id,
                                                                'get_amount_in',
                                                                20_00,
                                                                1_000_00,
                                                                1_000_00))

    def _prepare_add_liquidity_context(self, amount_a, amount_b):
        actions = [
            NCDepositAction(token_uid=self.token_a, amount=amount_a),
            NCDepositAction(token_uid=self.token_b, amount=amount_b),
        ]
        return self.create_context(actions=actions)

    def test_add_liquidity_no_change(self) -> None:
        self._initialize_contract(1_000_00, 500_000)
        storage = self.nc_storage

        reserve_a = storage.get_balance(self.token_a).value
        reserve_b = storage.get_balance(self.token_b).value

        amount_a = 100_00
        amount_b = self.runner.call_view_method(self.nc_id, 'quote', amount_a, reserve_a, reserve_b)

        ctx = self._prepare_add_liquidity_context(amount_a, amount_b)
        self.runner.call_public_method(self.nc_id, 'add_liquidity', ctx, amount_a, amount_b, ctx.caller_id)

        self.assertEqual(reserve_a + amount_a, storage.get_balance(self.token_a).value)
        self.assertEqual(reserve_b + amount_b, storage.get_balance(self.token_b).value)

        reserve_after = (reserve_a + amount_a, reserve_b + amount_b)
        self.assertEqual(reserve_after, self.runner.call_view_method(self.nc_id, 'get_reserves'))

    def test_add_liquidity_change_a(self) -> None:
        self._initialize_contract(1_000_00, 500_000)
        storage = self.nc_storage

        reserve_a = storage.get_balance(self.token_a).value
        reserve_b = storage.get_balance(self.token_b).value

        amount_a = 100_00
        amount_b = self.runner.call_view_method(self.nc_id, 'quote', amount_a, reserve_a, reserve_b)
        change = 1

        amount_a_min = amount_a
        amount_b_min = amount_b

        amount_a += change

        ctx = self._prepare_add_liquidity_context(amount_a, amount_b)
        self.runner.call_public_method(self.nc_id, 'add_liquidity', ctx, amount_a_min, amount_b_min, ctx.caller_id)

        self.assertEqual(reserve_a + amount_a, storage.get_balance(self.token_a).value)
        self.assertEqual(reserve_b + amount_b, storage.get_balance(self.token_b).value)

        reserve_after = (reserve_a + amount_a - change, reserve_b + amount_b)
        self.assertEqual(reserve_after, self.runner.call_view_method(self.nc_id, 'get_reserves'))

        self.assertEqual(change, self.contract.total_balance_a)
        self.assertEqual(0, self.contract.total_balance_b)

        self.assertEqual((change, 0), self.runner.call_view_method(self.nc_id, 'balance_of', ctx.caller_id))
        self.assertBalanceReserve(storage)

    def test_add_liquidity_change_b(self) -> None:
        self._initialize_contract(1_000_00, 500_000)
        storage = self.nc_storage

        reserve_a = storage.get_balance(self.token_a).value
        reserve_b = storage.get_balance(self.token_b).value

        amount_a = 100_00
        amount_b = self.runner.call_view_method(self.nc_id, 'quote', amount_a, reserve_a, reserve_b)
        change = 1

        amount_a_min = amount_a
        amount_b_min = amount_b

        amount_b += change

        ctx = self._prepare_add_liquidity_context(amount_a, amount_b)
        self.runner.call_public_method(self.nc_id, 'add_liquidity', ctx, amount_a_min, amount_b_min, ctx.caller_id)

        self.assertEqual(reserve_a + amount_a, storage.get_balance(self.token_a).value)
        self.assertEqual(reserve_b + amount_b, storage.get_balance(self.token_b).value)

        reserve_after = (reserve_a + amount_a, reserve_b + amount_b - change)
        self.assertEqual(reserve_after, self.runner.call_view_method(self.nc_id, 'get_reserves'))

        self.assertEqual(0, self.contract.total_balance_a)
        self.assertEqual(change, self.contract.total_balance_b)

        self.assertEqual((0, change), self.runner.call_view_method(self.nc_id, 'balance_of', ctx.caller_id))
        self.assertBalanceReserve(storage)
