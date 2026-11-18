from math import ceil
from pprint import pprint

from tests.nanocontracts.blueprints.unittest import BlueprintTestCase

from hathor.conf import HathorSettings
from hathor.nanocontracts.blueprints.liquidity_pool import LiquidityPool
from hathor.nanocontracts.exception import NCFail
from hathor.nanocontracts.types import Context, NCAction, NCActionType
from hathor.types import Amount

settings = HathorSettings()


class LiquidityPoolBlueprintTestCase(BlueprintTestCase):
    def setUp(self):
        super().setUp()

        self.nc_id = self.gen_random_nanocontract_id()
        self.runner.register_contract(LiquidityPool, self.nc_id)
        self.nc_storage = self.runner.get_storage(self.nc_id)

        self.token_a = self.gen_random_token_uid()
        self.token_b = self.gen_random_token_uid()
        self.lp_token = self.gen_random_token_uid()

    def _get_any_tx(self):
        return self.get_genesis_tx()

    def _get_any_address(self):
        return self.gen_random_address_with_key()

    def get_current_timestamp(self):
        return int(self.clock.seconds())

    def _initialize_contract(self, reserve_a, reserve_b, fee=0):
        tx = self._get_any_tx()
        actions = [
            NCAction(NCActionType.DEPOSIT, self.token_a, reserve_a),
            NCAction(NCActionType.DEPOSIT, self.token_b, reserve_b),
        ]
        context = Context(actions, tx, self._get_any_address(), timestamp=self.get_current_timestamp())
        self.runner.call_public_method(self.nc_id, 'initialize', context, self.token_a, self.token_b, self.lp_token, fee)

        storage = self.nc_storage
        self.assertEqual(storage.get('token_a'), self.token_a)
        self.assertEqual(storage.get('token_b'), self.token_b)
        self.assertEqual(storage.get('lp_token'), self.lp_token)

    def _prepare_swap_context(self, token_in, amount_in, token_out, amount_out):
        tx = self._get_any_tx()
        actions = [
            NCAction(NCActionType.DEPOSIT, token_in, amount_in),
            NCAction(NCActionType.WITHDRAWAL, token_out, amount_out),
        ]
        return Context(actions, tx, self._get_any_address, timestamp=self.get_current_timestamp())

    def _swap1(self, token_in, amount_in, token_out, amount_out):
        context = self._prepare_swap_context(token_in, amount_in, token_out, amount_out)
        result = self.runner.call_public_method(self.nc_id, 'swap_exact_tokens_for_tokens', context, context.address)
        return result, context

    def test_frontrunning_attack(self) -> None:
        amount_in = 100_000_00
        target_slippage = 0.10
        self._run_attack(amount_in, target_slippage)
        self.assertTrue(False)

        ret = []
        for pre_amount_in in range(1, 2_000_000, 100):
            self.nc_id = self.gen_random_nanocontract_id()
            self.runner.register_contract(LiquidityPool, self.nc_id)
            self.nc_storage = self.runner.get_storage(self.nc_id)

            profit = self._run_attack(amount_in, target_slippage, pre_amount_in=pre_amount_in)
            ret.append((pre_amount_in, profit))
            pre_amount_in += 1
            print()
            print()
            print(ret)
            print()
            print()

            fp = open('profits.txt', 'w')
            fp.writelines(f'{x} {y}\n' for x, y in ret)
            fp.close()

        self.assertTrue(False)

    def _find_attacker_best_amount_in(self, amount_in, amount_out_min, reserve_in, reserve_out):
        target_in = amount_in
        my_in = 1

        # Exponential search.
        while True:
            my_out = self.runner.call_private_method(self.nc_id, 'get_amount_out', my_in, reserve_in, reserve_out)
            target_out = self.runner.call_private_method(self.nc_id, 'get_amount_out', target_in, reserve_in + my_in, reserve_out - my_out)
            if target_out <= amount_out_min:
                break
            my_in *= 2

        # Binary search.
        lo = my_in // 2
        hi = my_in
        while True:
            my_in = (lo + hi) // 2
            my_out = self.runner.call_private_method(self.nc_id, 'get_amount_out', my_in, reserve_in, reserve_out)
            target_out = self.runner.call_private_method(self.nc_id, 'get_amount_out', target_in, reserve_in + my_in, reserve_out - my_out)
            if target_out < amount_out_min:
                hi = my_in
            elif target_out > amount_out_min:
                lo = my_in
            else:
                break

        return my_in

    def _run_attack(self, amount_in: Amount, target_slippage: float, *, pre_amount_in: Amount | None = None) -> Amount:
        #self._initialize_contract(1_000_000, 10_000_000, fee=1)

        # USDT/ETH = ~$2,650
        self._initialize_contract(59_997_152_67, 22_672_96, fee=5)

        fee_numerator = self.nc_storage.get('fee_numerator')
        fee_denominator = self.nc_storage.get('fee_denominator')
        reserve_a = self.nc_storage.get_balance(self.token_a)
        reserve_b = self.nc_storage.get_balance(self.token_b)

        print(f'LP Fees: {fee_numerator}/{fee_denominator} ({100*fee_numerator/fee_denominator:.4f}%)')
        print('Reserves:')
        print(f'  a = {reserve_a:,}')
        print(f'  b = {reserve_b:,}')
        print()

        # Prepare target.
        token_in = self.token_a
        token_out = self.token_b
        reserve_in = reserve_a
        reserve_out = reserve_b
        amount_out_max = self.runner.call_private_method(self.nc_id, 'get_amount_out', amount_in, reserve_in, reserve_out)
        amount_out_min = ceil((1 - target_slippage) * amount_out_max)
        slippage = 1 - amount_out_min / amount_out_max

        print('Target transaction')
        print(f'Amount in: {amount_in/100:,}')
        print(f'Amount out max: {amount_out_max/100:,}')
        print(f'Amount out min: {amount_out_min/100:,}')
        print(f'Slippage: max_amount={amount_out_max - amount_out_min} target={100*target_slippage:.2f}% allowed={100*slippage:.2f}%')
        print()
        print()

        # Preparing attack.
        max_pre_amount_in = self._find_attacker_best_amount_in(amount_in, amount_out_min, reserve_in, reserve_out)
        if pre_amount_in is None:
            pre_amount_in = max_pre_amount_in
        pre_amount_out = 0

        print('Attack swap: Before target')
        r1, context = self._swap1(token_in, pre_amount_in, token_out, pre_amount_out)
        pprint(r1._asdict())
        print()
        print()

        # Target
        print('Target')
        r2, context = self._swap1(token_in, amount_in, token_out, amount_out_min)
        pprint(r2._asdict())
        actual_slippage = 1 - r2.amount_out / amount_out_max
        print()
        print(f'Slippage = {amount_out_max - r2.amount_out} ({100*actual_slippage:.2f}%)')
        print()
        print()

        # Attack: Post-target.
        print('Attack swap: After target')
        r3, context = self._swap1(token_out, r1.amount_out, token_in, 0)
        pprint(r3._asdict())
        print()
        print()

        print('Summary')
        profit = r3.amount_out - pre_amount_in
        profit_percent = r3.amount_out / pre_amount_in - 1
        print(f'Attacker initial balance: {pre_amount_in/100:,}')
        print(f'Attacker final balance: {r3.amount_out/100:,}')
        print(f'Attacker profits: {profit/100:,} ({100*profit_percent:.2f}%)')
        print()

        aprox = r2.amount_in * (1 - 1 / (2 * r1.amount_in / reserve_in + 1))
        print(f'aprox: {aprox/100:,}')

        max_profit = r2.amount_in
        print(f'Efficiency: {100 * profit / max_profit:.2f}% ({profit} out of {max_profit})')

        return profit
