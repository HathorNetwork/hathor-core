import inspect

from hathor import ContractId, NCDepositAction, NCFail, NCWithdrawalAction, TokenUid, VertexId
from hathor.conf import HathorSettings
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from tests.nanocontracts.test_blueprints import hathordice

settings = HathorSettings()


class HathorDiceTestCase(BlueprintTestCase):
    nc_seed = b'a' * 32

    def setUp(self):
        super().setUp()

        self.blueprint_id = self.register_blueprint_file(inspect.getfile(hathordice))
        self.nc_id = ContractId(VertexId(b'1' * 32))

        self.token_uid = TokenUid(settings.HATHOR_TOKEN_UID)
        self.house_edge_basis_points = 190  # 1.90%
        self.caller_id = self.gen_random_address()

        self.initialize_contract()
        self.nc_storage = self.runner.get_storage(self.nc_id)

    def initialize_contract(self) -> None:
        actions = [
            NCDepositAction(token_uid=self.token_uid, amount=1_000_000_00),
        ]
        self.runner.create_contract(
            self.nc_id,
            self.blueprint_id,
            self.create_context(actions=actions),
            token_uid=self.token_uid,
            house_edge_basis_points=self.house_edge_basis_points,
            max_bet_amount=100_000_00,
            random_bit_length=16,
        )

    def test_bet(self) -> None:
        bet_amount = 100_00
        threshold = 10_000

        liquidity_provider_1 = 1_000_00
        actions = [
            NCDepositAction(token_uid=self.token_uid, amount=liquidity_provider_1),
        ]
        ctx = self.create_context(actions=actions, caller_id=self.caller_id)
        self.runner.call_public_method(self.nc_id, 'add_liquidity', ctx)

        contract = self.get_readonly_contract(self.nc_id)
        payouts = []
        wins = 0
        loses = 0
        for _ in range(2_000):
            actions = [
                NCDepositAction(token_uid=self.token_uid, amount=bet_amount),
            ]
            ctx = self.create_context(actions=actions, caller_id=self.caller_id)
            payout = self.runner.call_public_method(self.nc_id, 'place_bet', ctx, bet_amount, threshold)
            payouts.append(payout)

            if payout > 0:
                wins += 1
            else:
                loses += 1

        total_bet_amount = len(payouts) * bet_amount
        total_payouts = sum(payouts)

        assert total_payouts == contract.balances[self.caller_id]

        # print(payouts)
        print(f'wins: {wins}')
        print(f'loses: {loses}')
        print(f'total bet amount: {total_bet_amount:,}')
        print(f'total payouts: {total_payouts:,}')
        print()

        actions = [
            NCWithdrawalAction(token_uid=self.token_uid, amount=total_payouts),
        ]
        ctx = self.create_context(actions=actions, caller_id=self.caller_id)
        self.runner.call_public_method(self.nc_id, 'claim_balance', ctx)

        actions = [
            NCWithdrawalAction(token_uid=self.token_uid, amount=1),
        ]
        ctx = self.create_context(actions=actions, caller_id=self.caller_id)
        with self.assertRaises(NCFail):
            self.runner.call_public_method(self.nc_id, 'claim_balance', ctx)

        assert 0 == contract.balances[self.caller_id]

        amount = 100_00
        ret = self.runner.call_view_method(self.nc_id, 'calculate_maximum_liquidity_removal', amount=100_00)
        roi = ret / amount - 1
        print(f'amount: {amount}')
        print(f'ret: {ret}')
        print(f'roi: {100 * roi:.2f}%')
        print()

        # ---

        lp_2_amount = 200_00
        actions = [
            NCDepositAction(token_uid=self.token_uid, amount=lp_2_amount),
        ]
        ctx = self.create_context(actions=actions, caller_id=self.caller_id)
        lp_2_adjusted_amount = self.runner.call_public_method(self.nc_id, 'add_liquidity', ctx)
        lp_2_maximum_removal = self.runner.call_view_method(self.nc_id, 'calculate_maximum_liquidity_removal',
                                                            lp_2_adjusted_amount)

        assert abs(lp_2_amount - lp_2_maximum_removal) <= 2

        # ---

        lp_1_withdrawal = self.runner.call_view_method(
            self.nc_id,
            'calculate_maximum_liquidity_removal',
            amount=liquidity_provider_1,
        )
        actions = [
            NCWithdrawalAction(token_uid=self.token_uid, amount=lp_1_withdrawal),
        ]
        ctx = self.create_context(actions=actions, caller_id=self.caller_id)
        self.runner.call_public_method(self.nc_id, 'remove_liquidity', ctx)

        assert False

    def test_balance_only(self):
        bet_amount = 100_00
        threshold = 10_000

        wins = 0
        loses = 0
        for _ in range(100):
            contract = self.get_readwrite_contract(self.nc_id)
            contract.balances[self.caller_id] = bet_amount

            ctx = self.create_context(caller_id=self.caller_id)
            payout = self.runner.call_public_method(self.nc_id, 'place_bet', ctx, bet_amount, threshold)

            if payout > 0:
                # win!
                assert contract.balances[self.caller_id] == payout
                wins += 1
            else:
                # lose!
                assert contract.balances[self.caller_id] == 0
                loses += 1

        assert wins > 0
        assert loses > 0

    def test_partial_balance_and_deposit(self):
        bet_amount = 100_00
        threshold = 10_000

        wins = 0
        loses = 0
        for _ in range(100):
            contract = self.get_readwrite_contract(self.nc_id)
            contract.balances[self.caller_id] = bet_amount

            deposit_amount = bet_amount // 3
            balance_amount = bet_amount - deposit_amount
            assert balance_amount > 0

            actions = [
                NCDepositAction(token_uid=self.token_uid, amount=deposit_amount),
            ]
            ctx = self.create_context(actions=actions, caller_id=self.caller_id)
            payout = self.runner.call_public_method(self.nc_id, 'place_bet', ctx, bet_amount, threshold)

            if payout > 0:
                # win!
                assert contract.balances[self.caller_id] == bet_amount - balance_amount + payout
                wins += 1
            else:
                # lose!
                assert contract.balances[self.caller_id] == bet_amount - balance_amount
                loses += 1

        assert wins > 0
        assert loses > 0

    def test_large_deposit(self):
        bet_amount = 100_00
        threshold = 10_000
        initial_balance = 54

        wins = 0
        loses = 0
        for _ in range(100):
            contract = self.get_readwrite_contract(self.nc_id)
            contract.balances[self.caller_id] = initial_balance

            deposit_amount = 10 * bet_amount

            actions = [
                NCDepositAction(token_uid=self.token_uid, amount=deposit_amount),
            ]
            ctx = self.create_context(actions=actions, caller_id=self.caller_id)
            payout = self.runner.call_public_method(self.nc_id, 'place_bet', ctx, bet_amount, threshold)

            if payout > 0:
                # win!
                assert contract.balances[self.caller_id] == initial_balance + deposit_amount - bet_amount + payout
                wins += 1
            else:
                # lose!
                assert contract.balances[self.caller_id] == initial_balance + deposit_amount - bet_amount
                loses += 1

        assert wins > 0
        assert loses > 0
