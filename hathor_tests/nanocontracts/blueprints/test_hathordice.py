from hathor import ContractId, NCDepositAction, NCFail, NCWithdrawalAction, TokenUid, VertexId
from hathor.conf import HathorSettings
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathor_tests.nanocontracts.test_blueprints import hathordice

settings = HathorSettings()


class HathorDiceTestCase(BlueprintTestCase):
    nc_seed = b'a' * 32

    def setUp(self):
        super().setUp()

        # import inspect
        # self.blueprint_id = self.register_blueprint_file(inspect.getfile(hathordice))
        self.blueprint_id = self._register_blueprint_class(hathordice.HathorDice)
        self.nc_id = ContractId(VertexId(b'1' * 32))

        self.token_uid = TokenUid(settings.HATHOR_TOKEN_UID)
        self.house_edge_basis_points = 190  # 1.90%
        self.caller_id = self.gen_random_address()

    def initialize_contract(
        self,
        *,
        contract_id: ContractId | None = None,
        max_multiplier_tenths: int | None = None
    ) -> ContractId:
        if contract_id is None:
            contract_id = self.nc_id
        actions = [
            NCDepositAction(token_uid=self.token_uid, amount=1_000_000_00),
        ]
        self.runner.create_contract(
            contract_id,
            self.blueprint_id,
            self.create_context(actions=actions),
            token_uid=self.token_uid,
            house_edge_basis_points=self.house_edge_basis_points,
            max_bet_amount=100_000_00,
            max_multiplier_tenths=max_multiplier_tenths,
            random_bit_length=16,
        )
        return contract_id

    def test_bet(self) -> None:
        self.initialize_contract()
        self.nc_storage = self.runner.get_storage(self.nc_id)

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

    def test_balance_only(self):
        self.initialize_contract()
        self.nc_storage = self.runner.get_storage(self.nc_id)

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
        self.initialize_contract()
        self.nc_storage = self.runner.get_storage(self.nc_id)

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
        self.initialize_contract()
        self.nc_storage = self.runner.get_storage(self.nc_id)

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

    def test_initialize_max_multiplier_tenths_invalid(self) -> None:
        """Test that max_multiplier_tenths validation rejects values <= 10."""
        # Test max_multiplier_tenths = 10 (exactly 1.0x) should fail
        with self.assertRaises(NCFail):
            self.initialize_contract(max_multiplier_tenths=10)

        # Test max_multiplier_tenths = 0 should fail
        with self.assertRaises(NCFail):
            self.initialize_contract(max_multiplier_tenths=0)

        # Test max_multiplier_tenths < 0 should fail
        with self.assertRaises(NCFail):
            self.initialize_contract(max_multiplier_tenths=-1)

    def test_max_multiplier_tenths_enforcement(self) -> None:
        """Test that bets are rejected when multiplier would exceed max_multiplier_tenths."""
        nc_id_limited = self.initialize_contract(
            max_multiplier_tenths=25,  # 2.5x max
        )

        bet_amount = 100

        # Place a bet with a threshold that would produce > 1.1x multiplier
        # With a very low threshold (high payout), multiplier would be very high
        # With threshold = 2**15, multiplier ≈ (2**16 * 0.981) / 2**15 = 1.962 (lose)
        # With threshold = 2**14, multiplier ≈ (2**16 * 0.981) / 2**14 = 3.924 (too high)
        threshold = 2**14  # This should produce multiplier > 1.1x
        actions = [
            NCDepositAction(token_uid=self.token_uid, amount=bet_amount),
        ]
        ctx = self.create_context(actions=actions, caller_id=self.caller_id)
        with self.assertRaises(NCFail):
            self.runner.call_public_method(nc_id_limited, 'place_bet', ctx, bet_amount, threshold)

        # Place a bet with a higher threshold that keeps multiplier within limit
        # With threshold = 2**15, multiplier should be lower but greater than 1.
        threshold = 2**15
        actions = [
            NCDepositAction(token_uid=self.token_uid, amount=bet_amount),
        ]
        ctx = self.create_context(actions=actions, caller_id=self.caller_id)
        payout = self.runner.call_public_method(nc_id_limited, 'place_bet', ctx, bet_amount, threshold)
        assert payout >= 0

    def test_max_multiplier_tenths_none(self) -> None:
        """Test that max_multiplier_tenths=None allows unlimited multipliers."""
        self.initialize_contract()

        # Try placing a bet with very low threshold (high multiplier potential)
        # This should succeed because max_multiplier_tenths=None
        bet_amount = 100_00
        threshold = 100  # Very low threshold = very high multiplier potential
        actions = [
            NCDepositAction(token_uid=self.token_uid, amount=bet_amount),
        ]
        ctx = self.create_context(actions=actions, caller_id=self.caller_id)
        payout = self.runner.call_public_method(self.nc_id, 'place_bet', ctx, bet_amount, threshold)
        # Should succeed (either 0 for loss or payout for win)
        assert payout >= 0

    def test_max_multiplier_tenths_edge_cases(self) -> None:
        """Test edge cases with specific multiplier limits."""
        # Test with max_multiplier_tenths = 15 (1.5x)
        nc_id_15 = self.initialize_contract(
            contract_id=ContractId(VertexId(b'5' * 32)),
            max_multiplier_tenths=15,  # 1.5x max
        )

        # Test with max_multiplier_tenths = 20 (2.0x)
        nc_id_20 = self.initialize_contract(
            contract_id=ContractId(VertexId(b'6' * 32)),
            max_multiplier_tenths=20,  # 2.0x max
        )

        # Test with max_multiplier_tenths = 11 (1.1x) - smallest allowed
        nc_id_11 = self.initialize_contract(
            contract_id=ContractId(VertexId(b'7' * 32)),
            max_multiplier_tenths=11,  # 1.1x max
        )

        # Verify all three contracts exist and are properly initialized
        contract_15 = self.get_readonly_contract(nc_id_15)
        contract_20 = self.get_readonly_contract(nc_id_20)
        contract_11 = self.get_readonly_contract(nc_id_11)

        assert contract_15.max_multiplier_tenths == 15
        assert contract_20.max_multiplier_tenths == 20
        assert contract_11.max_multiplier_tenths == 11

    def test_add_and_remove_liquidity_in_parts(self) -> None:
        """Test adding liquidity and removing it in parts, verifying internal controls."""
        self.initialize_contract()

        # Get initial state (contract is initialized with liquidity from initialization)
        contract = self.get_readonly_contract(self.nc_id)
        initial_total_liquidity = contract.total_liquidity_provided
        initial_available = contract.available_tokens

        # Add liquidity from multiple other providers to create a realistic scenario
        provider_1 = self.gen_random_address()
        provider_2 = self.gen_random_address()

        liquidity_provider_1 = 500_000_00
        actions = [
            NCDepositAction(token_uid=self.token_uid, amount=liquidity_provider_1),
        ]
        ctx = self.create_context(actions=actions, caller_id=provider_1)
        adjusted_1 = self.runner.call_public_method(self.nc_id, 'add_liquidity', ctx)

        liquidity_provider_2 = 750_000_00
        actions = [
            NCDepositAction(token_uid=self.token_uid, amount=liquidity_provider_2),
        ]
        ctx = self.create_context(actions=actions, caller_id=provider_2)
        adjusted_2 = self.runner.call_public_method(self.nc_id, 'add_liquidity', ctx)

        # Verify other providers' liquidity was added
        contract = self.get_readonly_contract(self.nc_id)
        assert contract.liquidity_providers[provider_1] == adjusted_1
        assert contract.liquidity_providers[provider_2] == adjusted_2

        other_providers_total = initial_total_liquidity + adjusted_1 + adjusted_2
        other_providers_available = initial_available + liquidity_provider_1 + liquidity_provider_2

        assert contract.total_liquidity_provided == other_providers_total
        assert contract.available_tokens == other_providers_available

        # Simulate the pool gaining value (e.g., from bets that were lost)
        # This changes the ratio between available_tokens and total_liquidity_provided
        # We'll increase available_tokens by 20% to simulate house winnings
        pool_gain = other_providers_available * 20 // 100
        contract_rw = self.get_readwrite_contract(self.nc_id)
        contract_rw.available_tokens += pool_gain

        # Get the new pool state after simulated gains
        contract = self.get_readonly_contract(self.nc_id)
        pool_after_bets_total = contract.total_liquidity_provided
        pool_after_bets_available = contract.available_tokens

        # Verify liquidity shares didn't change, but available tokens did
        assert pool_after_bets_total == other_providers_total, "Liquidity shares should not change"
        assert pool_after_bets_available == other_providers_available + pool_gain, \
            f"Expected available {other_providers_available + pool_gain}, got {pool_after_bets_available}"

        # Now add liquidity from our test caller after the ratio has changed
        liquidity_to_add = 1_000_000_00
        actions = [
            NCDepositAction(token_uid=self.token_uid, amount=liquidity_to_add),
        ]
        ctx = self.create_context(actions=actions, caller_id=self.caller_id)
        adjusted_amount = self.runner.call_public_method(self.nc_id, 'add_liquidity', ctx)

        # Verify state after adding test caller's liquidity
        contract = self.get_readonly_contract(self.nc_id)
        assert contract.liquidity_providers[self.caller_id] == adjusted_amount
        assert contract.total_liquidity_provided == pool_after_bets_total + adjusted_amount
        assert contract.available_tokens == pool_after_bets_available + liquidity_to_add

        # Calculate how much we can remove - should get a share of the pool gains
        max_removal = self.runner.call_view_method(
            self.nc_id,
            'calculate_address_maximum_liquidity_removal',
            caller_id=self.caller_id
        )

        # Remove liquidity in 3 parts
        removal_1 = max_removal * 30 // 100
        actions = [
            NCWithdrawalAction(token_uid=self.token_uid, amount=removal_1),
        ]
        ctx = self.create_context(actions=actions, caller_id=self.caller_id)
        self.runner.call_public_method(self.nc_id, 'remove_liquidity', ctx)

        # Verify state after first removal - available_tokens should decrease
        contract = self.get_readonly_contract(self.nc_id)
        available_after_1 = contract.available_tokens
        expected_available_1 = pool_after_bets_available + liquidity_to_add - removal_1
        assert abs(available_after_1 - expected_available_1) <= 1, \
            f"Available tokens after removal 1: expected {expected_available_1}, got {available_after_1}"

        max_removal_1 = self.runner.call_view_method(
            self.nc_id,
            'calculate_address_maximum_liquidity_removal',
            caller_id=self.caller_id
        )

        # Remove second part
        removal_2 = max_removal_1 * 50 // 100
        actions = [
            NCWithdrawalAction(token_uid=self.token_uid, amount=removal_2),
        ]
        ctx = self.create_context(actions=actions, caller_id=self.caller_id)
        self.runner.call_public_method(self.nc_id, 'remove_liquidity', ctx)

        # Verify state after second removal
        contract = self.get_readonly_contract(self.nc_id)
        available_after_2 = contract.available_tokens
        expected_available_2 = available_after_1 - removal_2
        assert abs(available_after_2 - expected_available_2) <= 1, \
            f"Available tokens after removal 2: expected {expected_available_2}, got {available_after_2}"

        # Remove all remaining
        max_removal_2 = self.runner.call_view_method(
            self.nc_id,
            'calculate_address_maximum_liquidity_removal',
            caller_id=self.caller_id
        )
        actions = [
            NCWithdrawalAction(token_uid=self.token_uid, amount=max_removal_2),
        ]
        ctx = self.create_context(actions=actions, caller_id=self.caller_id)
        self.runner.call_public_method(self.nc_id, 'remove_liquidity', ctx)

        # Verify final state
        contract = self.get_readonly_contract(self.nc_id)

        # Caller should have zero or near-zero liquidity (within rounding tolerance)
        remaining = contract.liquidity_providers.get(self.caller_id, 0)
        assert abs(remaining) <= 10, f"Caller should have ~0 liquidity, got {remaining}"

        # Available tokens should be back to pool_after_bets_available (within small rounding tolerance)
        assert abs(contract.available_tokens - pool_after_bets_available) <= 2, \
            f"Expected available_tokens ~{pool_after_bets_available}, got {contract.available_tokens}"

        # Total liquidity should be back to pool_after_bets_total (within small rounding tolerance)
        assert abs(contract.total_liquidity_provided - pool_after_bets_total) <= 10, \
            f"Expected total_liquidity ~{pool_after_bets_total}, got {contract.total_liquidity_provided}"

        # Other providers should be unchanged
        assert contract.liquidity_providers[provider_1] == adjusted_1
        assert contract.liquidity_providers[provider_2] == adjusted_2

        # Total removed should approximately equal what we added plus our share of gains
        # With ceiling division for security, we might get slightly less due to rounding
        total_removed = removal_1 + removal_2 + max_removal_2
        # Due to pool gains, we should get close to what we added, possibly slightly more or less
        # The small difference is from rounding (ceiling division protects the pool)
        assert abs(total_removed - liquidity_to_add) <= liquidity_to_add * 1 // 100, \
            f"Total removed {total_removed} should be close to added {liquidity_to_add}"
