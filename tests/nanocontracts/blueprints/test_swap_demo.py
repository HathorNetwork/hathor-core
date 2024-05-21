from hathor.nanocontracts.blueprints.swap_demo import InvalidActions, InvalidRatio, InvalidTokens, SwapDemo
from hathor.nanocontracts.context import Context
from hathor.nanocontracts.types import NCAction, NCActionType, TokenUid
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class SwapDemoTestCase(BlueprintTestCase):
    def setUp(self):
        super().setUp()

        self.contract_id = self.gen_random_nanocontract_id()
        self.runner.register_contract(SwapDemo, self.contract_id)
        self.nc_storage = self.runner.get_storage(self.contract_id)

        # Test doubles:
        self.token_a = self.gen_random_token_uid()
        self.token_b = self.gen_random_token_uid()
        self.token_c = self.gen_random_token_uid()
        self.address = self.gen_random_address()
        self.tx = self.get_genesis_tx()

    def _initialize(
        self,
        init_token_a: tuple[TokenUid, int, int],
        init_token_b: tuple[TokenUid, int, int]
    ) -> None:
        # Arrange:
        token_a, multiplier_a, amount_a = init_token_a
        token_b, multiplier_b, amount_b = init_token_b
        deposit_a = NCAction(NCActionType.DEPOSIT, token_a, amount_a)
        deposit_b = NCAction(NCActionType.DEPOSIT, token_b, amount_b)
        context = Context(
            actions=[deposit_a, deposit_b],
            vertex=self.tx,
            address=self.address,
            timestamp=self.now
        )

        # Act:
        self.runner.call_public_method(self.contract_id,
                                       'initialize',
                                       context,
                                       token_a,
                                       token_b,
                                       multiplier_a,
                                       multiplier_b)

    def _swap(
        self,
        amount_a: tuple[int, TokenUid],
        amount_b: tuple[int, TokenUid]
    ) -> None:
        # Arrange:
        value_a, token_a = amount_a
        value_b, token_b = amount_b
        swap_a = NCAction(self.get_action_type(value_a), token_a, abs(value_a))
        swap_b = NCAction(self.get_action_type(value_b), token_b, abs(value_b))
        context = Context(
            actions=[swap_a, swap_b],
            vertex=self.tx,
            address=self.address,
            timestamp=self.now
        )

        # Act:
        self.runner.call_public_method(self.contract_id, 'swap', context)

    def test_lifecycle(self) -> None:
        # Create a contract.
        # Arrange and act within:
        self._initialize((self.token_a, 1, 100_00), (self.token_b, 1, 100_00))

        # Assert:
        self.assertEqual(100_00, self.nc_storage.get_balance(self.token_a))
        self.assertEqual(100_00, self.nc_storage.get_balance(self.token_b))
        self.assertEqual(0, self.nc_storage.get('swaps_counter'))

        # Make a valid swap.
        # Arrange and act within:
        self._swap((20_00, self.token_a), (-20_00, self.token_b))
        # Assert:
        self.assertEqual(120_00, self.nc_storage.get_balance(self.token_a))
        self.assertEqual(80_00, self.nc_storage.get_balance(self.token_b))
        self.assertEqual(1, self.nc_storage.get('swaps_counter'))

        # Make multiple invalid swaps raising all possible exceptions.
        with self.assertRaises(InvalidTokens):
            self._swap((-20_00, self.token_a), (20_00, self.token_c))
        with self.assertRaises(InvalidActions):
            self._swap((20_00, self.token_a), (40_00, self.token_b))
        with self.assertRaises(InvalidRatio):
            self._swap((20_00, self.token_a), (-40_00, self.token_b))

    def get_action_type(self, amount: int) -> NCActionType:
        if amount >= 0:
            return NCActionType.DEPOSIT
        else:
            return NCActionType.WITHDRAWAL
