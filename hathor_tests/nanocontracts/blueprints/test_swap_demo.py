from hathor.nanocontracts.nc_types import make_nc_type_for_arg_type as make_nc_type
from hathor.nanocontracts.storage.contract_storage import Balance
from hathor.nanocontracts.types import NCDepositAction, NCWithdrawalAction, TokenUid
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathor_tests.nanocontracts.test_blueprints.swap_demo import InvalidActions, InvalidRatio, InvalidTokens, SwapDemo

SWAP_NC_TYPE = make_nc_type(int)


class SwapDemoTestCase(BlueprintTestCase):
    def setUp(self):
        super().setUp()

        self.blueprint_id = self.gen_random_blueprint_id()
        self.contract_id = self.gen_random_contract_id()

        self.nc_catalog.blueprints[self.blueprint_id] = SwapDemo

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
        deposit_a = NCDepositAction(token_uid=token_a, amount=amount_a)
        deposit_b = NCDepositAction(token_uid=token_b, amount=amount_b)
        context = self.create_context(
            actions=[deposit_a, deposit_b],
            vertex=self.tx,
            caller_id=self.address,
            timestamp=self.now
        )

        # Act:
        self.runner.create_contract(
            self.contract_id,
            self.blueprint_id,
            context,
            token_a,
            token_b,
            multiplier_a,
            multiplier_b,
        )
        self.nc_storage = self.runner.get_storage(self.contract_id)

    def _swap(
        self,
        amount_a: tuple[int, TokenUid],
        amount_b: tuple[int, TokenUid]
    ) -> None:
        # Arrange:
        value_a, token_a = amount_a
        value_b, token_b = amount_b
        action_a_type = self.get_action_type(value_a)
        action_b_type = self.get_action_type(value_b)
        swap_a = action_a_type(token_uid=token_a, amount=abs(value_a))
        swap_b = action_b_type(token_uid=token_b, amount=abs(value_b))
        context = self.create_context(
            actions=[swap_a, swap_b],
            vertex=self.tx,
            caller_id=self.address,
            timestamp=self.now
        )

        # Act:
        self.runner.call_public_method(self.contract_id, 'swap', context)

    def test_lifecycle(self) -> None:
        # Create a contract.
        # Arrange and act within:
        self._initialize((self.token_a, 1, 100_00), (self.token_b, 1, 100_00))

        # Assert:
        self.assertEqual(
            Balance(value=100_00, can_mint=False, can_melt=False), self.nc_storage.get_balance(self.token_a)
        )
        self.assertEqual(
            Balance(value=100_00, can_mint=False, can_melt=False), self.nc_storage.get_balance(self.token_b)
        )
        self.assertEqual(0, self.nc_storage.get_obj(b'swaps_counter', SWAP_NC_TYPE))

        # Make a valid swap.
        # Arrange and act within:
        self._swap((20_00, self.token_a), (-20_00, self.token_b))
        # Assert:
        self.assertEqual(
            Balance(value=120_00, can_mint=False, can_melt=False), self.nc_storage.get_balance(self.token_a)
        )
        self.assertEqual(
            Balance(value=80_00, can_mint=False, can_melt=False), self.nc_storage.get_balance(self.token_b)
        )
        self.assertEqual(1, self.nc_storage.get_obj(b'swaps_counter', SWAP_NC_TYPE))

        # Make multiple invalid swaps raising all possible exceptions.
        with self.assertRaises(InvalidTokens):
            self._swap((-20_00, self.token_a), (20_00, self.token_c))
        with self.assertRaises(InvalidActions):
            self._swap((20_00, self.token_a), (40_00, self.token_b))
        with self.assertRaises(InvalidRatio):
            self._swap((20_00, self.token_a), (-40_00, self.token_b))

    def get_action_type(self, amount: int) -> type[NCDepositAction] | type[NCWithdrawalAction]:
        if amount >= 0:
            return NCDepositAction
        else:
            return NCWithdrawalAction
