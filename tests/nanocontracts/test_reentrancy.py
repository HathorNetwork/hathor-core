from hathor.nanocontracts import Blueprint, Context, NCFail, public
from hathor.nanocontracts.types import Amount, ContractId, NCAction, NCDepositAction, TokenUid
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase

HTR_TOKEN_UID = TokenUid(b'\0')


class InsufficientBalance(NCFail):
    pass


class MyBlueprint(Blueprint):
    # I used dict[bytes, int] for two reasons:
    # 1. `bytes` works for both Address and ContractId
    # 2. int allows negative values
    balances: dict[bytes, int]

    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public(allow_deposit=True)
    def deposit(self, ctx: Context) -> None:
        address = ctx.address
        action = ctx.get_single_action(HTR_TOKEN_UID)
        assert isinstance(action, NCDepositAction)
        amount = action.amount

        if address not in self.balances:
            self.balances[address] = amount
        else:
            self.balances[address] += amount

    @public
    def transfer_to(self, ctx: Context, amount: Amount, contract: ContractId, method: str) -> None:
        address = ctx.address
        if amount > self.balances.get(address, 0):
            raise InsufficientBalance('insufficient balance')

        actions: list[NCAction] = [NCDepositAction(token_uid=HTR_TOKEN_UID, amount=amount)]
        # This contract is vulnerable to reentrancy attack because it is transfering before reducing the balance.
        # Another issue is that it doesn't assert self.balances[address] >= 0.
        self.syscall.call_public_method(contract, method, actions=actions)
        self.balances[address] -= amount

    @public
    def fixed_transfer_to(self, ctx: Context, amount: Amount, contract: ContractId, method: str) -> None:
        address = ctx.address
        if amount > self.balances.get(address, 0):
            raise InsufficientBalance('insufficient balance')

        actions: list[NCAction] = [NCDepositAction(token_uid=HTR_TOKEN_UID, amount=amount)]
        # This contract is not vulnerable to reentrancy attack. The only difference relies on the moment the balance is
        # updated.
        self.balances[address] -= amount
        self.syscall.call_public_method(contract, method, actions=actions)


class AttackerBlueprint(Blueprint):
    target: ContractId
    amount: Amount
    n_calls: int
    counter: int

    @public(allow_deposit=True)
    def initialize(self, ctx: Context, target: ContractId, n_calls: int) -> None:
        self.target = target
        self.n_calls = n_calls
        self.counter = 0

        action = ctx.get_single_action(HTR_TOKEN_UID)
        assert isinstance(action, NCDepositAction)
        self.amount = Amount(action.amount)

        actions: list[NCAction] = [NCDepositAction(token_uid=HTR_TOKEN_UID, amount=self.amount)]
        self.syscall.call_public_method(target, 'deposit', actions=actions)

    @public(allow_deposit=True)
    def nop(self, ctx: Context) -> None:
        pass

    @public(allow_deposit=True)
    def attack(self, ctx: Context) -> None:
        self._run_attack('transfer_to')

    @public(allow_deposit=True)
    def attack_fail(self, ctx: Context) -> None:
        self._run_attack('fixed_transfer_to')

    def _run_attack(self, method: str) -> None:
        if self.counter >= self.n_calls:
            return

        self.counter += 1
        self.syscall.call_public_method(
            self.target,
            method,
            actions=[],
            amount=self.amount,
            contract=self.syscall.get_contract_id(),
            method='attack',
        )


class NCReentrancyTestCase(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.target_blueprint_id = self.gen_random_blueprint_id()
        self.attacker_blueprint_id = self.gen_random_blueprint_id()

        self.nc_catalog.blueprints[self.target_blueprint_id] = MyBlueprint
        self.nc_catalog.blueprints[self.attacker_blueprint_id] = AttackerBlueprint

        self.nc_target_id = self.gen_random_contract_id()
        self.nc_attacker_id = self.gen_random_contract_id()

        tx = self.get_genesis_tx()

        self.address1 = self.gen_random_address()
        self.address2 = self.gen_random_address()

        ctx = Context([], tx, self.address1, timestamp=0)
        self.runner.create_contract(self.nc_target_id, self.target_blueprint_id, ctx)

        self.n_calls = 15
        ctx = Context([NCDepositAction(token_uid=HTR_TOKEN_UID, amount=50)], tx, self.address2, timestamp=0)
        self.runner.create_contract(
            self.nc_attacker_id,
            self.attacker_blueprint_id,
            ctx,
            target=self.nc_target_id,
            n_calls=self.n_calls,
        )

        # Address1 deposits 1.00 HTR
        actions: list[NCAction] = [NCDepositAction(token_uid=HTR_TOKEN_UID, amount=1_00)]
        ctx = Context(actions, tx, self.address1, timestamp=0)
        self.runner.call_public_method(self.nc_target_id, 'deposit', ctx)

        # Address2 deposits 100.00 HTR
        actions = [NCDepositAction(token_uid=HTR_TOKEN_UID, amount=100_00)]
        ctx = Context(actions, tx, self.address2, timestamp=0)
        self.runner.call_public_method(self.nc_target_id, 'deposit', ctx)

        self.target_storage = self.runner.get_storage(self.nc_target_id)
        self.attacker_storage = self.runner.get_storage(self.nc_attacker_id)

        assert self.target_storage.get_balance(HTR_TOKEN_UID).value == 10_150
        assert self.attacker_storage.get_balance(HTR_TOKEN_UID).value == 0

    def test_basics(self) -> None:
        tx = self.get_genesis_tx()

        # Address1 sends 0.30 HTR to attacker contract.
        ctx = Context([], tx, self.address1, timestamp=0)
        self.runner.call_public_method(
            self.nc_target_id,
            'transfer_to',
            ctx,
            amount=30,
            contract=self.nc_attacker_id,
            method='nop',
        )

        assert self.target_storage.get_balance(HTR_TOKEN_UID).value == 10_150 - 30
        assert self.attacker_storage.get_balance(HTR_TOKEN_UID).value == 0 + 30

        # Address1 tries to send 0.80 HTR but it fails due to insufficient balance.
        # This misleads developers into thinking the safety mechanism is working.
        with self.assertRaises(InsufficientBalance):
            ctx = Context([], tx, self.address1, timestamp=0)
            self.runner.call_public_method(
                self.nc_target_id,
                'transfer_to',
                ctx,
                amount=80,
                contract=self.nc_attacker_id,
                method='nop',
            )

        assert self.target_storage.get_balance(HTR_TOKEN_UID).value == 10_150 - 30
        assert self.attacker_storage.get_balance(HTR_TOKEN_UID).value == 0 + 30

    def test_attack_succeed(self) -> None:
        tx = self.get_genesis_tx()

        # Attacker contract has a balance of 0.50 HTR in the target contract.
        # It tries to extract more than 0.50 HTR and succeeds.
        ctx = Context([], tx, self.address1, timestamp=0)
        self.runner.call_public_method(
            self.nc_attacker_id,
            'attack',
            ctx,
        )

        assert self.target_storage.get_balance(HTR_TOKEN_UID).value == 10_150 - self.n_calls * 50
        assert self.attacker_storage.get_balance(HTR_TOKEN_UID).value == self.n_calls * 50

    def test_attack_fail(self) -> None:
        tx = self.get_genesis_tx()

        # Attacker contract has a balance of 0.50 HTR in the target contract.
        # It tries to extract more than 0.50 HTR and fails.
        with self.assertRaises(InsufficientBalance):
            ctx = Context([], tx, self.address1, timestamp=0)
            self.runner.call_public_method(
                self.nc_attacker_id,
                'attack_fail',
                ctx,
            )

        assert self.target_storage.get_balance(HTR_TOKEN_UID).value == 10_150
        assert self.attacker_storage.get_balance(HTR_TOKEN_UID).value == 0
