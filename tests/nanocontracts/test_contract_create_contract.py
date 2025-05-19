from typing import Optional

from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.storage.contract_storage import Balance
from hathor.nanocontracts.types import (
    BlueprintId,
    ContractId,
    NCAction,
    NCDepositAction,
    TokenUid,
    VertexId,
    is_action_type,
)
from hathor.nanocontracts.utils import derive_child_contract_id
from tests.dag_builder.builder import TestDAGBuilder
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase

HTR_TOKEN_UID = TokenUid(b'\0')


class MyBlueprint1(Blueprint):
    counter: int
    contract: Optional[ContractId]

    @public
    def initialize(self, ctx: Context, blueprint_id: BlueprintId, initial: int) -> None:
        if initial > 0:
            token_uid = TokenUid(HTR_TOKEN_UID)
            action = ctx.get_single_action(token_uid)
            salt = b'x'
            assert is_action_type(action, NCDepositAction)
            new_actions: list[NCAction] = [NCDepositAction(token_uid=token_uid, amount=action.amount - initial)]
            self.contract, _ = self.syscall.create_contract(blueprint_id, salt, new_actions, blueprint_id, initial - 1)
        else:
            self.contract = None
        self.counter = initial

    @public
    def create_children(self, ctx: Context, blueprint_id: BlueprintId, salt: bytes) -> None:
        new_actions: list[NCAction] = []
        self.syscall.create_contract(blueprint_id, salt + b'1', new_actions, blueprint_id, 0)
        self.syscall.create_contract(blueprint_id, salt + b'2', new_actions, blueprint_id, 0)
        self.syscall.create_contract(blueprint_id, salt + b'3', new_actions, blueprint_id, 0)

    @public
    def nop(self, ctx: Context) -> None:
        pass


class MyBlueprint2(Blueprint):
    counter: int

    @public
    def initialize(self, ctx: Context, blueprint_id: BlueprintId, initial: int) -> None:
        self.counter = initial


class NCBlueprintTestCase(BlueprintTestCase):
    def setUp(self):
        super().setUp()
        self.blueprint1_id = self.gen_random_blueprint_id()
        self.blueprint2_id = self.gen_random_blueprint_id()
        self.register_blueprint_class(self.blueprint1_id, MyBlueprint1)
        self.register_blueprint_class(self.blueprint2_id, MyBlueprint2)

    def test_basic(self) -> None:
        counter = 5
        nc1_id = ContractId(VertexId(b'1' * 32))

        token_uid = HTR_TOKEN_UID
        deposit = 100
        actions: list[NCAction] = [NCDepositAction(token_uid=token_uid, amount=deposit)]
        address = self.gen_random_address()
        ctx = Context(actions, self.get_genesis_tx(), address, timestamp=0)
        self.runner.create_contract(nc1_id, self.blueprint1_id, ctx, self.blueprint1_id, counter)

        nc_id = nc1_id
        expected = counter
        remainder = deposit
        while True:
            nc_storage = self.runner.get_storage(nc_id)
            counter = nc_storage.get('counter')
            assert counter == expected
            new_nc_id = nc_storage.get('contract')
            balance = nc_storage.get_balance(token_uid)
            if new_nc_id is not None:
                expected_nc_id = derive_child_contract_id(nc_id, b'x', self.blueprint1_id)
                assert new_nc_id == expected_nc_id
                assert balance == Balance(value=expected, can_mint=False, can_melt=False)
                remainder -= balance.value
            else:
                assert balance.value == remainder
                break
            nc_id = new_nc_id
            expected -= 1

        actions = []
        ctx = Context(actions, self.get_genesis_tx(), address, timestamp=0)
        salt = b'123'
        self.runner.call_public_method(nc1_id, 'create_children', ctx, self.blueprint1_id, salt)
        child1_id = derive_child_contract_id(nc1_id, salt + b'1', self.blueprint1_id)
        child2_id = derive_child_contract_id(nc1_id, salt + b'2', self.blueprint1_id)
        child3_id = derive_child_contract_id(nc1_id, salt + b'3', self.blueprint1_id)
        child4_id = derive_child_contract_id(nc1_id, salt + b'4', self.blueprint1_id)

        assert self.runner.has_contract_been_initialized(child1_id)
        assert self.runner.has_contract_been_initialized(child2_id)
        assert self.runner.has_contract_been_initialized(child3_id)
        assert not self.runner.has_contract_been_initialized(child4_id)

        salt = b'456'
        self.runner.call_public_method(child1_id, 'create_children', ctx, self.blueprint1_id, salt)
        child1_child1_id = derive_child_contract_id(child1_id, salt + b'1', self.blueprint1_id)
        assert self.runner.has_contract_been_initialized(child1_child1_id)

    def test_dag_basic(self) -> None:
        salt1 = b'x'
        salt2 = b'1'
        salt21 = salt2 + b'1'

        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..34]
            blockchain b30 c[31..50]
            b34 < c31
            b30 < dummy

            c31.weight = 6

            nc1.nc_id = "{self.blueprint1_id.hex()}"
            nc1.nc_method = initialize("{self.blueprint1_id.hex()}", 1)
            nc1.nc_deposit = 10 HTR

            nc2.nc_id = nc1
            nc2.nc_method = create_children("{self.blueprint2_id.hex()}", "{salt1.hex()}")

            nc3.nc_id = child_contract(nc1, "{salt1.hex()}", "{self.blueprint1_id.hex()}")
            nc3.nc_method = create_children("{self.blueprint1_id.hex()}", "{salt2.hex()}")

            nc4.nc_id = child_contract(nc3.nc_id, "{salt21.hex()}", "{self.blueprint1_id.hex()}")
            nc4.nc_method = nop()

            nc1 <-- b31
            b31 < nc2
            nc2 <-- b32
            b32 < nc3
            nc3 <-- b33
            b33 < nc4
            nc4 <-- b34
        ''')

        artifacts.propagate_with(self.manager, up_to='b34')

        nc1 = artifacts.by_name['nc1'].vertex
        nc2 = artifacts.by_name['nc2'].vertex
        nc3 = artifacts.by_name['nc3'].vertex
        nc4 = artifacts.by_name['nc4'].vertex

        assert nc1.get_metadata().voided_by is None
        assert nc2.get_metadata().voided_by is None
        assert nc3.get_metadata().voided_by is None
        assert nc4.get_metadata().voided_by is None

        nc1_contract_id = ContractId(VertexId(nc1.hash))

        contracts = []
        # nc1
        contracts.append(nc1.hash)
        contracts.append(derive_child_contract_id(nc1_contract_id, salt1, self.blueprint1_id))
        # nc2
        contracts.append(derive_child_contract_id(nc1_contract_id, salt1 + b'1', self.blueprint2_id))
        contracts.append(derive_child_contract_id(nc1_contract_id, salt1 + b'2', self.blueprint2_id))
        contracts.append(derive_child_contract_id(nc1_contract_id, salt1 + b'3', self.blueprint2_id))
        # nc3
        nc1_child1_contract_id = ContractId(VertexId(contracts[1]))
        contracts.append(derive_child_contract_id(nc1_child1_contract_id, salt2 + b'1', self.blueprint1_id))
        contracts.append(derive_child_contract_id(nc1_child1_contract_id, salt2 + b'2', self.blueprint1_id))
        contracts.append(derive_child_contract_id(nc1_child1_contract_id, salt2 + b'3', self.blueprint1_id))
        # nc4
        # (empty)

        # Confirm that contract ids are different.
        assert len(set(contracts)) == len(contracts)

        runner = self.manager.get_best_block_nc_runner()
        for idx, nc_id in enumerate(contracts):
            assert runner.has_contract_been_initialized(nc_id), f'index={idx}'

        indexes = self.manager.tx_storage.indexes

        # blueprint_history: blueprint1
        result = set(indexes.blueprint_history.get_newest(self.blueprint1_id))
        expected = {nc1.hash, nc3.hash}
        assert result == expected

        # blueprint_history: blueprint2
        result = set(indexes.blueprint_history.get_newest(self.blueprint2_id))
        expected = {nc2.hash}
        assert result == expected

        # nc_creation
        result = set(indexes.nc_creation.get_newest())
        expected = {nc1.hash, nc2.hash, nc3.hash}
        assert result == expected

        # nc_history
        expected_list = [
            {nc1.hash, nc2.hash},
            {nc1.hash, nc3.hash},
            {nc2.hash},
            {nc2.hash},
            {nc2.hash},
            {nc3.hash, nc4.hash},
            {nc3.hash},
            {nc3.hash},
        ]
        assert len(contracts) == len(expected_list)
        match_list = []
        for nc_id, expected in zip(contracts, expected_list):
            result = set(indexes.nc_history.get_newest(nc_id))
            match_list.append(result == expected)
        assert all(match_list)

        # Reorg!
        artifacts.propagate_with(self.manager)

        runner = self.manager.get_best_block_nc_runner()
        for nc_id in contracts:
            assert not runner.has_contract_been_initialized(nc_id)

        # blueprint_history: blueprint1
        result = set(indexes.blueprint_history.get_newest(self.blueprint1_id))
        assert result == set([nc1.hash])

        # blueprint_history: blueprint2
        result = set(indexes.blueprint_history.get_newest(self.blueprint2_id))
        assert result == set()

        # nc_creation
        result = set(indexes.nc_creation.get_newest())
        assert result == set([nc1.hash])

        # nc_history
        expected_list = [
            {nc1.hash, nc2.hash},
            {nc3.hash},
            set(),
            set(),
            set(),
            {nc4.hash},
            set(),
            set(),
        ]
        assert len(contracts) == len(expected_list)
        match_list = []
        for nc_id, expected in zip(contracts, expected_list):
            result = set(indexes.nc_history.get_newest(nc_id))
            match_list.append(result == expected)
        assert all(match_list)

        # TODO Clean-up mempool after reorg?
