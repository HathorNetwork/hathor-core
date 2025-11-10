from typing import Optional

from hathor.nanocontracts import HATHOR_TOKEN_UID, Blueprint, Context, public
from hathor.nanocontracts.nc_types import NCType, make_nc_type_for_arg_type as make_nc_type
from hathor.nanocontracts.storage.contract_storage import Balance
from hathor.nanocontracts.types import (
    BlueprintId,
    ContractId,
    NCActionType,
    NCDepositAction,
    NCGrantAuthorityAction,
    NCWithdrawalAction,
    TokenUid,
    VertexId,
)
from hathor.nanocontracts.utils import derive_child_contract_id
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.headers.nano_header import NanoHeaderAction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase

INT_NC_TYPE = make_nc_type(int)
CONTRACT_NC_TYPE: NCType[ContractId | None] = make_nc_type(ContractId | None)  # type: ignore[arg-type]


class MyBlueprint1(Blueprint):
    counter: int
    contract: Optional[ContractId]
    token_uid: Optional[TokenUid]

    @public(allow_deposit=True, allow_grant_authority=True)
    def initialize(self, ctx: Context, blueprint_id: BlueprintId, initial: int, token_uid: Optional[TokenUid]) -> None:
        self.token_uid = token_uid
        if initial > 0:
            token_uid = TokenUid(HATHOR_TOKEN_UID)
            action = ctx.get_single_action(token_uid)
            salt = b'x'
            assert isinstance(action, NCDepositAction)
            new_action = NCDepositAction(token_uid=token_uid, amount=action.amount - initial)
            self.contract, _ = self.syscall.setup_new_contract(blueprint_id, new_action, salt=salt) \
                .initialize(blueprint_id, initial - 1, self.token_uid)
        else:
            self.contract = None
        self.counter = initial

    @public
    def create_children(self, ctx: Context, blueprint_id: BlueprintId, salt: bytes) -> None:
        new_actions = []
        if self.token_uid and self.syscall.can_mint(self.token_uid):
            new_actions.append(NCGrantAuthorityAction(token_uid=self.token_uid, mint=True, melt=True))

        self.syscall.setup_new_contract(blueprint_id, *new_actions, salt=salt + b'1') \
            .initialize(blueprint_id, 0, self.token_uid)

        self.syscall.setup_new_contract(blueprint_id, *new_actions, salt=salt + b'2') \
            .initialize(blueprint_id, 0, self.token_uid)

        self.syscall.setup_new_contract(blueprint_id, *new_actions, salt=salt + b'3') \
            .initialize(blueprint_id, 0, self.token_uid)

    @public
    def nop(self, ctx: Context) -> None:
        pass

    @public(allow_deposit=True)
    def mint(self, ctx: Context, amount: int) -> None:
        assert self.token_uid is not None
        self.syscall.mint_tokens(self.token_uid, amount)

    @public(allow_withdrawal=True)
    def withdraw(self, ctx: Context) -> None:
        pass


class MyBlueprint2(Blueprint):
    counter: int
    token_uid: Optional[TokenUid]

    @public(allow_grant_authority=True)
    def initialize(self, ctx: Context, blueprint_id: BlueprintId, initial: int, token_uid: Optional[TokenUid]) -> None:
        self.counter = initial
        self.token_uid = token_uid

    @public
    def melt(self, ctx: Context, amount: int, contract_id: ContractId) -> None:
        assert self.token_uid is not None
        action = NCWithdrawalAction(token_uid=self.token_uid, amount=amount)
        self.syscall.get_contract(contract_id, blueprint_id=None).public(action).withdraw()
        self.syscall.melt_tokens(self.token_uid, amount)


class NCBlueprintTestCase(BlueprintTestCase):
    def setUp(self):
        super().setUp()
        self.blueprint1_id = self._register_blueprint_class(MyBlueprint1)
        self.blueprint2_id = self._register_blueprint_class(MyBlueprint2)

    def test_basic(self) -> None:
        counter = 5
        nc1_id = ContractId(VertexId(b'1' * 32))

        token_uid = TokenUid(HATHOR_TOKEN_UID)
        deposit = 100
        actions = [NCDepositAction(token_uid=token_uid, amount=deposit)]
        address = self.gen_random_address()
        ctx = self.create_context(actions, caller_id=address)
        self.runner.create_contract(nc1_id, self.blueprint1_id, ctx, self.blueprint1_id, counter, None)

        nc_id = nc1_id
        expected = counter
        remainder = deposit
        while True:
            nc_storage = self.runner.get_storage(nc_id)
            counter = nc_storage.get_obj(b'counter', INT_NC_TYPE)
            assert counter == expected
            new_nc_id = nc_storage.get_obj(b'contract', CONTRACT_NC_TYPE)
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
        ctx = self.create_context(actions, self.get_genesis_tx(), address)
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
        salt11 = salt1 + b'1'
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
            nc1.nc_method = initialize("{self.blueprint1_id.hex()}", 1, `TKA`)
            nc1.nc_deposit = 10 HTR
            nc1.out[0] = 200 TKA

            nc2.nc_id = nc1
            nc2.nc_method = create_children("{self.blueprint2_id.hex()}", "{salt1.hex()}")

            nc3.nc_id = child_contract(nc1, "{salt1.hex()}", "{self.blueprint1_id.hex()}")
            nc3.nc_method = create_children("{self.blueprint1_id.hex()}", "{salt2.hex()}")

            nc4.nc_id = nc1
            nc4.nc_method = mint(456)
            nc4.nc_deposit = 5 HTR

            nc5.nc_id = child_contract(nc3.nc_id, "{salt21.hex()}", "{self.blueprint1_id.hex()}")
            nc5.nc_method = nop()

            nc6.nc_id = child_contract(nc2.nc_id, "{salt11.hex()}", "{self.blueprint2_id.hex()}")
            nc6.nc_method = melt(123, `nc1`)

            nc1 <-- b31
            b31 < nc2
            nc2 <-- b32
            b32 < nc3
            nc3 <-- nc4 <-- b33
            b33 < nc5
            nc5 <-- nc6 <-- b34
        ''')

        nc1, nc2, nc3, nc4, nc5, nc6 = artifacts.get_typed_vertices(
            ['nc1', 'nc2', 'nc3', 'nc4', 'nc5', 'nc6'],
            Transaction,
        )
        tka = artifacts.get_typed_vertex('TKA', TokenCreationTransaction)

        # TODO: The DAGBuilder currently doesn't support authority inputs/outputs,
        #  and neither authority actions, so we have to set them manually. Improve this.
        nc1.inputs.append(TxInput(tx_id=tka.hash, index=len(tka.outputs) - 1, data=b''))  # melt authority
        nc1.inputs.append(TxInput(tx_id=tka.hash, index=len(tka.outputs) - 2, data=b''))  # mint authority
        dag_builder._exporter.sign_all_inputs(nc1)
        nc1_header = nc1.get_nano_header()
        assert len(nc1_header.nc_actions) == 1
        grant_action = NanoHeaderAction(
            type=NCActionType.GRANT_AUTHORITY,
            token_index=1,
            amount=TxOutput.ALL_AUTHORITIES,
        )
        nc1_header.nc_actions.append(grant_action)
        # XXX: Dirty hack, by purposefully not clearing the cache, we don't have to re-sign the nano header.
        # nc1.clear_sighash_cache()

        artifacts.propagate_with(self.manager, up_to='b34')

        assert nc1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert nc1.get_metadata().voided_by is None

        assert nc2.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert nc2.get_metadata().voided_by is None

        assert nc3.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert nc3.get_metadata().voided_by is None

        assert nc4.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert nc4.get_metadata().voided_by is None

        assert nc5.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert nc5.get_metadata().voided_by is None

        assert nc6.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert nc6.get_metadata().voided_by is None

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
        # nc4, nc5, nc6
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

        # tokens
        htr_total = indexes.tokens.get_token_info(HATHOR_TOKEN_UID).get_total()
        tka_total = indexes.tokens.get_token_info(tka.hash).get_total()
        assert self.manager.tx_storage.get_height_best_block() == 34
        # genesis
        # +34 blocks
        # -2 from the TKA mint in nc1.out[0]
        # -5 from the mint in nc5.nc_method
        # +1 from the melt in nc6.nc_method
        assert htr_total == self._settings.GENESIS_TOKENS + 34 * self._settings.INITIAL_TOKENS_PER_BLOCK - 2 - 5 + 1
        # 200 from nc1.out[0]
        # +456 from nc5.nc_method
        # -123 from nc6.nc_method
        assert tka_total == 200 + 456 - 123

        # nc_history
        expected_list = [
            {nc1.hash, nc2.hash, nc4.hash, nc6.hash},
            {nc1.hash, nc3.hash},
            {nc2.hash, nc6.hash},
            {nc2.hash},
            {nc2.hash},
            {nc3.hash, nc5.hash},
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
        assert result == {nc1.hash}

        # blueprint_history: blueprint2
        result = set(indexes.blueprint_history.get_newest(self.blueprint2_id))
        assert result == set()

        # nc_creation
        result = set(indexes.nc_creation.get_newest())
        assert result == {nc1.hash}

        # tokens
        htr_total = indexes.tokens.get_token_info(HATHOR_TOKEN_UID).get_total()
        tka_total = indexes.tokens.get_token_info(tka.hash).get_total()
        assert self.manager.tx_storage.get_height_best_block() == 50
        # TODO: Is there a bug in the token index? It should be 50, not 52 blocks
        # genesis + 50 blocks - 2 from the TKA mint in nc1.out[0]
        assert htr_total == self._settings.GENESIS_TOKENS + 52 * self._settings.INITIAL_TOKENS_PER_BLOCK - 2
        # 200 from nc1.out[0]
        assert tka_total == 200

        # nc_history
        expected_list = [
            {nc1.hash, nc2.hash},
            set(),
            set(),
            set(),
            set(),
            set(),
            set(),
            set(),
        ]
        assert len(contracts) == len(expected_list)
        match_list = []
        for nc_id, expected in zip(contracts, expected_list):
            result = set(indexes.nc_history.get_newest(nc_id))
            match_list.append(result == expected)
        assert all(match_list)

        assert nc1.get_metadata().voided_by is None
        assert nc1.get_metadata().nc_execution == NCExecutionState.PENDING
        assert nc1 in self.manager.tx_storage.iter_mempool_from_best_index()
        assert self.manager.tx_storage.transaction_exists(nc1.hash)

        assert nc2.get_metadata().voided_by is None
        assert nc2.get_metadata().nc_execution == NCExecutionState.PENDING
        assert nc2 in self.manager.tx_storage.iter_mempool_from_best_index()
        assert self.manager.tx_storage.transaction_exists(nc2.hash)

        assert nc3.get_metadata().voided_by == {self._settings.PARTIALLY_VALIDATED_ID}
        assert nc3.get_metadata().nc_execution == NCExecutionState.PENDING
        assert nc3 not in self.manager.tx_storage.iter_mempool_from_best_index()
        assert not self.manager.tx_storage.transaction_exists(nc3.hash)

        assert nc4.get_metadata().voided_by == {self._settings.PARTIALLY_VALIDATED_ID}
        assert nc4.get_metadata().nc_execution == NCExecutionState.PENDING
        assert nc4 not in self.manager.tx_storage.iter_mempool_from_best_index()
        assert not self.manager.tx_storage.transaction_exists(nc4.hash)

        assert nc5.get_metadata().voided_by == {self._settings.PARTIALLY_VALIDATED_ID}
        assert nc5.get_metadata().nc_execution == NCExecutionState.PENDING
        assert nc5 not in self.manager.tx_storage.iter_mempool_from_best_index()
        assert not self.manager.tx_storage.transaction_exists(nc5.hash)

        assert nc6.get_metadata().voided_by == {self._settings.PARTIALLY_VALIDATED_ID}
        assert nc6.get_metadata().nc_execution == NCExecutionState.PENDING
        assert nc6 not in self.manager.tx_storage.iter_mempool_from_best_index()
        assert not self.manager.tx_storage.transaction_exists(nc6.hash)
