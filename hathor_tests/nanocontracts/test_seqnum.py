from hathor.nanocontracts import NC_EXECUTION_FAIL_ID, Blueprint, Context, public
from hathor.nanocontracts.exception import NCFail
from hathor.transaction import Block, Transaction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathor_tests.nanocontracts.utils import assert_nc_failure_reason


class MyBlueprint1(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def nop(self, ctx: Context) -> None:
        pass

    @public
    def fail(self, ctx: Context) -> None:
        raise NCFail('oops')


class NCBlueprintTestCase(BlueprintTestCase):
    def setUp(self):
        super().setUp()
        self.blueprint1_id = self._register_blueprint_class(MyBlueprint1)

    def test_seqnum_fail_after_success(self) -> None:
        """tx2 will successfully execute, so tx3 will fail because it has the same seqnum."""
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..34]
            b30 < dummy

            nc1.nc_id = "{self.blueprint1_id.hex()}"
            nc1.nc_method = initialize()

            tx2.nc_id = nc1
            tx2.nc_method = nop()
            tx2.nc_address = wallet1
            tx2.nc_seqnum = 0

            tx3.nc_id = nc1
            tx3.nc_method = nop()
            tx3.nc_address = wallet1
            tx3.nc_seqnum = 0
            tx3 --> tx2

            nc1 <-- b31
            tx2 <-- b31
            tx3 <-- b32
        ''')

        artifacts.propagate_with(self.manager)

        nc1, tx2, tx3 = artifacts.get_typed_vertices(['nc1', 'tx2', 'tx3'], Transaction)
        b32 = artifacts.get_typed_vertex('b32', Block)

        assert nc1.get_metadata().voided_by is None
        assert tx2.get_metadata().voided_by is None
        assert tx3.get_metadata().voided_by == {tx3.hash, NC_EXECUTION_FAIL_ID}
        assert nc1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx2.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx3.get_metadata().nc_execution == NCExecutionState.FAILURE

        tx2_nano_header = tx2.get_nano_header()
        tx3_nano_header = tx3.get_nano_header()

        assert tx2_nano_header.nc_address == tx3_nano_header.nc_address
        assert tx2_nano_header.nc_seqnum == tx3_nano_header.nc_seqnum

        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=tx3.hash,
            block_id=b32.hash,
            reason='NCFail: invalid seqnum (diff=0)'
        )

    def test_seqnum_fail_after_fail(self) -> None:
        """tx2 will fail execution but it should increase the seqnum anyways.
        So tx3 will fail because it has the same seqnum."""
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..34]
            b30 < dummy

            nc1.nc_id = "{self.blueprint1_id.hex()}"
            nc1.nc_method = initialize()

            tx2.nc_id = nc1
            tx2.nc_method = fail()
            tx2.nc_address = wallet1
            tx2.nc_seqnum = 0

            tx3.nc_id = nc1
            tx3.nc_method = nop()
            tx3.nc_address = wallet1
            tx3.nc_seqnum = 0
            tx3 --> tx2

            nc1 <-- b31
            tx2 <-- b31
            tx3 <-- b32
        ''')

        artifacts.propagate_with(self.manager)

        nc1, tx2, tx3 = artifacts.get_typed_vertices(['nc1', 'tx2', 'tx3'], Transaction)
        b31, b32 = artifacts.get_typed_vertices(['b31', 'b32'], Block)

        assert nc1.get_metadata().voided_by is None
        assert tx2.get_metadata().voided_by == {tx2.hash, NC_EXECUTION_FAIL_ID}
        assert tx3.get_metadata().voided_by == {tx3.hash, NC_EXECUTION_FAIL_ID}
        assert nc1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx2.get_metadata().nc_execution == NCExecutionState.FAILURE
        assert tx3.get_metadata().nc_execution == NCExecutionState.FAILURE

        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=tx2.hash,
            block_id=b31.hash,
            reason='NCFail: oops'
        )

        tx2_nano_header = tx2.get_nano_header()
        tx3_nano_header = tx3.get_nano_header()

        assert tx2_nano_header.nc_address == tx3_nano_header.nc_address
        assert tx2_nano_header.nc_seqnum == tx3_nano_header.nc_seqnum

        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=tx3.hash,
            block_id=b32.hash,
            reason='NCFail: invalid seqnum (diff=0)'
        )

    def test_seqnum_fail_after_skip(self) -> None:
        """tx2 will skip execution but it should increase the seqnum anyways.
        So tx3 will fail because it has the same seqnum."""
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..34]
            b30 < dummy

            nc1.nc_id = "{self.blueprint1_id.hex()}"
            nc1.nc_method = initialize()

            tx1.nc_id = nc1
            tx1.nc_method = fail()
            tx1.out[0] <<< tx2

            tx2.nc_id = nc1
            tx2.nc_method = nop()
            tx2.nc_address = wallet1
            tx2.nc_seqnum = 0

            tx3.nc_id = nc1
            tx3.nc_method = nop()
            tx3.nc_address = wallet1
            tx3.nc_seqnum = 0
            tx3 --> tx2

            nc1 <-- b31
            tx2 <-- b31
            tx3 <-- b32
        ''')

        artifacts.propagate_with(self.manager)

        nc1, tx1, tx2, tx3 = artifacts.get_typed_vertices(['nc1', 'tx1', 'tx2', 'tx3'], Transaction)
        b31, b32 = artifacts.get_typed_vertices(['b31', 'b32'], Block)

        assert nc1.get_metadata().voided_by is None
        assert tx1.get_metadata().voided_by == {tx1.hash, NC_EXECUTION_FAIL_ID}
        assert tx2.get_metadata().voided_by == {tx1.hash}
        assert tx3.get_metadata().voided_by == {tx3.hash, NC_EXECUTION_FAIL_ID}
        assert nc1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tx1.get_metadata().nc_execution == NCExecutionState.FAILURE
        assert tx2.get_metadata().nc_execution == NCExecutionState.SKIPPED
        assert tx3.get_metadata().nc_execution == NCExecutionState.FAILURE

        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=tx1.hash,
            block_id=b31.hash,
            reason='NCFail: oops'
        )

        tx2_nano_header = tx2.get_nano_header()
        tx3_nano_header = tx3.get_nano_header()

        assert tx2_nano_header.nc_address == tx3_nano_header.nc_address
        assert tx2_nano_header.nc_seqnum == tx3_nano_header.nc_seqnum

        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=tx3.hash,
            block_id=b32.hash,
            reason='NCFail: invalid seqnum (diff=0)'
        )

    def test_seqnum_fail_max_jump(self) -> None:
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..34]
            b30 < dummy

            nc1.nc_id = "{self.blueprint1_id.hex()}"
            nc1.nc_method = initialize()
            nc1.nc_address = wallet1
            nc1.nc_seqnum = 0

            tx2.nc_id = nc1
            tx2.nc_method = nop()
            tx2.nc_address = wallet1
            tx2.nc_seqnum = 11

            nc1 <-- tx2 <-- b31
        ''')

        artifacts.propagate_with(self.manager)

        nc1, tx2 = artifacts.get_typed_vertices(['nc1', 'tx2'], Transaction)
        b31 = artifacts.get_typed_vertex('b31', Block)

        assert nc1.get_metadata().voided_by is None
        assert nc1.get_metadata().nc_execution == NCExecutionState.SUCCESS

        assert tx2.get_metadata().voided_by == {tx2.hash, NC_EXECUTION_FAIL_ID}
        assert tx2.get_metadata().nc_execution == NCExecutionState.FAILURE
        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=tx2.hash,
            block_id=b31.hash,
            reason='NCFail: invalid seqnum (diff=11)'
        )

        nc1_nano_header = nc1.get_nano_header()
        tx2_nano_header = tx2.get_nano_header()

        assert nc1_nano_header.nc_address == tx2_nano_header.nc_address

    def test_invalid_block(self) -> None:
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..34]
            b30 < dummy

            nc1.nc_id = "{self.blueprint1_id.hex()}"
            nc1.nc_method = initialize()

            tx2.nc_id = nc1
            tx2.nc_method = nop()
            tx2.nc_address = wallet1
            tx2.nc_seqnum = 0

            tx3.nc_id = nc1
            tx3.nc_method = nop()
            tx3.nc_address = wallet1
            tx3.nc_seqnum = 0
            tx2.out[0] <<< tx3

            tx4.nc_id = nc1
            tx4.nc_method = nop()
            tx4.nc_address = wallet1
            tx4.nc_seqnum = 1
            tx4 --> tx3

            nc1 <-- b31
            tx4 <-- b32
        ''')

        artifacts.propagate_with(self.manager)

        nc1, tx2, tx3, tx4 = artifacts.get_typed_vertices(['nc1', 'tx2', 'tx3', 'tx4'], Transaction)
        b32 = artifacts.get_typed_vertex('b32', Block)

        assert nc1.get_metadata().voided_by is None
        assert nc1.get_metadata().nc_execution == NCExecutionState.SUCCESS

        assert tx2.get_metadata().voided_by is None
        assert tx2.get_metadata().nc_execution == NCExecutionState.SUCCESS

        assert tx3.get_metadata().voided_by == {tx3.hash, NC_EXECUTION_FAIL_ID}
        assert tx3.get_metadata().nc_execution == NCExecutionState.FAILURE

        assert tx4.get_metadata().voided_by is None
        assert tx4.get_metadata().nc_execution == NCExecutionState.SUCCESS

        assert b32.get_metadata().voided_by is None

        tx2_nano_header = tx2.get_nano_header()
        tx3_nano_header = tx3.get_nano_header()

        assert tx2_nano_header.nc_address == tx3_nano_header.nc_address
        assert tx2_nano_header.nc_seqnum == tx3_nano_header.nc_seqnum

        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=tx3.hash,
            block_id=b32.hash,
            reason='NCFail: invalid seqnum (diff=0)'
        )

    def test_circular_dependency(self) -> None:
        """
        nc3 has the same address as nc1, and it uses nc2 which spends from nc1, so there's an indirect dependency.
        However, nc3.seqnum < nc1.seqnum.
        """
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..11]
            b10 < dummy

            nc1.nc_id = "{self.blueprint1_id.hex()}"
            nc1.nc_method = initialize()
            nc1.nc_address = wallet1
            nc1.nc_seqnum = 2

            nc2.nc_id = "{self.blueprint1_id.hex()}"
            nc2.nc_method = initialize()
            nc1.out[0] <<< nc2

            nc3.nc_id = nc2
            nc3.nc_method = nop()
            nc3.nc_address = wallet1
            nc3.nc_seqnum = 1

            nc2 <-- b11
            nc3 <-- b11
        ''')

        artifacts.propagate_with(self.manager)

        nc1, nc2, nc3 = artifacts.get_typed_vertices(['nc1', 'nc2', 'nc3'], Transaction)
        b11 = artifacts.get_typed_vertex('b11', Block)

        nc1_nano_header = nc1.get_nano_header()
        nc2_nano_header = nc2.get_nano_header()
        nc3_nano_header = nc3.get_nano_header()
        assert nc1_nano_header.nc_address != nc2_nano_header.nc_address
        assert nc1_nano_header.nc_address == nc3_nano_header.nc_address
        assert nc1_nano_header.nc_seqnum > nc3_nano_header.nc_seqnum

        assert nc1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert nc1.get_metadata().voided_by is None

        assert nc2.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert nc2.get_metadata().voided_by is None

        assert nc3.get_metadata().nc_execution == NCExecutionState.FAILURE
        assert nc3.get_metadata().voided_by == {nc3.hash, NC_EXECUTION_FAIL_ID}
        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=nc3.hash,
            block_id=b11.hash,
            reason='NCFail: invalid seqnum (diff=-1)'
        )

    def test_timestamp_rule(self) -> None:
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            nc0.nc_id = "{self.blueprint1_id.hex()}"
            nc0.nc_method = initialize()

            nc1.nc_id = nc0
            nc1.nc_method = nop()
            nc1.nc_address = wallet1
            nc1.nc_seqnum = 2

            nc2.nc_id = nc0
            nc2.nc_method = nop()
            nc2.nc_address = wallet1
            nc2.nc_seqnum = 1

            nc1 < nc2
            nc0 <-- b11
            nc1 <-- b12
            nc2 <-- b12
        ''')

        artifacts.propagate_with(self.manager)
        b12 = artifacts.get_typed_vertex('b12', Block)
        nc0, nc1, nc2 = artifacts.get_typed_vertices(['nc0', 'nc1', 'nc2'], Transaction)

        nc1_nano_header = nc1.get_nano_header()
        nc2_nano_header = nc2.get_nano_header()
        assert nc1_nano_header.nc_address == nc2_nano_header.nc_address
        assert nc1_nano_header.nc_seqnum > nc2_nano_header.nc_seqnum
        assert nc1.timestamp < nc2.timestamp

        assert nc0.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert nc0.get_metadata().voided_by is None

        # The execution order of nc1 and nc2 is random because even though nc1.seqnum > nc2.seqnum, the timestamp
        # rule makes this order not guaranteed.
        # - When we execute nc1 before nc2, nc1 succeeds and nc2 fails.
        # - When we execute nc1 after nc2, both succeed.

        assert nc1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert nc1.get_metadata().voided_by is None

        if nc2.get_metadata().nc_execution == NCExecutionState.FAILURE:
            assert nc2.get_metadata().voided_by == {nc2.hash, NC_EXECUTION_FAIL_ID}
            assert_nc_failure_reason(
                manager=self.manager,
                tx_id=nc2.hash,
                block_id=b12.hash,
                reason='NCFail: invalid seqnum (diff=-1)'
            )

    def test_multiple_txs_same_seqnum(self) -> None:
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            nc0.nc_id = "{self.blueprint1_id.hex()}"
            nc0.nc_method = initialize()

            nc1.nc_id = nc0
            nc1.nc_method = nop()
            nc1.nc_address = wallet1
            nc1.nc_seqnum = 1

            nc2.nc_id = nc0
            nc2.nc_method = nop()
            nc2.nc_address = wallet1
            nc2.nc_seqnum = 1

            nc3.nc_id = nc0
            nc3.nc_method = nop()
            nc3.nc_address = wallet1
            nc3.nc_seqnum = 2

            nc4.nc_id = nc0
            nc4.nc_method = nop()
            nc4.nc_address = wallet1
            nc4.nc_seqnum = 2

            nc5.nc_id = nc0
            nc5.nc_method = nop()
            nc5.nc_address = wallet1
            nc5.nc_seqnum = 3

            nc6.nc_id = nc0
            nc6.nc_method = nop()
            nc6.nc_address = wallet1
            nc6.nc_seqnum = 3

            nc0 <-- b11
            nc1 <-- nc2 <-- nc3 <-- nc4 <-- nc5 <-- nc6 <-- b12
        ''')

        artifacts.propagate_with(self.manager)
        nc0, nc1, nc2, nc3, nc4, nc5, nc6 = artifacts.get_typed_vertices(
            ['nc0', 'nc1', 'nc2', 'nc3', 'nc4', 'nc5', 'nc6'],
            Transaction,
        )

        nc1_nano_header = nc1.get_nano_header()
        nc2_nano_header = nc2.get_nano_header()
        nc3_nano_header = nc3.get_nano_header()
        nc4_nano_header = nc4.get_nano_header()
        nc5_nano_header = nc5.get_nano_header()
        nc6_nano_header = nc6.get_nano_header()
        assert len({
            nc1_nano_header.nc_address,
            nc2_nano_header.nc_address,
            nc3_nano_header.nc_address,
            nc4_nano_header.nc_address,
            nc5_nano_header.nc_address,
            nc6_nano_header.nc_address,
        }) == 1
        assert nc1_nano_header.nc_seqnum == nc2_nano_header.nc_seqnum
        assert nc3_nano_header.nc_seqnum == nc4_nano_header.nc_seqnum
        assert nc5_nano_header.nc_seqnum == nc6_nano_header.nc_seqnum

        assert nc0.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert nc0.get_metadata().voided_by is None

        expected_states = {NCExecutionState.SUCCESS, NCExecutionState.FAILURE}
        assert {nc1.get_metadata().nc_execution, nc2.get_metadata().nc_execution} == expected_states
        assert {nc3.get_metadata().nc_execution, nc4.get_metadata().nc_execution} == expected_states
        assert {nc5.get_metadata().nc_execution, nc6.get_metadata().nc_execution} == expected_states
