from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.exception import NCFail
from hathor.transaction import Block, Transaction
from hathor.transaction.nc_execution_state import NCExecutionState
from tests.dag_builder.builder import TestDAGBuilder
from tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from tests.nanocontracts.utils import assert_nc_failure_reason


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
        self.blueprint1_id = self.gen_random_blueprint_id()
        self.register_blueprint_class(self.blueprint1_id, MyBlueprint1)

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
            tx3 <-- b31
        ''')

        artifacts.propagate_with(self.manager)

        nc1, tx2, tx3 = artifacts.get_typed_vertices(['nc1', 'tx2', 'tx3'], Transaction)
        b31 = artifacts.get_typed_vertex('b31', Block)

        assert nc1.get_metadata().voided_by is None
        assert tx2.get_metadata().voided_by is None
        assert tx3.get_metadata().voided_by == {tx3.hash, self._settings.NC_EXECUTION_FAIL_ID}
        assert nc1.get_metadata().nc_execution is NCExecutionState.SUCCESS
        assert tx2.get_metadata().nc_execution is NCExecutionState.SUCCESS
        assert tx3.get_metadata().nc_execution is NCExecutionState.FAILURE

        tx2_nano_header = tx2.get_nano_header()
        tx3_nano_header = tx3.get_nano_header()

        assert tx2_nano_header.nc_address == tx3_nano_header.nc_address
        assert tx2_nano_header.nc_seqnum == tx3_nano_header.nc_seqnum

        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=tx3.hash,
            block_id=b31.hash,
            reason='NCFail: invalid seqnum'
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
            tx3 <-- b31
        ''')

        artifacts.propagate_with(self.manager)

        nc1, tx2, tx3 = artifacts.get_typed_vertices(['nc1', 'tx2', 'tx3'], Transaction)
        b31 = artifacts.get_typed_vertex('b31', Block)

        assert nc1.get_metadata().voided_by is None
        assert tx2.get_metadata().voided_by == {tx2.hash, self._settings.NC_EXECUTION_FAIL_ID}
        assert tx3.get_metadata().voided_by == {tx3.hash, self._settings.NC_EXECUTION_FAIL_ID}
        assert nc1.get_metadata().nc_execution is NCExecutionState.SUCCESS
        assert tx2.get_metadata().nc_execution is NCExecutionState.FAILURE
        assert tx3.get_metadata().nc_execution is NCExecutionState.FAILURE

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
            block_id=b31.hash,
            reason='NCFail: invalid seqnum'
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
            tx3 <-- b31
        ''')

        artifacts.propagate_with(self.manager)

        nc1, tx1, tx2, tx3 = artifacts.get_typed_vertices(['nc1', 'tx1', 'tx2', 'tx3'], Transaction)
        b31 = artifacts.get_typed_vertex('b31', Block)

        assert nc1.get_metadata().voided_by is None
        assert tx1.get_metadata().voided_by == {tx1.hash, self._settings.NC_EXECUTION_FAIL_ID}
        assert tx2.get_metadata().voided_by == {tx1.hash}
        assert tx3.get_metadata().voided_by == {tx3.hash, self._settings.NC_EXECUTION_FAIL_ID}
        assert nc1.get_metadata().nc_execution is NCExecutionState.SUCCESS
        assert tx1.get_metadata().nc_execution is NCExecutionState.FAILURE
        assert tx2.get_metadata().nc_execution is NCExecutionState.SKIPPED
        assert tx3.get_metadata().nc_execution is NCExecutionState.FAILURE

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
            block_id=b31.hash,
            reason='NCFail: invalid seqnum'
        )

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
            tx3 --> tx2

            tx4.nc_id = nc1
            tx4.nc_method = nop()
            tx4.nc_address = wallet1
            tx4.nc_seqnum = 1
            tx4 --> tx3

            tx5.nc_id = nc1
            tx5.nc_method = nop()
            tx5.nc_address = wallet1
            tx5.nc_seqnum = 12
            tx5 --> tx4

            tx6.nc_id = nc1
            tx6.nc_method = nop()
            tx6.nc_address = wallet1
            tx6.nc_seqnum = 11
            tx6 --> tx5

            nc1 <-- b31
            tx6 <-- b32
        ''')

        artifacts.propagate_with(self.manager)

        nc1, tx2, tx3 = artifacts.get_typed_vertices(['nc1', 'tx2', 'tx3'], Transaction)
        tx4, tx5, tx6 = artifacts.get_typed_vertices(['tx4', 'tx5', 'tx6'], Transaction)
        b32 = artifacts.get_typed_vertex('b32', Block)

        assert nc1.get_metadata().voided_by is None
        assert nc1.get_metadata().nc_execution is NCExecutionState.SUCCESS

        assert tx2.get_metadata().voided_by is None
        assert tx2.get_metadata().nc_execution is NCExecutionState.SUCCESS

        assert tx3.get_metadata().voided_by == {tx3.hash, self._settings.NC_EXECUTION_FAIL_ID}
        assert tx3.get_metadata().nc_execution is NCExecutionState.FAILURE

        assert tx4.get_metadata().voided_by is None
        assert tx4.get_metadata().nc_execution is NCExecutionState.SUCCESS

        assert tx5.get_metadata().voided_by == {tx5.hash, self._settings.NC_EXECUTION_FAIL_ID}
        assert tx5.get_metadata().nc_execution is NCExecutionState.FAILURE

        assert tx6.get_metadata().voided_by is None
        assert tx6.get_metadata().nc_execution is NCExecutionState.SUCCESS

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
        assert_nc_failure_reason(
            manager=self.manager,
            tx_id=tx5.hash,
            block_id=b32.hash,
            reason='NCFail: invalid seqnum (diff=11)'
        )
