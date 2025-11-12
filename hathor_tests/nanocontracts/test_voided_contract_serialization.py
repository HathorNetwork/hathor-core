from hathor.nanocontracts import NC_EXECUTION_FAIL_ID, Blueprint, Context, public
from hathor.nanocontracts.exception import NCFail
from hathor.transaction import Block, Transaction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class FailingInitializeBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        raise NCFail('boom')

    @public
    def nop(self, ctx: Context) -> None:
        pass


class VoidedContractSerializationTest(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.fail_blueprint_id = self._register_blueprint_class(FailingInitializeBlueprint)

    def test_to_json_extended_for_voided_contract_call(self) -> None:
        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            nc_fail.nc_id = "{self.fail_blueprint_id.hex()}"
            nc_fail.nc_method = initialize()

            call.nc_id = nc_fail
            call.nc_method = nop()
            call.nc_address = wallet1
            call.nc_seqnum = 0

            nc_fail < call
            nc_fail <-- b11
            b11 < call
            call <-- b12
        ''')
        # stop right after adding 'b11', and thus before 'call' and 'b12'
        artifacts.propagate_with(self.manager, up_to='b11')

        nc_fail, call_tx = artifacts.get_typed_vertices(['nc_fail', 'call'], Transaction)
        b12 = artifacts.get_typed_vertex('b12', Block)

        assert nc_fail.get_metadata().nc_execution == NCExecutionState.FAILURE
        assert nc_fail.get_metadata().first_block == artifacts.get_typed_vertex('b11', Block).hash

        # sanity check call_tx and b12 should not have been validated yet
        assert call_tx.storage is None
        assert call_tx.get_metadata().validation.is_initial()
        assert b12.storage is None
        assert b12.get_metadata().validation.is_initial()

        # manually add call_tx as if it was received from the push_tx endpoint
        # XXX: in the future if this has to be refactored check `hathor/transaction/resources/push_tx.py` and mimick it
        call_tx.storage = self.manager.tx_storage
        self.manager.push_tx(call_tx, allow_non_standard_script=True)
        call_meta = call_tx.get_metadata()
        assert call_meta.validation.is_valid()
        assert call_meta.first_block is None
        assert call_meta.voided_by is None

        # now manually add b12 as if it was received from the network
        assert self.manager.vertex_handler.on_new_block(b12, deps=[])

        call_meta = call_tx.get_metadata()
        assert call_meta.first_block == b12.hash
        assert call_meta.voided_by is not None
        assert NC_EXECUTION_FAIL_ID in call_meta.voided_by

        b12_meta = b12.get_metadata()
        assert b12_meta.validation.is_valid()
        assert b12_meta.voided_by is None

        # extras, this should not fail:
        stored_call = self.manager.tx_storage.get_transaction(call_tx.hash)
        data = stored_call.to_json_extended()
        assert data['nc_id'] == nc_fail.hash_hex
        assert data['nc_blueprint_id'] == self.fail_blueprint_id.hex()
