# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor.crypto.util import get_address_b58_from_bytes
from hathor.nanocontracts import OnChainBlueprint
from hathor.transaction import Block, Transaction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathorlib.token_amount_version import TokenAmountVersion


class TestAllFields(unittest.TestCase):
    def test_all_fields_ocb(self) -> None:
        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()
        manager = self.create_peer('unittests')
        dag_builder = TestDAGBuilder.from_manager(manager)

        # XXX: using an OCB to make sure any syntax/imports/etc are accepted
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..12]
            b10 < dummy

            ocb1.ocb_private_key = "{private_key}"
            ocb1.ocb_password = "{password}"
            ocb1.ocb_code = address_example.py, AddressExample
            ocb1 <-- b11

            nc1.nc_id = ocb1
            nc1.nc_method = initialize()
            nc1 <-- b12
        ''')
        artifacts.propagate_with(manager)

        b11, b12 = artifacts.get_typed_vertices(['b11', 'b12'], Block)
        ocb1 = artifacts.get_typed_vertex('ocb1', OnChainBlueprint)
        nc1 = artifacts.get_typed_vertex('nc1', Transaction)

        assert b11.get_metadata().voided_by is None
        assert ocb1.get_metadata().voided_by is None
        assert ocb1.get_metadata().first_block == b11.hash
        assert nc1.get_metadata().voided_by is None
        assert nc1.get_metadata().first_block == b12.hash
        assert nc1.get_metadata().nc_execution == NCExecutionState.SUCCESS

        runner = manager.get_nc_runner(b12, token_amount_version=TokenAmountVersion.V1)
        method_address = runner.call_view_method(nc1.hash, 'get_last_address_str')
        expected_address = get_address_b58_from_bytes(nc1.get_nano_header().nc_address)
        assert method_address == expected_address
