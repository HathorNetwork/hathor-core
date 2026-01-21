from twisted.internet.defer import inlineCallbacks

from hathor.conf import HathorSettings
from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.nc_exec_logs import NCLogConfig
from hathor.nanocontracts.resources import NanoContractHistoryResource
from hathor.transaction import Transaction
from hathor.transaction.resources import TransactionResource
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest

settings = HathorSettings()


class LogEmitBlueprint(Blueprint):
    value: int

    @public
    def initialize(self, ctx: Context, value: int) -> None:
        self.value = value

    @public
    def log_and_emit(self, ctx: Context, message: str) -> None:
        self.log.info(f'Log: {message}')
        self.syscall.emit_event(message.encode('utf-8'))


class TransactionNanoContractTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()

        self.blueprint_id = b'x' * 32
        self.catalog = NCBlueprintCatalog({
            self.blueprint_id: LogEmitBlueprint
        })

        self.manager = self.create_peer(
            'unittests',
            unlock_wallet=True,
            wallet_index=True,
            nc_indexes=True,
            nc_log_config=NCLogConfig.ALL,
        )
        self.manager.tx_storage.nc_catalog = self.catalog
        self.web_transaction = StubSite(TransactionResource(self.manager))
        self.web_history = StubSite(NanoContractHistoryResource(self.manager))

    @inlineCallbacks
    def test_include_nc_logs_and_events(self):
        """Test include_nc_logs and include_nc_events parameters for both TransactionResource
        and NanoContractHistoryResource."""
        dag_builder = TestDAGBuilder.from_manager(self.manager)

        # nc1: initialize (no logs, no events)
        # nc2: log_and_emit (logs and events)
        artifacts = dag_builder.build_from_str(f'''
            blockchain genesis b[1..33]
            b30 < dummy

            nc1.nc_id = "{self.blueprint_id.hex()}"
            nc1.nc_method = initialize(42)

            nc2.nc_id = nc1
            nc2.nc_method = log_and_emit("combined test")

            b31 --> nc1
            b32 --> nc2
        ''')

        artifacts.propagate_with(self.manager)

        nc1, nc2 = artifacts.get_typed_vertices(['nc1', 'nc2'], Transaction)

        # Test TransactionResource API
        # Test nc1 (initialize - no logs, no events)
        response = yield self.web_transaction.get('transaction', {
            b'id': nc1.hash.hex().encode('ascii'),
            b'include_nc_logs': b'true',
            b'include_nc_events': b'true',
        })
        data = response.json_value()
        self.assertTrue(data['success'])
        self.assertEqual(data['nc_args_decoded'], [42])
        self.assertIn('nc_logs', data)
        self.assertIn('nc_events', data)
        # Should have empty events list for initialize method
        self.assertEqual(data['nc_events'], [])

        # Test nc2 (log_and_emit - has logs and events)
        response = yield self.web_transaction.get('transaction', {
            b'id': nc2.hash.hex().encode('ascii'),
            b'include_nc_logs': b'true',
            b'include_nc_events': b'true',
        })
        data = response.json_value()
        self.assertTrue(data['success'])
        self.assertEqual(data['nc_args_decoded'], ["combined test"])
        # Should have both logs and events
        self.assertIn('nc_logs', data)
        self.assertIsInstance(data['nc_logs'], dict)
        self.assertGreater(len(data['nc_logs']), 0)
        self.assertIn('nc_events', data)
        self.assertIsInstance(data['nc_events'], list)
        self.assertEqual(len(data['nc_events']), 1)
        event = data['nc_events'][0]
        self.assertEqual(bytes.fromhex(event['data']), b'combined test')

        # Test NanoContractHistoryResource API
        # By default, transactions are created with increasing timestamps, so nc2 is newer than nc1.
        # Test history for nc1 with default order (desc)
        response_desc = yield self.web_history.get('history', {
            b'id': nc1.hash.hex().encode('ascii'),
            b'include_nc_logs': b'true',
            b'include_nc_events': b'true',
        })
        data_desc = response_desc.json_value()
        self.assertTrue(data_desc['success'])
        self.assertEqual(len(data_desc['history']), 2)

        # Check order (desc), newest first: nc2, then nc1
        self.assertEqual(data_desc['history'][0]['hash'], nc2.hash_hex)
        self.assertEqual(data_desc['history'][1]['hash'], nc1.hash_hex)

        # Check content of nc2 in history
        nc2_in_history = data_desc['history'][0]
        self.assertEqual(nc2_in_history['nc_args_decoded'], ["combined test"])
        self.assertIn('nc_logs', nc2_in_history)
        self.assertIsInstance(nc2_in_history['nc_logs'], dict)
        self.assertGreater(len(nc2_in_history['nc_logs']), 0)
        self.assertIn('nc_events', nc2_in_history)
        self.assertIsInstance(nc2_in_history['nc_events'], list)
        self.assertEqual(len(nc2_in_history['nc_events']), 1)
        event = nc2_in_history['nc_events'][0]
        self.assertEqual(bytes.fromhex(event['data']), b'combined test')

        # Check content of nc1 in history
        nc1_in_history = data_desc['history'][1]
        self.assertEqual(nc1_in_history['nc_args_decoded'], [42])
        self.assertIn('nc_logs', nc1_in_history)
        self.assertIn('nc_events', nc1_in_history)
        self.assertEqual(nc1_in_history['nc_events'], [])

        # Test history for nc1 with asc order
        response_asc = yield self.web_history.get('history', {
            b'id': nc1.hash.hex().encode('ascii'),
            b'order': b'asc',
        })
        data_asc = response_asc.json_value()
        self.assertTrue(data_asc['success'])
        self.assertEqual(len(data_asc['history']), 2)

        # Check order (asc), oldest first: nc1, then nc2
        self.assertEqual(data_asc['history'][0]['hash'], nc1.hash_hex)
        self.assertEqual(data_asc['history'][1]['hash'], nc2.hash_hex)
