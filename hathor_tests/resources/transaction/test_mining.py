from twisted.internet.defer import inlineCallbacks

from hathor.mining.cpu_mining_service import CpuMiningService
from hathor.transaction.resources import mining
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest


class MiningApiTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.get_block_template = StubSite(mining.GetBlockTemplateResource(self.manager, self.manager._settings))
        self.submit_block = StubSite(mining.SubmitBlockResource(self.manager))

    @inlineCallbacks
    def test_get_block_template_with_address(self):
        resp = yield self.get_block_template.get('', {b'address': b'HC7w4j7mPet49BBN5a2An3XUiPvK6C1TL7'})
        data = resp.json_value()

        self.assertEqual(len(data['parents']), 3)
        del data['parents']
        del data['timestamp']
        # score is now calculated from static metadata and will be non-zero
        self.assertGreater(data['metadata']['score'], 0)
        self.assertEqual(data['metadata']['score_raw'], str(data['metadata']['score']))
        data['metadata']['score'] = 0
        data['metadata']['score_raw'] = '0'
        self.assertEqual(data, {
            'version': 0,
            'weight': 1.0,
            'outputs': [{'value': 6400, 'token_data': 0, 'script': 'dqkUPW28v25nssvMMiWZR1alal4tOieIrA=='}],
            'metadata': {
                'hash': None,
                'spent_outputs': [],
                'received_by': [],
                'children': [],
                'has_more_children': False,
                'conflict_with': [],
                'voided_by': [],
                'twins': [],
                'validation': 'initial',
                'accumulated_weight': 1.0,
                'score': 0,
                'height': 1,
                'min_height': 0,
                'first_block': None,
                'feature_activation_bit_counts': [0, 0, 0, 0],
                'accumulated_weight_raw': '2',
                'score_raw': '0',
                'nc_block_root_id': None,
                'nc_execution': None,
                'nc_calls': None,
                'nc_events': None,
            },
            'tokens': [],
            'data': '',
            'signal_bits': 0
        })

    @inlineCallbacks
    def test_get_block_template_without_address(self):
        resp = yield self.get_block_template.get('')
        data = resp.json_value()

        self.assertEqual(len(data['parents']), 3)
        del data['parents']
        del data['timestamp']
        # score is now calculated from static metadata and will be non-zero
        self.assertGreater(data['metadata']['score'], 0)
        self.assertEqual(data['metadata']['score_raw'], str(data['metadata']['score']))
        data['metadata']['score'] = 0
        data['metadata']['score_raw'] = '0'
        self.assertEqual(data, {
            'version': 0,
            'weight': 1.0,
            'outputs': [{'value': 6400, 'token_data': 0, 'script': ''}],
            'metadata': {
                'hash': None,
                'spent_outputs': [],
                'received_by': [],
                'children': [],
                'has_more_children': False,
                'conflict_with': [],
                'voided_by': [],
                'twins': [],
                'validation': 'initial',  # FIXME: change to 'full' when validations are enabled
                'accumulated_weight': 1.0,
                'score': 0,
                'height': 1,
                'min_height': 0,
                'first_block': None,
                'feature_activation_bit_counts': [0, 0, 0, 0],
                'accumulated_weight_raw': '2',
                'score_raw': '0',
                'nc_block_root_id': None,
                'nc_execution': None,
                'nc_calls': None,
                'nc_events': None,
            },
            'tokens': [],
            'data': '',
            'signal_bits': 0
        })

    @inlineCallbacks
    def test_get_block_template_while_node_syncing(self):
        self.manager._allow_mining_without_peers = False
        resp = yield self.get_block_template.get('')
        data = resp.json_value()

        self.assertEqual(data, {
            'error': 'Node syncing',
        })

    @inlineCallbacks
    def test_get_block_template_and_submit_block(self):
        from hathor.client import create_tx_from_dict
        resp = yield self.get_block_template.get('', {b'address': b'HC7w4j7mPet49BBN5a2An3XUiPvK6C1TL7'})
        data = resp.json_value()
        block = create_tx_from_dict(data)
        CpuMiningService().resolve(block, update_time=False)
        self.assertTrue(self.manager.propagate_tx(block))
