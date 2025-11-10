from twisted.internet.defer import inlineCallbacks

from hathor.p2p.netfilter import get_table
from hathor.p2p.resources import NetfilterRuleResource
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest


class NetfilterTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(NetfilterRuleResource(self.manager))

        # Clean rules before each test
        table = get_table('filter')
        for _, v in table.chains.items():
            v.rules = []

    @inlineCallbacks
    def test_netfilter_rule(self):
        # chain param is required
        response = yield self.web.get('netfilter')
        data = response.json_value()
        self.assertEqual(data['success'], False)

        # invalid chain
        response = yield self.web.get('netfilter', {b'chain': bytes('xxx', 'utf-8')})
        data = response.json_value()
        self.assertEqual(data['success'], False)

        response = yield self.web.get('netfilter', {b'chain': bytes('post_peerid', 'utf-8')})
        data = response.json_value()
        self.assertEqual(len(data['rules']), 0)

        # invalid chain
        response_post = yield self.web.post('netfilter', {
            'chain': {
                'name': 'xxx'
            },
            'match': 'peer_id',
            'match_params': {
                'peer_id': '1234'
            },
            "target": {
                "type": "NetfilterReject",
                "target_params": {}
            },
        })
        data = response_post.json_value()
        self.assertEqual(data['success'], False)

        # invalid match
        response_post = yield self.web.post('netfilter', {
            'chain': {
                'name': 'post_peerid',
            },
            'match': {
                'type': 'xxx',
                'match_params': {
                    'peer_id': '1234'
                },
            },
            "target": {
                "type": "NetfilterReject",
                "target_params": {}
            },
        })
        data = response_post.json_value()
        self.assertEqual(data['success'], False)

        # invalid match params
        response_post = yield self.web.post('netfilter', {
            'chain': {
                'name': 'post_peerid',
            },
            'match': {
                'type': 'NetfilterMatchPeerId',
                'match_params': {
                    'xxx': '1234'
                },
            },
            "target": {
                "type": "NetfilterReject",
                "target_params": {}
            },
        })
        data = response_post.json_value()
        self.assertEqual(data['success'], False)

        # invalid target
        response_post = yield self.web.post('netfilter', {
            'chain': {
                'name': 'post_peerid',
            },
            'match': {
                'type': 'NetfilterMatchPeerId',
                'match_params': {
                    'peer_id': '1234',
                },
            },
            "target": {
                "type": "xxx",
                "target_params": {}
            },
        })
        data = response_post.json_value()
        self.assertEqual(data['success'], False)

        # Success
        response_post = yield self.web.post('netfilter', {
            'chain': {
                'name': 'post_peerid',
            },
            'match': {
                'type': 'NetfilterMatchPeerId',
                'match_params': {
                    'peer_id': '1234'
                },
            },
            "target": {
                "type": "NetfilterReject",
                "target_params": {}
            },
        })
        data_post_success1 = response_post.json_value()
        self.assertEqual(data_post_success1['success'], True)

        response = yield self.web.get('netfilter', {b'chain': bytes('post_peerid', 'utf-8')})
        data_get = response.json_value()
        self.assertEqual(len(data_get['rules']), 1)

        # Add IP Address rule
        response_post = yield self.web.post('netfilter', {
            'chain': {
                'name': 'post_peerid',
            },
            'match': {
                'type': 'NetfilterMatchIPAddress',
                'match_params': {
                    'host': '127.0.0.1'
                },
            },
            "target": {
                "type": "NetfilterAccept",
                "target_params": {}
            },
        })
        data_post_success2 = response_post.json_value()
        self.assertEqual(data_post_success2['success'], True)

        response = yield self.web.get('netfilter', {b'chain': bytes('post_peerid', 'utf-8')})
        data_get = response.json_value()
        self.assertEqual(len(data_get['rules']), 2)

        # Delete peer ID rule
        response_delete = yield self.web.delete('netfilter', {
            'chain': 'post_peerid',
            'rule_uuid': data_post_success1['rule']['uuid']
        })
        data = response_delete.json_value()
        self.assertEqual(data['success'], True)

        response = yield self.web.get('netfilter', {b'chain': bytes('post_peerid', 'utf-8')})
        data = response.json_value()
        self.assertEqual(len(data['rules']), 1)

        # Delete ip address rule
        response_delete = yield self.web.delete('netfilter', {
            'chain': 'post_peerid',
            'rule_uuid': data_post_success2['rule']['uuid']
        })
        data = response_delete.json_value()
        self.assertEqual(data['success'], True)

        response = yield self.web.get('netfilter', {b'chain': bytes('post_peerid', 'utf-8')})
        data = response.json_value()
        self.assertEqual(len(data['rules']), 0)

        # Validate we can do dump -> reload
        for d in data_get['rules']:
            response_post = yield self.web.post('netfilter', d)

        response = yield self.web.get('netfilter', {b'chain': bytes('post_peerid', 'utf-8')})
        data_get = response.json_value()
        self.assertEqual(len(data_get['rules']), 2)
