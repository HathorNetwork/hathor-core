from twisted.internet.defer import inlineCallbacks

from hathor.p2p.netfilter import get_table
from hathor.p2p.resources import NetfilterRuleResource
from tests import unittest
from tests.resources.base_resource import StubSite, _BaseResourceTest


class BaseNetfilterTest(_BaseResourceTest._ResourceTest):
    __test__ = False

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
            'chain': 'xxx',
            'match': 'peer_id',
            'match_params': {
                'peer_id': '1234'
            },
            'target': 'reject'
        })
        data = response_post.json_value()
        self.assertEqual(data['success'], False)

        # invalid match
        response_post = yield self.web.post('netfilter', {
            'chain': 'post_peerid',
            'match': 'xxx',
            'match_params': {
                'peer_id': '1234'
            },
            'target': 'reject'
        })
        data = response_post.json_value()
        self.assertEqual(data['success'], False)

        # invalid match params
        response_post = yield self.web.post('netfilter', {
            'chain': 'post_peerid',
            'match': 'peer_id',
            'match_params': {
                'xxx': '1234'
            },
            'target': 'reject'
        })
        data = response_post.json_value()
        self.assertEqual(data['success'], False)

        # invalid target
        response_post = yield self.web.post('netfilter', {
            'chain': 'post_peerid',
            'match': 'peer_id',
            'match_params': {
                'peer_id': '1234'
            },
            'target': 'xxx'
        })
        data = response_post.json_value()
        self.assertEqual(data['success'], False)

        # Success
        response_post = yield self.web.post('netfilter', {
            'chain': 'post_peerid',
            'match': 'peer_id',
            'match_params': {
                'peer_id': '1234'
            },
            'target': 'reject'
        })
        data = response_post.json_value()
        self.assertEqual(data['success'], True)

        response = yield self.web.get('netfilter', {b'chain': bytes('post_peerid', 'utf-8')})
        data = response.json_value()
        self.assertEqual(len(data['rules']), 1)

        # Delete
        response_delete = yield self.web.delete('netfilter', {
            'chain': 'post_peerid',
            'match': 'peer_id',
            'match_params': {
                'peer_id': '1234'
            },
            'target': 'reject'
        })
        data = response_delete.json_value()
        self.assertEqual(data['success'], True)

        response = yield self.web.get('netfilter', {b'chain': bytes('post_peerid', 'utf-8')})
        data = response.json_value()
        self.assertEqual(len(data['rules']), 0)


class SyncV1NetfilterTest(unittest.SyncV1Params, BaseNetfilterTest):
    __test__ = True


class SyncV2NetfilterTest(unittest.SyncV2Params, BaseNetfilterTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeNetfilterTest(unittest.SyncBridgeParams, SyncV2NetfilterTest):
    pass
