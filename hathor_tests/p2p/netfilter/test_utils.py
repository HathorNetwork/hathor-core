from hathor.p2p.netfilter import get_table
from hathor.p2p.netfilter.utils import add_peer_id_blacklist
from hathor_tests import unittest


class NetfilterUtilsTest(unittest.TestCase):
    def test_peer_id_blacklist(self) -> None:
        post_peerid = get_table('filter').get_chain('post_peerid')

        # Chain starts empty
        self.assertEqual(len(post_peerid.rules), 0)

        # Add two rules to reject peer ids
        blacklist = ['123', '456']
        add_peer_id_blacklist(blacklist)

        # Chain has two rules now
        self.assertEqual(len(post_peerid.rules), 2)

        # Check that the rules are what we expect
        for rule in post_peerid.rules:
            data = rule.to_json()
            self.assertEqual(data['chain']['name'], 'post_peerid')
            self.assertEqual(data['match']['type'], 'NetfilterMatchPeerId')
            self.assertIn(data['match']['match_params']['peer_id'], blacklist)
            self.assertEqual(data['target']['type'], 'NetfilterReject')
