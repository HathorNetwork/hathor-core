from twisted.internet.address import IPv4Address

from hathor.p2p.netfilter.context import NetfilterContext
from hathor.p2p.netfilter.matches_remote import NetfilterMatchIPAddressRemoteURL
from hathor_tests import unittest


class NetfilterMatchRemoteTest(unittest.TestCase):
    def test_match_ip(self) -> None:
        matcher = NetfilterMatchIPAddressRemoteURL('test', self.clock, 'http://localhost:8080')
        context = NetfilterContext(addr=IPv4Address('TCP', '192.168.0.1', 1234))
        self.assertFalse(matcher.match(context))

        matcher._update_cb(b'hathor-ip-list\n192.168.0.1')
        self.assertTrue(matcher.match(context))

        matcher._update_cb(b'hathor-ip-list\n192.168.0.2')
        self.assertFalse(matcher.match(context))

        # Guarantee the to_json is working fine
        json = matcher.to_json()
        self.assertEqual(json['match_params']['name'], 'test')
        self.assertEqual(json['match_params']['url'], 'http://localhost:8080')
