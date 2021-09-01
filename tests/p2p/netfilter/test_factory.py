from twisted.internet.address import IPv4Address

from hathor.p2p.factory import HathorServerFactory
from hathor.p2p.netfilter import get_table
from hathor.p2p.netfilter.factory import NetfilterFactory
from hathor.p2p.netfilter.matches import NetfilterMatchIPAddress
from hathor.p2p.netfilter.rule import NetfilterRule
from hathor.p2p.netfilter.targets import NetfilterReject
from hathor.p2p.peer_id import PeerId
from tests import unittest


class NetfilterFactoryTest(unittest.TestCase):
    def test_factory(self):
        pre_conn = get_table('filter').get_chain('pre_conn')

        match = NetfilterMatchIPAddress('192.168.0.1/32')
        rule = NetfilterRule(match, NetfilterReject())
        pre_conn.add_rule(rule)

        wrapped_factory = HathorServerFactory('testnet', PeerId(), node=None, use_ssl=False)
        factory = NetfilterFactory(connections=None, wrappedFactory=wrapped_factory)

        ret = factory.buildProtocol(IPv4Address('TCP', '192.168.0.1', 1234))
        self.assertIsNone(ret)

        ret = factory.buildProtocol(IPv4Address('TCP', '192.168.0.2', 1234))
        self.assertIsNotNone(ret)
