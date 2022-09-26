from ipaddress import ip_network

from twisted.internet.address import HostnameAddress, IPv4Address, IPv6Address, UNIXAddress

from hathor.p2p.netfilter.context import NetfilterContext
from hathor.p2p.netfilter.matches import (
    NetfilterMatch,
    NetfilterMatchAll,
    NetfilterMatchAnd,
    NetfilterMatchIPAddress,
    NetfilterMatchOr,
    NetfilterMatchPeerId,
)
from hathor.p2p.peer_id import PeerId
from hathor.simulator import FakeConnection
from tests import unittest


class NetfilterNeverMatch(NetfilterMatch):
    def match(self, context: 'NetfilterContext') -> bool:
        return False


class NetfilterMatchTest(unittest.TestCase):
    def test_match_all(self):
        matcher = NetfilterMatchAll()
        context = NetfilterContext()
        self.assertTrue(matcher.match(context))

        # Guarantee the to_json is working fine
        json = matcher.to_json()
        self.assertEqual(json['type'], 'NetfilterMatchAll')

    def test_never_match(self):
        matcher = NetfilterNeverMatch()
        context = NetfilterContext()
        self.assertFalse(matcher.match(context))

        # Guarantee the to_json is working fine
        json = matcher.to_json()
        self.assertEqual(json['type'], 'NetfilterNeverMatch')

    def test_match_and_success(self):
        m1 = NetfilterMatchAll()
        m2 = NetfilterMatchAll()
        matcher = NetfilterMatchAnd(m1, m2)
        context = NetfilterContext()
        self.assertTrue(matcher.match(context))

    def test_match_and_fail_01(self):
        m1 = NetfilterNeverMatch()
        m2 = NetfilterMatchAll()
        matcher = NetfilterMatchAnd(m1, m2)
        context = NetfilterContext()
        self.assertFalse(matcher.match(context))

        # Guarantee the to_json is working fine
        json = matcher.to_json()
        self.assertEqual(json['type'], 'NetfilterMatchAnd')
        self.assertEqual(json['match_params']['a']['type'], 'NetfilterNeverMatch')
        self.assertEqual(json['match_params']['b']['type'], 'NetfilterMatchAll')

    def test_match_and_fail_10(self):
        m1 = NetfilterMatchAll()
        m2 = NetfilterNeverMatch()
        matcher = NetfilterMatchAnd(m1, m2)
        context = NetfilterContext()
        self.assertFalse(matcher.match(context))

    def test_match_and_fail_00(self):
        m1 = NetfilterNeverMatch()
        m2 = NetfilterNeverMatch()
        matcher = NetfilterMatchAnd(m1, m2)
        context = NetfilterContext()
        self.assertFalse(matcher.match(context))

    def test_match_or_success_11(self):
        m1 = NetfilterMatchAll()
        m2 = NetfilterMatchAll()
        matcher = NetfilterMatchOr(m1, m2)
        context = NetfilterContext()
        self.assertTrue(matcher.match(context))

    def test_match_or_success_10(self):
        m1 = NetfilterMatchAll()
        m2 = NetfilterNeverMatch()
        matcher = NetfilterMatchOr(m1, m2)
        context = NetfilterContext()
        self.assertTrue(matcher.match(context))

        # Guarantee the to_json is working fine
        json = matcher.to_json()
        self.assertEqual(json['type'], 'NetfilterMatchOr')
        self.assertEqual(json['match_params']['a']['type'], 'NetfilterMatchAll')
        self.assertEqual(json['match_params']['b']['type'], 'NetfilterNeverMatch')

    def test_match_or_success_01(self):
        m1 = NetfilterNeverMatch()
        m2 = NetfilterMatchAll()
        matcher = NetfilterMatchOr(m1, m2)
        context = NetfilterContext()
        self.assertTrue(matcher.match(context))

    def test_match_or_fail_00(self):
        m1 = NetfilterNeverMatch()
        m2 = NetfilterNeverMatch()
        matcher = NetfilterMatchOr(m1, m2)
        context = NetfilterContext()
        self.assertFalse(matcher.match(context))

    def test_match_ip_address_empty_context(self):
        matcher = NetfilterMatchIPAddress('192.168.0.0/24')
        context = NetfilterContext()
        self.assertFalse(matcher.match(context))

        # Guarantee the to_json is working fine
        json = matcher.to_json()
        self.assertEqual(json['type'], 'NetfilterMatchIPAddress')
        self.assertEqual(json['match_params']['host'], '192.168.0.0/24')

    def test_match_ip_address_ipv4_net(self):
        matcher = NetfilterMatchIPAddress('192.168.0.0/24')
        context = NetfilterContext(addr=IPv4Address('TCP', '192.168.0.10', 1234))
        self.assertTrue(matcher.match(context))
        context = NetfilterContext(addr=IPv4Address('TCP', '192.168.1.10', 1234))
        self.assertFalse(matcher.match(context))
        context = NetfilterContext(addr=IPv4Address('TCP', '127.0.0.1', 1234))
        self.assertFalse(matcher.match(context))
        context = NetfilterContext(addr=IPv4Address('TCP', '', 1234))
        self.assertFalse(matcher.match(context))

    def test_match_ip_address_ipv4_ip(self):
        matcher = NetfilterMatchIPAddress('192.168.0.1/32')
        context = NetfilterContext(addr=IPv4Address('TCP', '192.168.0.1', 1234))
        self.assertTrue(matcher.match(context))
        context = NetfilterContext(addr=IPv4Address('TCP', '192.168.0.10', 1234))
        self.assertFalse(matcher.match(context))
        context = NetfilterContext(addr=IPv4Address('TCP', '', 1234))
        self.assertFalse(matcher.match(context))

    def test_match_ip_address_ipv4_hostname(self):
        matcher = NetfilterMatchIPAddress('192.168.0.1/32')
        context = NetfilterContext(addr=HostnameAddress('hathor.network', 80))
        self.assertFalse(matcher.match(context))

    def test_match_ip_address_ipv4_unix(self):
        matcher = NetfilterMatchIPAddress('192.168.0.1/32')
        context = NetfilterContext(addr=UNIXAddress('/unix.sock'))
        self.assertFalse(matcher.match(context))

    def test_match_ip_address_ipv4_ipv6(self):
        matcher = NetfilterMatchIPAddress('192.168.0.1/32')
        context = NetfilterContext(addr=IPv6Address('TCP', '2001:db8::', 80))
        self.assertFalse(matcher.match(context))
        context = NetfilterContext(addr=IPv6Address('TCP', '', 80))
        self.assertFalse(matcher.match(context))

    def test_match_ip_address_ipv6_net(self):
        matcher = NetfilterMatchIPAddress('2001:0db8:0:f101::/64')
        context = NetfilterContext(addr=IPv6Address('TCP', '2001:db8::8a2e:370:7334', 1234))
        self.assertFalse(matcher.match(context))
        context = NetfilterContext(addr=IPv6Address('TCP', '2001:db8:0:f101:2::7334', 1234))
        self.assertTrue(matcher.match(context))

        # Guarantee the to_json is working fine
        json = matcher.to_json()
        self.assertEqual(json['type'], 'NetfilterMatchIPAddress')
        self.assertEqual(json['match_params']['host'], str(ip_network('2001:0db8:0:f101::/64')))

    def test_match_ip_address_ipv6_ip(self):
        matcher = NetfilterMatchIPAddress('2001:0db8:0:f101::1/128')
        context = NetfilterContext(addr=IPv6Address('TCP', '2001:db8:0:f101::1', 1234))
        self.assertTrue(matcher.match(context))
        context = NetfilterContext(addr=IPv6Address('TCP', '2001:db8::8a2e:370:7334', 1234))
        self.assertFalse(matcher.match(context))
        context = NetfilterContext(addr=IPv6Address('TCP', '2001:db8:0:f101:2::7334', 1234))
        self.assertFalse(matcher.match(context))

    def test_match_ip_address_ipv6_hostname(self):
        matcher = NetfilterMatchIPAddress('2001:0db8:0:f101::1/128')
        context = NetfilterContext(addr=HostnameAddress('hathor.network', 80))
        self.assertFalse(matcher.match(context))

    def test_match_ip_address_ipv6_unix(self):
        matcher = NetfilterMatchIPAddress('2001:0db8:0:f101::1/128')
        context = NetfilterContext(addr=UNIXAddress('/unix.sock'))
        self.assertFalse(matcher.match(context))

    def test_match_ip_address_ipv6_ipv4(self):
        matcher = NetfilterMatchIPAddress('2001:0db8:0:f101::1/128')
        context = NetfilterContext(addr=IPv4Address('TCP', '192.168.0.1', 1234))
        self.assertFalse(matcher.match(context))

    def test_match_peer_id_empty_context(self):
        matcher = NetfilterMatchPeerId('123')
        context = NetfilterContext()
        self.assertFalse(matcher.match(context))


class BaseNetfilterMatchTest(unittest.TestCase):
    __test__ = False

    def test_match_peer_id(self):
        network = 'testnet'
        peer_id1 = PeerId()
        peer_id2 = PeerId()
        manager1 = self.create_peer(network, peer_id=peer_id1)
        manager2 = self.create_peer(network, peer_id=peer_id2)

        conn = FakeConnection(manager1, manager2)
        self.assertTrue(conn.proto2.is_state(conn.proto2.PeerState.HELLO))

        matcher = NetfilterMatchPeerId(str(peer_id1.id))
        context = NetfilterContext(protocol=conn.proto2)
        self.assertFalse(matcher.match(context))

        conn.run_one_step()
        self.assertTrue(conn.proto2.is_state(conn.proto2.PeerState.PEER_ID))
        self.assertFalse(matcher.match(context))

        # Success because the connection is ready and proto2 is connected to proto1.
        conn.run_one_step()
        conn.run_one_step()
        self.assertTrue(conn.proto2.is_state(conn.proto2.PeerState.READY))
        self.assertTrue(matcher.match(context))

        # Fail because proto1 is connected to proto2, and the peer id cannot match.
        context = NetfilterContext(protocol=conn.proto1)
        self.assertFalse(matcher.match(context))

        # Guarantee the to_json is working fine
        json = matcher.to_json()
        self.assertEqual(json['type'], 'NetfilterMatchPeerId')
        self.assertEqual(json['match_params']['peer_id'], str(peer_id1.id))


class SyncV1NetfilterMatchTest(unittest.SyncV1Params, BaseNetfilterMatchTest):
    __test__ = True


class SyncV2NetfilterMatchTest(unittest.SyncV2Params, BaseNetfilterMatchTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeNetfilterMatchTest(unittest.SyncBridgeParams, SyncV2NetfilterMatchTest):
    pass
