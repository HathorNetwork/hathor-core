from hathor.p2p.peer_endpoint import PeerAddress, PeerEndpoint, Protocol
from hathor_tests import unittest


class EntrypointTestCase(unittest.TestCase):
    def test_is_ipv6(self) -> None:
        valid_addresses = [
            '::',
            '::1',
            '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
            '2001:db8:85a3:0:0:8a2e:370:7334',
            '2001:db8::8a2e:370:7334',
            '2001:db8:0:0:0:0:2:1',
            '1234::5678',
            'fe80::',
            '::abcd:abcd:abcd:abcd:abcd:abcd',
            '0:0:0:0:0:0:0:1',
            '0:0:0:0:0:0:0:0'
        ]

        invalid_addresses = [
            '127.0.0.1',
            '1200::AB00:1234::2552:7777:1313',
            '2001:db8::g123',
            '2001:db8::85a3::7334',
            '2001:db8:85a3:0000:0000:8a2e:0370:7334:1234',
            '12345::abcd',
            '2001:db8:85a3:8a2e:0370',
            '2001:db8:85a3::8a2e:3707334',
            '1234:56789::abcd',
            ':2001:db8::1',
            '2001:db8::1:',
            '2001::85a3::8a2e:370:7334'
        ]

        for address in valid_addresses:
            peer_address = PeerAddress(Protocol.TCP, address, 40403)
            self.assertTrue(PeerEndpoint(peer_address).addr.is_ipv6())

        for address in invalid_addresses:
            peer_address = PeerAddress(Protocol.TCP, address, 40403)
            self.assertFalse(PeerEndpoint(peer_address).addr.is_ipv6())
