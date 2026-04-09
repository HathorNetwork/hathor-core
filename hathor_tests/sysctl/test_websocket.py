from hathor.sysctl import WebsocketManagerSysctl
from hathor.sysctl.exception import SysctlException
from hathor.websocket.factory import HathorAdminWebsocketFactory
from hathor_tests import unittest


class WebsocketSysctlTestCase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.manager = self.create_peer('testnet')

    def test_max_subs_addrs_conn(self):
        ws_factory = HathorAdminWebsocketFactory(self.manager)
        sysctl = WebsocketManagerSysctl(ws_factory)

        sysctl.unsafe_set('max_subs_addrs_conn', 10)
        self.assertEqual(ws_factory.max_subs_addrs_conn, 10)
        self.assertEqual(sysctl.get('max_subs_addrs_conn'), 10)

        sysctl.unsafe_set('max_subs_addrs_conn', 0)
        self.assertEqual(ws_factory.max_subs_addrs_conn, 0)
        self.assertEqual(sysctl.get('max_subs_addrs_conn'), 0)

        sysctl.unsafe_set('max_subs_addrs_conn', -1)
        self.assertIsNone(ws_factory.max_subs_addrs_conn)
        self.assertEqual(sysctl.get('max_subs_addrs_conn'), -1)

        with self.assertRaises(SysctlException):
            sysctl.unsafe_set('max_subs_addrs_conn', -2)

    def test_max_subs_addrs_empty(self):
        ws_factory = HathorAdminWebsocketFactory(self.manager)
        sysctl = WebsocketManagerSysctl(ws_factory)

        sysctl.unsafe_set('max_subs_addrs_empty', 10)
        self.assertEqual(ws_factory.max_subs_addrs_empty, 10)
        self.assertEqual(sysctl.get('max_subs_addrs_empty'), 10)

        sysctl.unsafe_set('max_subs_addrs_empty', 0)
        self.assertEqual(ws_factory.max_subs_addrs_empty, 0)
        self.assertEqual(sysctl.get('max_subs_addrs_empty'), 0)

        sysctl.unsafe_set('max_subs_addrs_empty', -1)
        self.assertIsNone(ws_factory.max_subs_addrs_empty)
        self.assertEqual(sysctl.get('max_subs_addrs_empty'), -1)

        with self.assertRaises(SysctlException):
            sysctl.unsafe_set('max_subs_addrs_empty', -2)
