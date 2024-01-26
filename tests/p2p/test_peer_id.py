import os
import shutil
import tempfile

from hathor.p2p.peer_id import InvalidPeerIdException, PeerId
from hathor.p2p.peer_storage import PeerStorage
from tests import unittest
from tests.unittest import TestBuilder


class PeerIdTest(unittest.TestCase):
    def test_invalid_id(self):
        p1 = PeerId()
        p1.id = p1.id[::-1]
        self.assertRaises(InvalidPeerIdException, p1.validate)

    def test_invalid_public_key(self):
        p1 = PeerId()
        p2 = PeerId()
        p1.public_key = p2.public_key
        self.assertRaises(InvalidPeerIdException, p1.validate)

    def test_invalid_private_key(self):
        p1 = PeerId()
        p2 = PeerId()
        p1.private_key = p2.private_key
        self.assertRaises(InvalidPeerIdException, p1.validate)

    def test_no_private_key(self):
        p1 = PeerId()
        p1.private_key = None
        p1.validate()

    def test_create_from_json(self):
        p1 = PeerId()
        data1 = p1.to_json(include_private_key=True)
        p2 = PeerId.create_from_json(data1)
        data2 = p2.to_json(include_private_key=True)
        self.assertEqual(data1, data2)
        p2.validate()

    def test_create_from_json_without_private_key(self):
        p1 = PeerId()
        data1 = p1.to_json()
        # Just to test a part of the code
        del data1['entrypoints']
        p2 = PeerId.create_from_json(data1)
        data2 = p2.to_json()
        self.assertEqual(data2['entrypoints'], [])
        data1['entrypoints'] = []
        self.assertEqual(data1, data2)
        p2.validate()

    def test_sign_verify(self):
        data = b'abacate'
        p1 = PeerId()
        signature = p1.sign(data)
        self.assertTrue(p1.verify_signature(signature, data))

    def test_sign_verify_fail(self):
        data = b'abacate'
        p1 = PeerId()
        signature = p1.sign(data)
        signature = signature[::-1]
        self.assertFalse(p1.verify_signature(signature, data))

    def test_merge_peer(self):
        # Testing peer storage with merge of peers
        peer_storage = PeerStorage()

        p1 = PeerId()
        p2 = PeerId()
        p2.id = p1.id
        p2.public_key = p1.public_key
        p1.public_key = ''

        peer_storage.add_or_merge(p1)
        self.assertEqual(len(peer_storage), 1)

        peer_storage.add_or_merge(p2)

        peer = peer_storage[p1.id]
        self.assertEqual(peer.id, p1.id)
        self.assertEqual(peer.private_key, p1.private_key)
        self.assertEqual(peer.public_key, p1.public_key)
        self.assertEqual(peer.entrypoints, [])

        p3 = PeerId()
        p3.entrypoints.append('1')
        p3.entrypoints.append('3')
        p3.public_key = ''

        p4 = PeerId()
        p4.public_key = ''
        p4.private_key = ''
        p4.id = p3.id
        p4.entrypoints.append('2')
        p4.entrypoints.append('3')
        peer_storage.add_or_merge(p4)

        self.assertEqual(len(peer_storage), 2)

        peer_storage.add_or_merge(p3)
        self.assertEqual(len(peer_storage), 2)

        peer = peer_storage[p3.id]
        self.assertEqual(peer.id, p3.id)
        self.assertEqual(peer.private_key, p3.private_key)
        self.assertEqual(peer.entrypoints, ['2', '3', '1'])

        with self.assertRaises(ValueError):
            peer_storage.add(p1)

    def test_save_peer_file(self):
        import json

        p = PeerId()
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, 'peer.json')
        p.save_to_file(path)

        with open(path, 'r') as f:
            peer_from_file = json.load(f)

        self.assertEqual(p.to_json(include_private_key=True), peer_from_file)

        # Removing tmpdir
        shutil.rmtree(tmpdir)

    def test_retry_connection(self):
        p = PeerId()
        interval = p.retry_interval
        p.increment_retry_attempt(0)
        self.assertEqual(self._settings.PEER_CONNECTION_RETRY_INTERVAL_MULTIPLIER*interval, p.retry_interval)
        self.assertEqual(interval, p.retry_timestamp)

        # when retry_interval is already 180
        p.retry_interval = self._settings.PEER_CONNECTION_RETRY_MAX_RETRY_INTERVAL + 10
        p.increment_retry_attempt(0)
        self.assertEqual(self._settings.PEER_CONNECTION_RETRY_MAX_RETRY_INTERVAL, p.retry_interval)

        # reset
        p.reset_retry_timestamp()
        self.assertEqual(p.retry_interval, 5)
        self.assertEqual(p.retry_timestamp, 0)

    def test_validate_certificate(self):
        builder = TestBuilder()
        artifacts = builder.build()
        protocol = artifacts.p2p_manager.server_factory.buildProtocol('127.0.0.1')

        peer = PeerId('testnet')

        class FakeTransport:
            def getPeerCertificate(self):
                from OpenSSL import crypto

                # we use a new peer here just to save the trouble of manually creating a certificate
                random_peer = PeerId('testnet')
                return crypto.X509.from_cryptography(random_peer.get_certificate())
        protocol.transport = FakeTransport()
        result = peer.validate_certificate(protocol)
        self.assertFalse(result)

    def test_retry_logic(self):
        peer = PeerId('testnet')
        self.assertTrue(peer.can_retry(0))

        retry_interval = peer.retry_interval

        peer.increment_retry_attempt(0)
        self.assertFalse(peer.can_retry(0))
        self.assertFalse(peer.can_retry(retry_interval - 1))
        self.assertTrue(peer.can_retry(retry_interval))
        self.assertTrue(peer.can_retry(retry_interval + 1))

        peer.increment_retry_attempt(0)
        self.assertFalse(peer.can_retry(retry_interval))

        retry_interval *= self._settings.PEER_CONNECTION_RETRY_INTERVAL_MULTIPLIER
        self.assertFalse(peer.can_retry(retry_interval - 1))
        self.assertTrue(peer.can_retry(retry_interval))
        self.assertTrue(peer.can_retry(retry_interval))

        # Retry until we reach max retry interval.
        while peer.retry_interval < self._settings.PEER_CONNECTION_RETRY_MAX_RETRY_INTERVAL:
            peer.increment_retry_attempt(0)
        # We need to call it once more because peer.retry_interval is always one step behind.
        peer.increment_retry_attempt(0)

        # Confirm we are at the max retry interval.
        self.assertFalse(peer.can_retry(self._settings.PEER_CONNECTION_RETRY_MAX_RETRY_INTERVAL - 1))
        self.assertTrue(peer.can_retry(self._settings.PEER_CONNECTION_RETRY_MAX_RETRY_INTERVAL))
        self.assertTrue(peer.can_retry(self._settings.PEER_CONNECTION_RETRY_MAX_RETRY_INTERVAL + 1))

        # It shouldn't change with another retry.
        peer.increment_retry_attempt(0)
        self.assertFalse(peer.can_retry(self._settings.PEER_CONNECTION_RETRY_MAX_RETRY_INTERVAL - 1))
        self.assertTrue(peer.can_retry(self._settings.PEER_CONNECTION_RETRY_MAX_RETRY_INTERVAL))
        self.assertTrue(peer.can_retry(self._settings.PEER_CONNECTION_RETRY_MAX_RETRY_INTERVAL + 1))

        # Finally, reset it.
        peer.reset_retry_timestamp()
        self.assertTrue(peer.can_retry(0))


class BasePeerIdTest(unittest.TestCase):
    __test__ = False

    async def test_validate_entrypoint(self):
        manager = self.create_peer('testnet', unlock_wallet=False)
        peer_id = manager.my_peer
        peer_id.entrypoints = ['tcp://127.0.0.1:40403']

        # we consider that we are starting the connection to the peer
        protocol = manager.connections.client_factory.buildProtocol('127.0.0.1')
        protocol.connection_string = 'tcp://127.0.0.1:40403'
        result = await peer_id.validate_entrypoint(protocol)
        self.assertTrue(result)
        # if entrypoint is an URI
        peer_id.entrypoints = ['uri_name']
        result = await peer_id.validate_entrypoint(protocol)
        self.assertTrue(result)
        # test invalid. DNS in test mode will resolve to '127.0.0.1:40403'
        protocol.connection_string = 'tcp://45.45.45.45:40403'
        result = await peer_id.validate_entrypoint(protocol)
        self.assertFalse(result)

        # now test when receiving the connection - i.e. the peer starts it
        protocol.connection_string = None
        peer_id.entrypoints = ['tcp://127.0.0.1:40403']

        class FakeTransport:
            def getPeer(self):
                from collections import namedtuple
                Peer = namedtuple('Peer', 'host')
                return Peer(host='127.0.0.1')
        protocol.transport = FakeTransport()
        result = await peer_id.validate_entrypoint(protocol)
        self.assertTrue(result)
        # if entrypoint is an URI
        peer_id.entrypoints = ['uri_name']
        result = await peer_id.validate_entrypoint(protocol)
        self.assertTrue(result)


class SyncV1PeerIdTest(unittest.SyncV1Params, BasePeerIdTest):
    __test__ = True


class SyncV2PeerIdTest(unittest.SyncV2Params, BasePeerIdTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgePeerIdTest(unittest.SyncBridgeParams, SyncV2PeerIdTest):
    pass
