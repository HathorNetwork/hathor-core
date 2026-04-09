import os
import shutil
import tempfile
from typing import cast
from unittest.mock import Mock

import pytest
from twisted.internet.interfaces import ITransport

from hathor.p2p.peer import InvalidPeerIdException, PrivatePeer, PublicPeer, UnverifiedPeer
from hathor.p2p.peer_endpoint import PeerAddress, PeerEndpoint
from hathor.p2p.peer_id import PeerId
from hathor.p2p.peer_storage import VerifiedPeerStorage
from hathor_tests import unittest
from hathor_tests.unittest import TestBuilder


class PeerIdTest(unittest.TestCase):
    def test_invalid_id(self) -> None:
        p1 = PrivatePeer.auto_generated()
        p1._public_peer._peer.id = PeerId(str(p1.id)[::-1])
        self.assertRaises(InvalidPeerIdException, p1.validate)

    def test_invalid_public_key(self) -> None:
        p1 = PrivatePeer.auto_generated()
        p2 = PrivatePeer.auto_generated()
        p1._public_peer.public_key = p2.public_key
        self.assertRaises(InvalidPeerIdException, p1.validate)

    def test_invalid_private_key(self) -> None:
        p1 = PrivatePeer.auto_generated()
        p2 = PrivatePeer.auto_generated()
        p1.private_key = p2.private_key
        self.assertRaises(InvalidPeerIdException, p1.validate)

    def test_no_private_key(self) -> None:
        p1 = PrivatePeer.auto_generated().to_public_peer()
        p1.validate()

    def test_create_from_json(self) -> None:
        p1 = PrivatePeer.auto_generated()
        data1 = p1.to_json_private()
        p2 = PrivatePeer.create_from_json(data1)
        data2 = p2.to_json_private()
        self.assertEqual(data1, data2)
        p2.validate()

    def test_create_from_json_without_private_key(self) -> None:
        p1 = PrivatePeer.auto_generated()
        data1 = p1.to_json()
        # Just to test a part of the code
        del data1['entrypoints']
        p2 = PublicPeer.create_from_json(data1)
        data2 = p2.to_json()
        self.assertEqual(data2['entrypoints'], [])
        data1['entrypoints'] = []
        self.assertEqual(data1, data2)
        p2.validate()

    def test_sign_verify(self) -> None:
        data = b'abacate'
        p1 = PrivatePeer.auto_generated()
        signature = p1.sign(data)
        self.assertTrue(p1.to_public_peer().verify_signature(signature, data))

    def test_sign_verify_fail(self) -> None:
        data = b'abacate'
        p1 = PrivatePeer.auto_generated()
        signature = p1.sign(data)
        signature = signature[::-1]
        self.assertFalse(p1.to_public_peer().verify_signature(signature, data))

    def test_merge_peer(self) -> None:
        # Testing peer storage with merge of peers
        peer_storage = VerifiedPeerStorage(rng=self.rng, max_size=100)

        p1 = PrivatePeer.auto_generated()
        p2 = PrivatePeer.auto_generated()
        p2._public_peer._peer.id = p1.id
        p2._public_peer.public_key = p1.public_key

        peer_storage.add_or_merge(p1.to_public_peer())
        self.assertEqual(len(peer_storage), 1)

        peer_storage.add_or_merge(p2.to_public_peer())
        peer = peer_storage[p1.id]
        self.assertEqual(peer.id, p1.id)
        self.assertEqual(peer.public_key, p1.public_key)
        self.assertEqual(peer.info.entrypoints, set())

        ep1 = PeerAddress.parse('tcp://127.0.0.1:1001')
        ep2 = PeerAddress.parse('tcp://127.0.0.1:1002')
        ep3 = PeerAddress.parse('tcp://127.0.0.1:1003')

        p3 = PrivatePeer.auto_generated().to_public_peer()
        p3.info.entrypoints.add(ep1)
        p3.info.entrypoints.add(ep2)

        p4 = PublicPeer(UnverifiedPeer(id=p3.id), public_key=p3.public_key)
        p4.info.entrypoints.add(ep2)
        p4.info.entrypoints.add(ep3)
        peer_storage.add_or_merge(p4)

        self.assertEqual(len(peer_storage), 2)

        peer_storage.add_or_merge(p3)
        self.assertEqual(len(peer_storage), 2)

        peer = peer_storage[p3.id]
        self.assertEqual(peer.id, p3.id)
        self.assertEqual(set(peer.info.entrypoints), {ep1, ep2, ep3})

        with self.assertRaises(ValueError):
            peer_storage.add(p1.to_public_peer())

    def test_save_peer_file(self) -> None:
        import json

        p = PrivatePeer.auto_generated()
        tmpdir = tempfile.mkdtemp()
        path = os.path.join(tmpdir, 'peer.json')
        p.save_to_file(path)

        with open(path, 'r') as f:
            peer_from_file = json.load(f)

        self.assertEqual(p.to_json_private(), peer_from_file)

        # Removing tmpdir
        shutil.rmtree(tmpdir)

    def test_retry_connection(self) -> None:
        p = PrivatePeer.auto_generated()
        interval = p.info.retry_interval
        p.info.increment_retry_attempt(0)
        self.assertEqual(self._settings.PEER_CONNECTION_RETRY_INTERVAL_MULTIPLIER*interval, p.info.retry_interval)
        self.assertEqual(interval, p.info.retry_timestamp)

        # when retry_interval is already 180
        p.info.retry_interval = self._settings.PEER_CONNECTION_RETRY_MAX_RETRY_INTERVAL + 10
        p.info.increment_retry_attempt(0)
        self.assertEqual(self._settings.PEER_CONNECTION_RETRY_MAX_RETRY_INTERVAL, p.info.retry_interval)

        # reset
        p.info.reset_retry_timestamp()
        self.assertEqual(p.info.retry_interval, 5)
        self.assertEqual(p.info.retry_timestamp, 0)

    def test_validate_certificate(self) -> None:
        builder = TestBuilder()
        artifacts = builder.build()
        protocol = artifacts.p2p_manager.server_factory.buildProtocol(Mock())

        peer = PrivatePeer.auto_generated()

        from OpenSSL import crypto

        class FakeTransport:
            def getPeerCertificate(self) -> crypto.X509:
                # we use a new peer here just to save the trouble of manually creating a certificate
                random_peer = PrivatePeer.auto_generated()
                return crypto.X509.from_cryptography(random_peer.certificate)
        protocol.transport = cast(ITransport, FakeTransport())
        result = peer.to_public_peer().validate_certificate(protocol)
        self.assertFalse(result)

    def test_retry_logic(self) -> None:
        peer = PrivatePeer.auto_generated()
        self.assertTrue(peer.info.can_retry(0))

        retry_interval = peer.info.retry_interval

        peer.info.increment_retry_attempt(0)
        self.assertFalse(peer.info.can_retry(0))
        self.assertFalse(peer.info.can_retry(retry_interval - 1))
        self.assertTrue(peer.info.can_retry(retry_interval))
        self.assertTrue(peer.info.can_retry(retry_interval + 1))

        peer.info.increment_retry_attempt(0)
        self.assertFalse(peer.info.can_retry(retry_interval))

        retry_interval *= self._settings.PEER_CONNECTION_RETRY_INTERVAL_MULTIPLIER
        self.assertFalse(peer.info.can_retry(retry_interval - 1))
        self.assertTrue(peer.info.can_retry(retry_interval))
        self.assertTrue(peer.info.can_retry(retry_interval))

        # Retry until we reach max retry interval.
        while peer.info.retry_interval < self._settings.PEER_CONNECTION_RETRY_MAX_RETRY_INTERVAL:
            peer.info.increment_retry_attempt(0)
        # We need to call it once more because peer.retry_interval is always one step behind.
        peer.info.increment_retry_attempt(0)

        # Confirm we are at the max retry interval.
        self.assertFalse(peer.info.can_retry(self._settings.PEER_CONNECTION_RETRY_MAX_RETRY_INTERVAL - 1))
        self.assertTrue(peer.info.can_retry(self._settings.PEER_CONNECTION_RETRY_MAX_RETRY_INTERVAL))
        self.assertTrue(peer.info.can_retry(self._settings.PEER_CONNECTION_RETRY_MAX_RETRY_INTERVAL + 1))

        # It shouldn't change with another retry.
        peer.info.increment_retry_attempt(0)
        self.assertFalse(peer.info.can_retry(self._settings.PEER_CONNECTION_RETRY_MAX_RETRY_INTERVAL - 1))
        self.assertTrue(peer.info.can_retry(self._settings.PEER_CONNECTION_RETRY_MAX_RETRY_INTERVAL))
        self.assertTrue(peer.info.can_retry(self._settings.PEER_CONNECTION_RETRY_MAX_RETRY_INTERVAL + 1))

        # Finally, reset it.
        peer.info.reset_retry_timestamp()
        self.assertTrue(peer.info.can_retry(0))

    def test_unverified_peer_to_json_roundtrip(self) -> None:
        peer_id = PrivatePeer.auto_generated().id
        addr1 = 'tcp://localhost:40403'
        addr2 = 'tcp://192.168.0.1:40404'
        addr3 = 'tcp://foo.bar:80'

        peer_json_simple = dict(
            id=str(peer_id),
            entrypoints=sorted({addr1, addr2, addr3})
        )
        result = UnverifiedPeer.create_from_json(peer_json_simple)

        assert result.id == peer_id
        assert result.info.entrypoints == {
            PeerAddress.parse(addr1),
            PeerAddress.parse(addr2),
            PeerAddress.parse(addr3),
        }
        assert result.to_json() == peer_json_simple

        # We support this for compatibility with old peers that may send ids in the URLs
        peer_json_with_ids = dict(
            id=str(peer_id),
            entrypoints=[
                f'{addr1}/?id={peer_id}',
                f'{addr2}/?id={peer_id}',
                addr3,
            ]
        )
        result = UnverifiedPeer.create_from_json(peer_json_with_ids)

        assert result.id == peer_id
        assert result.info.entrypoints == {
            PeerAddress.parse(addr1),
            PeerAddress.parse(addr2),
            PeerAddress.parse(addr3),
        }
        assert result.to_json() == peer_json_simple  # the roundtrip erases the ids from the URLs

        other_peer_id = PrivatePeer.auto_generated().id
        peer_json_with_conflicting_ids = dict(
            id=str(peer_id),
            entrypoints=[
                f'{addr1}/?id={peer_id}',
                f'{addr2}/?id={other_peer_id}',
                addr3,
            ]
        )

        with pytest.raises(ValueError) as e:
            UnverifiedPeer.create_from_json(peer_json_with_conflicting_ids)
        assert str(e.value) == f'conflicting peer_id: {other_peer_id} != {peer_id}'

    async def test_validate_entrypoint(self) -> None:
        manager = self.create_peer('testnet', unlock_wallet=False)
        peer = manager.my_peer
        peer.info.entrypoints = [PeerAddress.parse('tcp://127.0.0.1:40403')]

        # we consider that we are starting the connection to the peer
        protocol = manager.connections.client_factory.buildProtocol('127.0.0.1')
        protocol.entrypoint = PeerEndpoint.parse('tcp://127.0.0.1:40403')
        result = await peer.info.validate_entrypoint(protocol)
        self.assertTrue(result)
        # if entrypoint is an URI
        peer.info.entrypoints = [PeerAddress.parse('tcp://uri_name:40403')]
        result = await peer.info.validate_entrypoint(protocol)
        self.assertTrue(result)
        # if entrypoint is an IPv6
        peer.entrypoints = [PeerEndpoint.parse('tcp://[::1]:40403')]
        result = await peer.info.validate_entrypoint(protocol)
        self.assertTrue(result)
        # test invalid. DNS in test mode will resolve to '127.0.0.1:40403'
        protocol.entrypoint = PeerEndpoint.parse('tcp://45.45.45.45:40403')
        result = await peer.info.validate_entrypoint(protocol)
        self.assertFalse(result)

        # now test when receiving the connection - i.e. the peer starts it
        protocol.entrypoint = None
        peer.info.entrypoints = [PeerAddress.parse('tcp://127.0.0.1:40403')]

        from collections import namedtuple
        DummyPeer = namedtuple('DummyPeer', 'host')

        class FakeTransport:
            def getPeer(self) -> DummyPeer:
                return DummyPeer(host='127.0.0.1')
        protocol.transport = FakeTransport()
        result = await peer.info.validate_entrypoint(protocol)
        self.assertTrue(result)
        # if entrypoint is an URI
        peer.info.entrypoints = [PeerAddress.parse('tcp://uri_name:40403')]
        result = await peer.info.validate_entrypoint(protocol)
        self.assertTrue(result)
        # if entrypoint is an IPv6
        peer.entrypoints = [PeerEndpoint.parse('tcp://[2001:db8::ff00:42:8329]:40403')]
        result = await peer.info.validate_entrypoint(protocol)
        self.assertTrue(result)
