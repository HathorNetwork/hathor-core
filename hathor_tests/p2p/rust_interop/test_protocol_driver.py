# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Drive the real `htr-core` protocol state machine from Python via `htr_core.ProtocolPeer`.

`ProtocolPeer` is a sans-IO stepper over the Rust engine: Python plays the remote peer, feeding
reference-true wire lines (built the same way the Python p2p stack builds them) and asserting the
exact outbound lines and state transitions the Rust engine produces. This exercises the *real*
handshake and per-state message handling deterministically — no sockets, TLS, async, or subprocess —
and on the `unittests` network the Python test suite already runs on.
"""

from __future__ import annotations

import json

import htr_core

from hathor.p2p.peer import PrivatePeer
from hathor.p2p.utils import get_representation_for_all_genesis
from hathor_tests import unittest


class RustProtocolDriverTest(unittest.TestCase):
    def _genesis_short_hash(self) -> str:
        return get_representation_for_all_genesis(self._settings).hex()[:7]

    def _hello_line(self, *, network: str | None = None, genesis: str | None = None) -> str:
        """A reference-true HELLO line; override network/genesis to test the engine's validation."""
        payload = {
            'app': 'Hathor-test v1.0.0',
            'network': network if network is not None else self._settings.NETWORK_NAME,
            'remote_address': '127.0.0.1:40403',
            'genesis_short_hash': genesis if genesis is not None else self._genesis_short_hash(),
            'timestamp': 1700000000.0,
            'capabilities': ['sync-version'],
            'sync_versions': ['v2'],
        }
        return 'HELLO ' + json.dumps(payload)

    def _peer_id_line(self) -> str:
        """A reference-true PEER-ID line, built from a real Python peer (same shape the node sends)."""
        peer = PrivatePeer.auto_generated()
        payload = {'id': str(peer.id), 'pubKey': peer.get_public_key(), 'entrypoints': []}
        return 'PEER-ID ' + json.dumps(payload)

    def _drive_to_ready(self) -> htr_core.ProtocolPeer:
        peer = htr_core.ProtocolPeer('unittests')
        self.assertEqual(peer.state, 'hello')

        hello = peer.start()
        self.assertEqual(len(hello), 1)
        self.assertTrue(hello[0].startswith('HELLO '))

        out = peer.feed(self._hello_line())
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0].startswith('PEER-ID '))
        self.assertEqual(peer.state, 'peer-id')

        out = peer.feed(self._peer_id_line())
        self.assertEqual(out, ['READY'])
        self.assertEqual(peer.state, 'peer-id')

        out = peer.feed('READY')
        self.assertEqual(out, [])
        self.assertEqual(peer.state, 'ready')
        return peer

    def test_unknown_network_rejected(self) -> None:
        with self.assertRaises(ValueError):
            htr_core.ProtocolPeer('not-a-network')

    def test_own_hello_matches_test_network(self) -> None:
        # The HELLO the Rust peer sends must carry our network and genesis, so a real Python node on
        # the unittests network would accept it.
        peer = htr_core.ProtocolPeer('unittests')
        line = peer.start()[0]
        self.assertTrue(line.startswith('HELLO '))
        data = json.loads(line[len('HELLO '):])
        self.assertEqual(data['network'], self._settings.NETWORK_NAME)
        self.assertEqual(data['genesis_short_hash'], self._genesis_short_hash())

    def test_full_handshake_reaches_ready(self) -> None:
        self._drive_to_ready()

    def test_ping_pongs_in_ready(self) -> None:
        peer = self._drive_to_ready()
        self.assertEqual(peer.feed('PING deadbeef'), ['PONG deadbeef'])
        self.assertEqual(peer.state, 'ready')

    def test_ignored_messages_keep_ready_open(self) -> None:
        peer = self._drive_to_ready()
        # The default engine policy does not answer these, but the connection stays open and usable.
        self.assertEqual(peer.feed('GET-PEERS'), [])
        self.assertEqual(peer.feed('GET-BEST-BLOCK'), [])
        self.assertEqual(peer.feed('PONG cafe'), [])
        self.assertEqual(peer.state, 'ready')
        self.assertEqual(peer.feed('PING cafe'), ['PONG cafe'])

    def test_error_closes_ready(self) -> None:
        peer = self._drive_to_ready()
        self.assertEqual(peer.feed('ERROR boom'), [])
        self.assertEqual(peer.state, 'closed')
        with self.assertRaises(ValueError):
            peer.feed('PING x')

    def test_throttle_is_advisory_in_ready(self) -> None:
        peer = self._drive_to_ready()
        self.assertEqual(peer.feed('THROTTLE global slow-down'), [])
        self.assertEqual(peer.state, 'ready')

    def test_network_mismatch_closes_with_error(self) -> None:
        peer = htr_core.ProtocolPeer('unittests')
        peer.start()
        out = peer.feed(self._hello_line(network='mainnet'))
        self.assertEqual(out, ['ERROR network-mismatch'])
        self.assertEqual(peer.state, 'closed')

    def test_genesis_mismatch_closes_with_error(self) -> None:
        peer = htr_core.ProtocolPeer('unittests')
        peer.start()
        out = peer.feed(self._hello_line(genesis='0000000'))
        self.assertEqual(out, ['ERROR genesis-mismatch'])
        self.assertEqual(peer.state, 'closed')

    def test_out_of_state_message_rejected_but_peer_usable(self) -> None:
        peer = htr_core.ProtocolPeer('unittests')
        peer.start()
        # A READY-only message during HELLO does not parse in this state.
        with self.assertRaises(ValueError):
            peer.feed('PING nope')
        # The peer is unchanged and can still complete a normal handshake.
        self.assertEqual(peer.state, 'hello')
        self.assertTrue(peer.feed(self._hello_line())[0].startswith('PEER-ID '))

    def test_unexpected_ready_during_peer_id_closes(self) -> None:
        peer = htr_core.ProtocolPeer('unittests')
        peer.start()
        peer.feed(self._hello_line())  # -> peer-id state, awaiting PEER-ID
        out = peer.feed('READY')
        self.assertEqual(out, ['ERROR peer-id-expected'])
        self.assertEqual(peer.state, 'closed')
