#  Copyright 2025 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Cross-implementation serialization parity between the Rust port (`htr_next`) and the Python
reference.

The Rust codecs are exposed through the `htr_next` PyO3 extension (crate `hathor-next-py`):

- `vertex_decode_encode(bytes) -> bytes` decodes a serialized vertex and re-encodes it. Since the
  input is produced by the Python reference (`bytes(vertex)`), byte-identity of the output proves
  the Rust codec reads and writes the exact same wire format.
- `message_reencode(state, line) -> str` parses a p2p wire line in a protocol state and re-renders
  it. We assert it round-trips (idempotence) and that JSON payloads keep the same shape the Python
  senders produce.
"""

from __future__ import annotations

import json

import htr_next

from hathor.nanocontracts import OnChainBlueprint
from hathor.nanocontracts.utils import load_builtin_blueprint_for_ocb
from hathor.p2p.sync_v2.payloads import GetNextBlocksPayload, GetTransactionsBFSPayload
from hathor.transaction import Transaction
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts import test_blueprints

# Reference-serialized vertices captured from the Python implementation, one per vertex kind. These
# mirror the regression vectors in `hathor_tests/tx/test_tx_deserialization.py` — real on-wire bytes
# that the reference produces via `bytes(vertex)`.
REFERENCE_VERTEX_VECTORS: dict[str, bytes] = {
    'regular_block': bytes.fromhex(
        '0000010000190000001976a9143d6dbcbf6e67b2cbcc3225994756a56a5e2d3a2788ac40350000000000005'
        'e0f84de03000006cb93385b8b87a545a1cbb6197e6caff600c12cc12fc54250d39c8088fc0002d4d2a15def'
        '7604688e1878ab681142a7b155cbe52a6b4e031250ae96db0a0002ad8d1519daaddc8e1a37b14aac0b04512'
        '9c01832281fb1c02d873c7abbf9623731383164323332613136626139353030316465323264333135316230'
        '3237652d38336231356462333436393734386262623962623933303638613836333634362d6365326637376'
        '23939313037343461316231366565666630663032316130663200000002000000000000000080326758'
    ),
    'merge_mined_block': bytes.fromhex(
        '00030100000c8000001976a914980f1b0f1c7a7a6c42be02df5ede0bf2785adaba88ac4050357517a827ea'
        '608334c303000000000000000021d76c80fbd19f2ddbb9d6ac15dcc76d3555585984f1d93600000000939f'
        '2222fcbc4128f4a16b56a7b971f4e7a334d866d636c4356c6be300000000b7f4fb8573e2110989fd48968e'
        '729a8a3f3004a37bc57227ce944b5b0000a07b248cca37a8e6144fa66bbcc7feafbf06d412556b946d4ccc'
        '03000000000000000032010000000100000000000000000000000000000000000000000000000000000000'
        '00000000ffffffff3d038b720a48617468405a554c55506f6f4c2d4243484e0007178052000000ffffffff'
        '01abba5d25000000001976a9141fd680935cd42f95702493d44c8de964a42656b588ac000000000c0007f3'
        '2f902f6a69cf0ce343e653da8ff02491a438ef23c8980f426d8856bfbe5ae313742fb14b4aaafc408e42d5'
        '535fdf0277f6f6bf6365cabb4630f5dfac7495905b267569f02af2aea67f7251b8e2be11c3e0bcd64138d3'
        '5061c94cb6dcdce57983a8ca6b45f9bba4b30fd676b5aa6f3ab165c04acf134c5c6f0ae29b71c50d85a561'
        'd31f9f1aabf06a92e2afc3bb7e1890577b99327057f05a2c7dc4e60c537996c7a1281001e7a35f3942f78d'
        '503e6d664324ad551f57e14d9cf3cba3d323529f5a40ee4a1b921eaadeade3a065e6d909179bddc59e26d5'
        'bf6d5f62b52f57587a1999ce1d873b2c78a35f831edc399f1b34cdec33bc524ecb18a737b0da285443ddd5'
        'fc72d506d71202b64c4dc9c14f224ec7496313b41bf7813ded6ff99ac61d3cd0bcb5b538ab8a7a2a7f4cd0'
        'a0425e2c1da057367a56c69c37d2d039b30ae82992eb80fe6058cf2d2c23e2f5dfaa4a16208b7672ed6afe'
        '34054d41a52aba7b8fd5483b83bc8c361b667eda73286be0fcba763583a65853a06e1b8f14ad3483608ad4'
        '03180a130afe'
    ),
    'regular_transaction': bytes.fromhex(
        '000100010200000000b7f4fb8573e2110989fd48968e729a8a3f3004a37bc57227ce944b5b0000694630440'
        '220139d8549e6e9be0dbf8f239f0a76a410c79861f62d66e58579fc34982e9c26be022041100a9a32da836f'
        '524b28c6a9397e44ed94979e106decdafeec7df735b172dd21030d8a0db18eed94e16d58651b6446a47dc12'
        '1088321e36d8c2da1069fad13bd850000923900001976a91430e129a98a497cdc3c46a6a8390ad606bb62b0'
        '3088ac007276a300001976a914b3c38f156655a508ea1157da7336d3f63d8e6ebb88ac4035152270ab19ca6'
        '08334890200000000b7f4fb8573e2110989fd48968e729a8a3f3004a37bc57227ce944b5b000000009332ed'
        '6f9347dad83dff1ea73fc49c34765c24ba100bfd12bef86aed33d7d5ce'
    ),
    'token_creation_transaction': bytes.fromhex(
        '00020104000005551d7740fd7d3c0acc50b5677fdd844f1225985aa431e1712af2a2fd8900006a473045022'
        '100a445edb5cd6c79a0a7b5ed837582fd65b8d511ee60b64fd076e07bd8f63f75a202202dca24320bffc4c3'
        'ca2a07cdfff38f7c839bde70ed49ef634ac6588972836cab2103bfa995d676e3c0ed7b863c74cfef9683fab'
        '3163b42b6f21442326a023fc57fba0000264800001976a9146876f9578221fdb678d4e8376503098a9228b1'
        '3288ac00004e2001001976a914031761ef85a24603203c97e75af355b83209f08f88ac0000000181001976a'
        '9149f091256cb98649c7c35df0aad44d7805710691e88ac0000000281001976a914b1d7a5ee505ad4d3b93e'
        'a1a5162ba83d5049ec4e88ac0109546f5468654d6f6f6e04f09f9a804034a52aec6cece75e0fc0e30200001'
        'a72272f48339fcc5d5ec5deaf197855964b0eb912e8c6eefe00928b6cf600001055641c20b71871ed2c5c7d'
        '4096a34f40888d79c25bce74421646e732dc01ff7369'
    ),
}

# A 32-byte hash, hex-encoded, used to build canonical wire lines that carry vertex/block ids.
_HASH_A = 'aa' * 32
_HASH_B = 'bb' * 32


class RustVertexParityTest(unittest.TestCase):
    """Vertices serialized by the Python reference must round-trip byte-identically in Rust."""

    def _assert_vertex_roundtrip(self, name: str, vertex_bytes: bytes) -> None:
        reencoded = htr_next.vertex_decode_encode(vertex_bytes)
        self.assertEqual(
            reencoded,
            vertex_bytes,
            f'Rust re-encoding of {name} diverged from the Python reference bytes',
        )

    def test_reference_vectors(self) -> None:
        for name, vertex_bytes in REFERENCE_VERTEX_VECTORS.items():
            self._assert_vertex_roundtrip(name, vertex_bytes)

    def test_malformed_vertex_raises(self) -> None:
        for bad in [b'', b'\x00', b'\x00\x00', b'\xff' * 8, b'not a vertex at all']:
            with self.assertRaises(ValueError):
                htr_next.vertex_decode_encode(bad)


class RustVertexParityFromBuilderTest(unittest.TestCase):
    """Parity for freshly built vertices (varied nonces/weights/parents) and the kinds the static
    vectors don't cover: genesis, on-chain blueprints, and nano-header transactions."""

    def setUp(self) -> None:
        super().setUp()
        from hathor.simulator.patches import SimulatorCpuMiningService
        from hathor.simulator.simulator import _build_vertex_verifiers

        builder = self.get_builder() \
            .set_vertex_verifiers_builder(_build_vertex_verifiers) \
            .set_cpu_mining_service(SimulatorCpuMiningService())
        self.manager = self.create_peer_from_builder(builder)
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def _assert_vertex_roundtrip(self, name: str, vertex_bytes: bytes) -> None:
        reencoded = htr_next.vertex_decode_encode(vertex_bytes)
        self.assertEqual(
            reencoded,
            vertex_bytes,
            f'Rust re-encoding of {name} diverged from the Python reference bytes',
        )

    def test_genesis_vertices(self) -> None:
        genesis = self.manager.tx_storage.get_all_genesis()
        self.assertEqual(len(genesis), 3)  # 1 block + 2 transactions
        for vertex in genesis:
            self._assert_vertex_roundtrip(f'genesis:{vertex.hash_hex}', bytes(vertex))

    def test_blocks_and_transaction(self) -> None:
        artifacts = self.dag_builder.build_from_str("""
            blockchain genesis b[1..50]
            b1.out[0] <<< tx1
            b30 < tx1
            b40 --> tx1
        """)
        artifacts.propagate_with(self.manager)
        for node, vertex in artifacts.list:
            self._assert_vertex_roundtrip(node.name, bytes(vertex))

    def test_on_chain_blueprint_and_nano_header(self) -> None:
        bet_code = load_builtin_blueprint_for_ocb('bet.py', 'Bet', test_blueprints)
        private_key = unittest.OCB_TEST_PRIVKEY.hex()
        password = unittest.OCB_TEST_PASSWORD.hex()
        artifacts = self.dag_builder.build_from_str(f"""
            blockchain genesis b[1..11]
            b10 < dummy

            ocb1.ocb_private_key = "{private_key}"
            ocb1.ocb_password = "{password}"
            ocb1.ocb_code = "{bet_code.encode().hex()}"

            nc1.nc_id = ocb1
            nc1.nc_method = initialize("00", "00", 0)

            ocb1 <-- b11
            b11 < nc1
        """)
        artifacts.propagate_with(self.manager)

        ocb1 = artifacts.get_typed_vertex('ocb1', OnChainBlueprint)
        nc1 = artifacts.get_typed_vertex('nc1', Transaction)
        self.assertTrue(nc1.is_nano_contract())  # carries a NanoHeader

        self._assert_vertex_roundtrip('on_chain_blueprint', bytes(ocb1))
        self._assert_vertex_roundtrip('nano_header_transaction', bytes(nc1))


class RustMessageParityTest(unittest.TestCase):
    """Every p2p message the Rust port models must parse and re-render in its state, and JSON
    payloads must keep the shape the Python reference produces."""

    def _assert_message_roundtrip(self, state: str, line: str) -> str:
        rendered = htr_next.message_reencode(state, line)
        # Re-rendering is idempotent: feeding the canonical form back yields the same string.
        self.assertEqual(
            htr_next.message_reencode(state, rendered),
            rendered,
            f'{state} message did not re-render stably: {line!r} -> {rendered!r}',
        )
        return rendered

    def test_hello_state_messages(self) -> None:
        hello = json.dumps({
            'app': 'Hathor v1.2.3',
            'network': 'unittests',
            'remote_address': '127.0.0.1:40403',
            'genesis_short_hash': 'abc1234',
            'timestamp': 1700000000.0,
            'capabilities': ['sync-version', 'ipv6'],
            'sync_versions': ['v2'],
        })
        for line in [f'HELLO {hello}', 'ERROR boom', 'THROTTLE global rate-limit']:
            self._assert_message_roundtrip('hello', line)

    def test_peer_id_state_messages(self) -> None:
        # READY and the control messages are valid in the PEER-ID state. The PEER-ID payload itself
        # needs a real keypair and is covered by the Rust unit tests.
        for line in ['READY', 'ERROR boom', 'THROTTLE global rate-limit']:
            self._assert_message_roundtrip('peer-id', line)

    def test_ready_state_control_and_ready_messages(self) -> None:
        lines = [
            'ERROR boom',
            'THROTTLE global rate-limit',
            'PING deadbeef',
            'PONG deadbeef',
            'GET-PEERS',
            'PEERS []',
            'GET-BEST-BLOCKCHAIN',
            'GET-BEST-BLOCKCHAIN 10',
            f'BEST-BLOCKCHAIN [[5, "{_HASH_A}"]]',
            f'GET-BLOCK-NC-ROOT-ID {_HASH_A}',
        ]
        for line in lines:
            self._assert_message_roundtrip('ready', line)

    def test_ready_state_sync_v2_messages(self) -> None:
        block_b64 = _b64(REFERENCE_VERTEX_VECTORS['regular_block'])
        tx_b64 = _b64(REFERENCE_VERTEX_VECTORS['regular_transaction'])
        lines = [
            'GET-BEST-BLOCK',
            'BLOCKS-END 2',
            'STOP-BLOCK-STREAMING',
            'TRANSACTIONS-END 7',
            'STOP-TRANSACTIONS-STREAMING',
            'GET-TIPS',
            f'TIPS ["{_HASH_A}", "{_HASH_B}"]',
            'TIPS-END',
            'MEMPOOL-END',
            f'GET-DATA {{"txid": "{_HASH_A}"}}',
            f'GET-DATA {{"txid": "{_HASH_A}", "origin": "mempool"}}',
            f'NOT-FOUND {_HASH_A}',
            'RELAY',
            'RELAY true',
            'RELAY false',
            'GET-PEER-BLOCK-HASHES [1, 2, 3]',
            f'PEER-BLOCK-HASHES [[100, "{_HASH_A}"], [101, "{_HASH_B}"]]',
            f'BLOCKS {block_b64}',
            f'TRANSACTION {tx_b64}',
            f'DATA {block_b64}',
            f'DATA mempool {block_b64}',
        ]
        for line in lines:
            self._assert_message_roundtrip('ready', line)

    def test_get_next_blocks_json_shape_matches_python(self) -> None:
        # Build the payload with the actual Python sender model, then confirm Rust parses that exact
        # JSON and preserves every field.
        payload = GetNextBlocksPayload(
            start_hash=bytes.fromhex(_HASH_A),
            end_hash=bytes.fromhex(_HASH_B),
            quantity=20,
        )
        line = f'GET-NEXT-BLOCKS {payload.model_dump_json()}'
        rendered = self._assert_message_roundtrip('ready', line)

        _word, _, rust_json = rendered.partition(' ')
        self.assertEqual(json.loads(rust_json), json.loads(payload.model_dump_json()))

    def test_get_transactions_bfs_json_shape_matches_python(self) -> None:
        payload = GetTransactionsBFSPayload(
            start_from=[bytes.fromhex(_HASH_A)],
            first_block_hash=bytes.fromhex(_HASH_B),
            last_block_hash=bytes.fromhex(_HASH_A),
        )
        line = f'GET-TRANSACTIONS-BFS {payload.model_dump_json()}'
        rendered = self._assert_message_roundtrip('ready', line)

        _word, _, rust_json = rendered.partition(' ')
        self.assertEqual(json.loads(rust_json), json.loads(payload.model_dump_json()))

    def test_embedded_vertex_in_message_roundtrips(self) -> None:
        # The vertex carried inside BLOCKS/TRANSACTION/DATA must survive the message round-trip
        # byte-for-byte, exercising the codec through the wire-message path.
        import base64
        block = REFERENCE_VERTEX_VECTORS['regular_block']
        rendered = htr_next.message_reencode('ready', f'BLOCKS {_b64(block)}')
        _word, _, payload_b64 = rendered.partition(' ')
        self.assertEqual(base64.b64decode(payload_b64), block)

    def test_out_of_state_messages_are_rejected(self) -> None:
        # A READY-only message is not valid during HELLO/PEER-ID, and HELLO is not valid in READY.
        with self.assertRaises(ValueError):
            htr_next.message_reencode('hello', 'PING x')
        with self.assertRaises(ValueError):
            htr_next.message_reencode('peer-id', 'GET-PEERS')
        with self.assertRaises(ValueError):
            htr_next.message_reencode('ready', 'HELLO {}')

    def test_unknown_state_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            htr_next.message_reencode('not-a-state', 'GET-PEERS')

    def test_reference_messages_not_modeled_by_rust(self) -> None:
        # The Rust port does not yet model these reference messages (no BEST-BLOCK response variant,
        # no GET-MEMPOOL). This pins the current gap: it will fail — prompting an update here — once
        # the Rust port adds them.
        with self.assertRaises(ValueError):
            htr_next.message_reencode('ready', f'BEST-BLOCK {{"block": "{_HASH_A}", "height": 5}}')
        with self.assertRaises(ValueError):
            htr_next.message_reencode('ready', 'GET-MEMPOOL')


def _b64(data: bytes) -> str:
    import base64
    return base64.b64encode(data).decode('ascii')
