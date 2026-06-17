#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Differential tests for the Rust vertex parser fast path (htr_lib.parse_vertex).

Contract: conservative acceptance. Whenever Rust accepts a byte string, the reconstructed vertex
must be identical to the Python parser's (type, every field, hash, and byte-exact re-serialization).
Whenever Rust rejects, the public deserialize() falls back to Python, so rejection semantics are
Python's by construction — the fuzz only needs to prove the acceptance side."""

from hypothesis import HealthCheck, given, settings as hypothesis_settings, strategies as st

from hathor.conf.get_settings import get_global_settings
from hathor.transaction import Block, Transaction, TxInput, TxOutput
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.transaction.vertex_parser import VertexParser

FUZZ = hypothesis_settings(max_examples=600, deadline=None, derandomize=True,
                           suppress_health_check=[HealthCheck.too_slow])

P2PKH_OUT = bytes.fromhex('76a914a390bb4d6d4ab570767ef21f66c3edc1a4d6902688ac')


def _parser() -> VertexParser:
    return VertexParser(settings=get_global_settings())


def assert_rust_acceptance_equivalent(data: bytes) -> None:
    """If the Rust path accepts `data`, the result must be indistinguishable from Python's."""
    parser = _parser()
    rust_vertex = parser._deserialize_rust(data, None)
    if rust_vertex is None:
        return  # fallback: Python semantics by construction
    python_vertex = parser._deserialize_python(data)
    assert type(rust_vertex) is type(python_vertex)
    assert rust_vertex.hash == python_vertex.hash
    assert bytes(rust_vertex) == bytes(python_vertex) == data
    assert rust_vertex.signal_bits == python_vertex.signal_bits
    assert rust_vertex.weight == python_vertex.weight or (
        rust_vertex.weight != rust_vertex.weight and python_vertex.weight != python_vertex.weight  # NaN
    )
    assert rust_vertex.timestamp == python_vertex.timestamp
    assert rust_vertex.nonce == python_vertex.nonce
    assert rust_vertex.parents == python_vertex.parents
    assert getattr(rust_vertex, 'tokens', None) == getattr(python_vertex, 'tokens', None)
    assert [(i.tx_id, i.index, i.data) for i in rust_vertex.inputs] == \
        [(i.tx_id, i.index, i.data) for i in python_vertex.inputs]
    assert [(o.value, o.script, o.token_data) for o in rust_vertex.outputs] == \
        [(o.value, o.script, o.token_data) for o in python_vertex.outputs]


def _corpus() -> list[bytes]:
    vertices: list[Block | Transaction] = []
    tx = Transaction(timestamp=1000, weight=10.5,
                     inputs=[TxInput(b'\x11' * 32, 0, b'\xab' * 107)],
                     outputs=[TxOutput(100, P2PKH_OUT)],
                     parents=[b'\x22' * 32, b'\x33' * 32], nonce=12345)
    vertices.append(tx)
    big = Transaction(timestamp=2_000_000_000, weight=60.25,
                      inputs=[TxInput(b'\x11' * 32, i % 256, bytes([i % 256]) * (i % 50 + 1)) for i in range(8)],
                      outputs=[TxOutput(5_000_000_000, P2PKH_OUT, 1), TxOutput(2**31 - 1, b'\x51', 0x81)],
                      tokens=[b'\x44' * 32], parents=[b'\x22' * 32, b'\x33' * 32])
    vertices.append(big)
    vertices.append(Transaction(timestamp=1, weight=0.0, outputs=[TxOutput(2**63, b'')]))  # max value, empty script
    block = Block(timestamp=3000, weight=21.0, outputs=[TxOutput(6400, P2PKH_OUT)],
                  parents=[b'\x55' * 32, b'\x66' * 32, b'\x77' * 32], data=b'\xde\xad', nonce=2**100)
    vertices.append(block)
    token_tx = TokenCreationTransaction(timestamp=4000, weight=15.0,
                                        inputs=[TxInput(b'\x11' * 32, 0, b'\xcd' * 10)],
                                        outputs=[TxOutput(100, P2PKH_OUT)],
                                        parents=[b'\x22' * 32, b'\x33' * 32],
                                        token_name='MyToken', token_symbol='MTK')
    vertices.append(token_tx)
    for vertex in vertices:
        vertex.update_hash()
    return [bytes(v) for v in vertices]


def test_corpus_acceptance_and_equality() -> None:
    parser = _parser()
    for data in _corpus():
        rust_vertex = parser._deserialize_rust(data, None)
        assert rust_vertex is not None, f'fast path must accept the corpus: {data.hex()[:40]}...'
        assert_rust_acceptance_equivalent(data)


def test_public_deserialize_uses_fast_path_transparently() -> None:
    parser = _parser()
    for data in _corpus():
        vertex = parser.deserialize(data)
        python_vertex = parser._deserialize_python(data)
        assert type(vertex) is type(python_vertex)
        assert vertex.hash == python_vertex.hash
        assert bytes(vertex) == data


def test_mutations() -> None:
    for data in _corpus():
        for cut in range(len(data)):
            assert_rust_acceptance_equivalent(data[:cut])
        for position in range(len(data)):
            mutated = bytearray(data)
            mutated[position] ^= 0xFF
            assert_rust_acceptance_equivalent(bytes(mutated))
        assert_rust_acceptance_equivalent(data + b'\x00')


@FUZZ
@given(data=st.binary(max_size=300))
def test_fuzz_random_bytes(data: bytes) -> None:
    assert_rust_acceptance_equivalent(data)


@FUZZ
@given(
    base_index=st.integers(min_value=0, max_value=4),
    position=st.integers(min_value=0, max_value=10_000),
    new_byte=st.integers(min_value=0, max_value=255),
    cut=st.integers(min_value=0, max_value=10_000),
)
def test_fuzz_structured_mutations(base_index: int, position: int, new_byte: int, cut: int) -> None:
    corpus = _corpus()
    data = bytearray(corpus[base_index % len(corpus)])
    data[position % len(data)] = new_byte
    assert_rust_acceptance_equivalent(bytes(data[:max(1, cut % (len(data) + 1))]))
