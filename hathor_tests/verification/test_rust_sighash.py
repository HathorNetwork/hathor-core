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

"""Differential tests for the Rust sighash splice: for every supported serialized vertex,
`htr_lib.sighash_from_vertex_bytes(bytes(tx))` must equal Python's `tx.get_sighash_all()`
byte for byte. The splice returns the wire bytes' funds region with input data zeroed, so
equality here proves both the span bookkeeping and the canonical-encoding property the
splice relies on."""

import random

import htr_lib

from hathor.conf.get_settings import get_global_settings
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor_tests.tx.test_parallel_script_verification import build_multisig_tx, build_p2pkh_tx

MAX_SIZE = get_global_settings().MAX_SERIALIZED_VERTEX_SIZE


def _assert_sighash_equal(tx: Transaction) -> None:
    data = bytes(tx)
    rust = htr_lib.sighash_from_vertex_bytes(data, MAX_SIZE)
    assert rust is not None, 'rust must support this vertex'
    tx.clear_sighash_cache()
    assert rust == tx.get_sighash_all(), type(tx).__name__


def test_sighash_p2pkh_and_multisig() -> None:
    _assert_sighash_equal(build_p2pkh_tx([0]))
    _assert_sighash_equal(build_p2pkh_tx([0, 1, 2, 3]))
    _assert_sighash_equal(build_multisig_tx(2))


def test_sighash_with_tokens_and_shapes() -> None:
    rng = random.Random(1234)
    for _ in range(50):
        num_tokens = rng.randrange(0, 3)
        num_inputs = rng.randrange(0, 4)
        num_outputs = rng.randrange(1, 4)
        tx = Transaction(
            timestamp=rng.randrange(1, 2**31),
            weight=rng.random() * 30,
            tokens=[rng.randbytes(32) for _ in range(num_tokens)],
            inputs=[
                TxInput(rng.randbytes(32), rng.randrange(256), rng.randbytes(rng.randrange(0, 80)))
                for _ in range(num_inputs)
            ],
            outputs=[
                TxOutput(rng.randrange(1, 2**31), rng.randbytes(rng.randrange(1, 60)), rng.randrange(num_tokens + 1))
                for _ in range(num_outputs)
            ],
            parents=[rng.randbytes(32) for _ in range(rng.randrange(0, 3))],
        )
        _assert_sighash_equal(tx)


def test_sighash_token_creation() -> None:
    tx = TokenCreationTransaction(
        timestamp=1000,
        weight=8.0,
        inputs=[TxInput(b'\x11' * 32, 0, b'\xaa\xbb')],
        outputs=[TxOutput(100, b'\x51', 0b10000001)],
        token_name='MyToken',
        token_symbol='MTK',
    )
    _assert_sighash_equal(tx)


def test_sighash_large_output_value() -> None:
    # 8-byte output-value encoding must survive the splice untouched
    tx = Transaction(
        timestamp=1000,
        weight=8.0,
        inputs=[TxInput(b'\x11' * 32, 0, b'\xaa')],
        outputs=[TxOutput(5_000_000_000, b'\x51', 0)],
    )
    _assert_sighash_equal(tx)
