#  Copyright 2026 Hathor Labs
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

"""How a vertex's token amount version is derived from `signal_bits`, and which vertices are exempt.

If any test here fails because of a production bug, the bug is not fixed here: the failing assertion is
kept, annotated with a comment explaining the production defect, and left failing. See the test plan in
`test_token_amount_version.py` for this convention.
"""

from __future__ import annotations

from hathor.transaction import Block, Transaction
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathorlib.token_amount_version import TokenAmountVersion


class TestTokenAmountVersionDerivation(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

        from hathor.simulator.patches import SimulatorCpuMiningService
        from hathor.simulator.simulator import _build_vertex_verifiers

        builder = self.get_builder() \
            .set_vertex_verifiers_builder(_build_vertex_verifiers) \
            .set_cpu_mining_service(SimulatorCpuMiningService())

        self.manager = self.create_peer_from_builder(builder)
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def _build_simple_tx(self) -> Transaction:
        """Build a single, well-formed HTR transaction whose `signal_bits` we can then manipulate."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..11]
            b10 < dummy

            tx.out[0] = 100 HTR
        ''')
        return artifacts.get_typed_vertex('tx', Transaction)

    def test_version_reads_only_signal_bits_lsb(self) -> None:
        """Only bit 0 of `signal_bits` selects the version; the higher (feature-signaling) bits are
        independent. An even LSB is V1 and an odd LSB is V2, regardless of the higher bits."""
        tx = self._build_simple_tx()

        expected_by_signal_bits = {
            0b0: TokenAmountVersion.V1,
            0b1: TokenAmountVersion.V2,
            0b10: TokenAmountVersion.V1,
            0b11: TokenAmountVersion.V2,
            0b100: TokenAmountVersion.V1,
            0b101: TokenAmountVersion.V2,
        }

        for signal_bits, expected in expected_by_signal_bits.items():
            tx.signal_bits = signal_bits
            assert tx.get_token_amount_version() == expected

    def test_version_is_one_indexed(self) -> None:
        """The on-chain mapping is 1-indexed: LSB 0 maps to V1 (not V0) and LSB 1 maps to V2. This mapping
        is encoded on-chain and must never drift."""
        assert int(TokenAmountVersion.V1) == 1
        assert int(TokenAmountVersion.V2) == 2
        assert not hasattr(TokenAmountVersion, 'V0')

        tx = self._build_simple_tx()
        tx.signal_bits = 0b0
        assert tx.get_token_amount_version() == TokenAmountVersion.V1
        assert int(tx.get_token_amount_version()) == 1

    def test_block_token_amount_version_is_always_v1(self) -> None:
        """A block's feature-signaling bits never make it V2: with the LSB set (and the feature active, as
        it is by default in `unittests.yml`) the block still reports V1 and its reward outputs encode as V1."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..11]
            b10 < dummy
        ''')
        block = artifacts.get_typed_vertex('b1', Block)

        # The LSB is the bit that selects V2 on a transaction; on a block it is only a feature-signaling bit.
        block.signal_bits = 0b11

        assert block.to_json()['token_amount_version'] == TokenAmountVersion.V1.value
        assert len(block.outputs) > 0
        for output in block.outputs:
            assert output.value.is_v1()

    def test_genesis_is_v1(self) -> None:
        """Genesis vertices, including the genesis transactions, report V1: genesis is unaffected by the
        feature."""
        genesis = self.manager.tx_storage.get_all_genesis()
        genesis_txs = [vertex for vertex in genesis if not vertex.is_block]
        genesis_blocks = [vertex for vertex in genesis if vertex.is_block]

        assert len(genesis_txs) > 0
        assert len(genesis_blocks) > 0

        for tx in genesis_txs:
            assert isinstance(tx, Transaction)
            assert tx.get_token_amount_version() == TokenAmountVersion.V1

        for block in genesis_blocks:
            assert block.to_json()['token_amount_version'] == TokenAmountVersion.V1.value

    def test_token_creation_tx_version_round_trips(self) -> None:
        """The token amount version is part of a token-creation tx's serialization contract: a V2
        `TokenCreationTransaction` keeps V2 across `get_struct()`/`create_from_struct`, and its outputs
        decode under V2."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            b10 < dummy

            tx_v1.out[0] = 100 TK1

            tx_v2.out[0] = 100 TK2
            tx_v2.token_amount_version = V2
            TK2.token_amount_version = V2

            b11 < tx_v1
            b12 < tx_v2
            tx_v1 <-- tx_v2 <-- b13
        ''')
        artifacts.propagate_with(self.manager)
        token_creation_tx = artifacts.get_typed_vertex('TK2', TokenCreationTransaction)

        assert token_creation_tx.get_token_amount_version() == TokenAmountVersion.V2

        parsed = TokenCreationTransaction.create_from_struct(token_creation_tx.get_struct())
        assert parsed == token_creation_tx
        assert parsed.get_token_amount_version() == TokenAmountVersion.V2
        assert parsed.signal_bits == token_creation_tx.signal_bits

        assert len(parsed.outputs) > 0
        for output in parsed.outputs:
            assert output.value.is_v2()
