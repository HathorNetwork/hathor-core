# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

import pytest

from hathor.exception import InvalidNewTransaction
from hathor.transaction import Block, Transaction
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder


class TestSignalBitsVerification(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

    def _test_tx(self, *, signal_bits: int) -> None:
        manager = self.create_peer('unittests')
        dag_builder = TestDAGBuilder.from_manager(manager)
        artifacts = dag_builder.build_from_str('''
            blockchain genesis b[1..10]
            b10 < dummy < tx1
        ''')
        tx1 = artifacts.get_typed_vertex('tx1', Transaction)

        tx1.signal_bits = signal_bits
        artifacts.propagate_with(manager)

    def _test_block(self, *, signal_bits: int) -> None:
        manager = self.create_peer('unittests')
        dag_builder = TestDAGBuilder.from_manager(manager)
        artifacts = dag_builder.build_from_str('''
            blockchain genesis b[1..1]
        ''')
        b1 = artifacts.get_typed_vertex('b1', Block)

        b1.signal_bits = signal_bits
        artifacts.propagate_with(manager)

    def test_tx_no_signal_bits_success(self) -> None:
        self._test_tx(signal_bits=0)

    def test_tx_token_amount_version_bit_is_known(self) -> None:
        """Bit 0 encodes the transaction's token amount version, so `verify_signal_bits` accepts it.

        It is gated separately by `TransactionVerifier.verify_token_amount_version`, covered in
        `hathor_tests/token_amount_version/`.
        """
        manager = self.create_peer('unittests')
        dag_builder = TestDAGBuilder.from_manager(manager)
        artifacts = dag_builder.build_from_str('''
            blockchain genesis b[1..10]
            b10 < dummy < tx1
        ''')
        tx1 = artifacts.get_typed_vertex('tx1', Transaction)

        tx1.signal_bits = 1 << 0
        manager.verification_service.verifiers.vertex.verify_signal_bits(tx1)

    def test_tx_unknown_signal_bits_fail(self) -> None:
        signal_bits = (
            1 << 1,
            1 << 2,
            1 << 3,
            1 << 4,
            1 << 5,
            1 << 6,
            1 << 7,
        )

        for bits in signal_bits:
            with pytest.raises(Exception) as e:
                self._test_tx(signal_bits=bits)
            assert isinstance(e.value.__cause__, InvalidNewTransaction)
            assert str(e.value.__cause__) == f'full validation failed: vertex has unknown signal bits: {bin(bits)}'

    def test_block_no_signal_bits_success(self) -> None:
        self._test_block(signal_bits=0)

    def test_block_feature_activation_signal_bits_success(self) -> None:
        signal_bits = (
            1 << 0,
            1 << 1,
            1 << 2,
            1 << 3,
        )

        for bits in signal_bits:
            self._test_block(signal_bits=bits)

    def test_block_unknown_signal_bits_fail(self) -> None:
        signal_bits = (
            1 << 4,
            1 << 5,
            1 << 6,
            1 << 7,
        )

        for bits in signal_bits:
            with pytest.raises(Exception) as e:
                self._test_block(signal_bits=bits)
            assert isinstance(e.value.__cause__, InvalidNewTransaction)
            assert str(e.value.__cause__) == f'full validation failed: vertex has unknown signal bits: {bin(bits)}'
