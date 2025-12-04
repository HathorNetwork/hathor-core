#  Copyright 2025 Hathor Labs
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

from hathor.transaction import Block, Transaction
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder


class GenerateTxParentsTestCase(unittest.TestCase):
    """These tests cover all return cases of `generate_parent_txs`."""

    def setUp(self) -> None:
        super().setUp()
        self.manager = self.create_peer(network='unittests')
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def test_two_unconfirmed_genesis(self) -> None:
        parent_txs = self.manager.generate_parent_txs(timestamp=None)
        assert parent_txs.must_include == ()
        assert parent_txs.can_include == [self._settings.GENESIS_TX1_HASH, self._settings.GENESIS_TX2_HASH]

    def test_two_unconfirmed_txs(self) -> None:
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..10]
            b10 < dummy < tx1
        ''')

        dummy, tx1 = artifacts.get_typed_vertices(('dummy', 'tx1'), Transaction)

        artifacts.propagate_with(self.manager)
        assert dummy.get_metadata().first_block is None
        assert tx1.get_metadata().first_block is None

        parent_txs = self.manager.generate_parent_txs(timestamp=None)
        assert parent_txs.must_include == ()
        assert parent_txs.can_include == [dummy.hash, tx1.hash]

    def test_zero_unconfirmed_two_confirmed(self) -> None:
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..11]
            b10 < dummy < tx1
            dummy <-- b11
            tx1 <-- b11
        ''')

        b11, = artifacts.get_typed_vertices(('b11',), Block)
        dummy, tx1 = artifacts.get_typed_vertices(('dummy', 'tx1'), Transaction)

        artifacts.propagate_with(self.manager)
        assert dummy.get_metadata().first_block == b11.hash
        assert tx1.get_metadata().first_block == b11.hash

        parent_txs = self.manager.generate_parent_txs(timestamp=None)
        assert parent_txs.must_include == ()
        assert parent_txs.can_include == [dummy.hash, tx1.hash]

    def test_zero_unconfirmed_one_confirmed(self) -> None:
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..11]
            b10 < dummy
            dummy <-- tx1 <-- b11
        ''')

        b11, = artifacts.get_typed_vertices(('b11',), Block)
        dummy, tx1, = artifacts.get_typed_vertices(('dummy', 'tx1'), Transaction)

        artifacts.propagate_with(self.manager)
        assert dummy.get_metadata().first_block == b11.hash
        assert tx1.get_metadata().first_block == b11.hash

        parent_txs = self.manager.generate_parent_txs(timestamp=None)
        assert parent_txs.must_include == (tx1.hash,)
        assert set(parent_txs.can_include) == {dummy.hash, self._settings.GENESIS_TX1_HASH}

    def test_one_unconfirmed_one_confirmed(self) -> None:
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..11]
            b10 < dummy < tx1
            dummy <-- b11
        ''')

        b11, = artifacts.get_typed_vertices(('b11',), Block)
        dummy, tx1 = artifacts.get_typed_vertices(('dummy', 'tx1'), Transaction)

        artifacts.propagate_with(self.manager)
        assert dummy.get_metadata().first_block == b11.hash
        assert tx1.get_metadata().first_block is None

        parent_txs = self.manager.generate_parent_txs(timestamp=None)
        assert parent_txs.must_include == (tx1.hash,)
        assert parent_txs.can_include == [dummy.hash]

    def test_one_unconfirmed_zero_confirmed(self) -> None:
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..11]
            b10 < dummy
            dummy <-- b11
            dummy <-- tx1
        ''')

        b11, = artifacts.get_typed_vertices(('b11',), Block)
        dummy, tx1, = artifacts.get_typed_vertices(('dummy', 'tx1'), Transaction)

        artifacts.propagate_with(self.manager)
        assert dummy.get_metadata().first_block == b11.hash
        assert tx1.get_metadata().first_block is None

        parent_txs = self.manager.generate_parent_txs(timestamp=None)
        assert parent_txs.must_include == (tx1.hash,)
        assert set(parent_txs.can_include) == {dummy.hash, self._settings.GENESIS_TX1_HASH}

    def test_some_confirmed_txs(self) -> None:
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..11]
            b10 < dummy

            dummy < tx1 < tx2 < tx3 < tx4 < tx5

            dummy <-- tx2 <-- b11
            tx3 <-- tx4 <-- tx5 <-- b11
        ''')

        b11, = artifacts.get_typed_vertices(('b11',), Block)
        dummy, tx1, tx2, tx3, tx4, tx5 = artifacts.get_typed_vertices(
            ('dummy', 'tx1', 'tx2', 'tx3', 'tx4', 'tx5'), Transaction
        )

        artifacts.propagate_with(self.manager)
        assert tx1.get_metadata().first_block is None
        assert tx2.get_metadata().first_block == b11.hash
        assert tx3.get_metadata().first_block == b11.hash
        assert tx4.get_metadata().first_block == b11.hash
        assert tx5.get_metadata().first_block == b11.hash
        assert dummy.get_metadata().first_block == b11.hash

        parent_txs = self.manager.generate_parent_txs(timestamp=None)
        assert parent_txs.must_include == (tx1.hash,)
        assert parent_txs.can_include == [tx2.hash, tx5.hash]
