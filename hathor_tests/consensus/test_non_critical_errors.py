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

from typing import Any

import pytest
from structlog.testing import capture_logs

from hathor.transaction import Transaction
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder


class TestNonCriticalErrors(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        builder = self.get_builder().enable_address_index()
        self.manager = self.create_peer_from_builder(builder)
        self.indexes = self.manager.tx_storage.indexes
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def test_error_on_critical_index(self) -> None:
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..10]
            b10 < dummy

            tx1 < tx2 < tx3 < tx4
        ''')

        tx1, tx2, tx3, tx4 = artifacts.get_typed_vertices(('tx1', 'tx2', 'tx3', 'tx4'), Transaction)
        artifacts.propagate_with(self.manager, up_to='tx2')

        def update(*args: Any, **kwargs: Any) -> None:
            raise Exception('test error')

        self.indexes.mempool_tips.update = update  # type: ignore[method-assign]

        with pytest.raises(SystemExit), capture_logs() as log_list:
            artifacts.propagate_with(self.manager)

        logs = '\n'.join(map(str, log_list))
        assert 'unexpected exception in on_new_vertex()' in logs
        assert (
            'Critical failure occurred, causing the full node to halt execution. Manual intervention is required.'
        ) in logs

        assert tx1.get_metadata().validation.is_fully_connected()
        assert tx1.get_metadata().voided_by is None

        assert tx2.get_metadata().validation.is_fully_connected()
        assert tx2.get_metadata().voided_by is None

        assert tx3.get_metadata().validation.is_fully_connected()
        assert tx3.get_metadata().voided_by == {self._settings.CONSENSUS_FAIL_ID}

        assert tx4.get_metadata().validation.is_initial()
        assert tx4.get_metadata().voided_by is None

    def test_error_on_non_critical_index(self) -> None:
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..10]
            b10 < dummy

            tx1 < tx2 < tx3 < tx4
        ''')

        tx1, tx2, tx3, tx4 = artifacts.get_typed_vertices(('tx1', 'tx2', 'tx3', 'tx4'), Transaction)
        artifacts.propagate_with(self.manager, up_to='tx2')

        def add_tx(*args: Any, **kwargs: Any) -> None:
            raise Exception('test error')

        assert self.indexes.addresses is not None
        self.indexes.addresses.add_tx = add_tx  # type: ignore[method-assign]

        with capture_logs() as log_list:
            artifacts.propagate_with(self.manager)

        logs = '\n'.join(map(str, log_list))
        assert 'ignoring error in non-critical code' in logs

        assert tx1.get_metadata().validation.is_fully_connected()
        assert tx1.get_metadata().voided_by is None

        assert tx2.get_metadata().validation.is_fully_connected()
        assert tx2.get_metadata().voided_by is None

        assert tx3.get_metadata().validation.is_fully_connected()
        assert tx3.get_metadata().voided_by is None

        assert tx4.get_metadata().validation.is_fully_connected()
        assert tx4.get_metadata().voided_by is None
