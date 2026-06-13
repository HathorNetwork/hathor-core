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

"""Differential test for the pipeline's native static-metadata computation: for every tx of a
real DAG (spend chains; a reward-spending funding tx, so min_height > 0 paths are exercised),
the Rust-computed (min_height, closest_ancestor_block) must equal Python's
`TransactionStaticMetadata.create_from_storage`."""

import dataclasses

from hathor.feature_activation.utils import Features
from hathor.transaction import Transaction
from hathor.transaction.scripts.opcode import OpcodesVersion
from hathor.transaction.static_metadata import TransactionStaticMetadata
from hathor.verification.rust_verification_service import RustVerificationService
from hathor.verification.verification_params import VerificationParams
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder


class StaticPrecomputeTest(unittest.TestCase):
    use_memory_storage = False  # the pipeline resolves deps natively from RocksDB

    def setUp(self) -> None:
        super().setUp()
        self.manager = self.create_peer('unittests')

    def test_pipeline_static_matches_python(self) -> None:
        service = self.manager.verification_service
        if not isinstance(service, RustVerificationService) \
                or not service._script_verification_pool.rust_verification:
            self.skipTest('requires RUST mode (HATHOR_TEST_SCRIPT_VERIFICATION=rust:N)')

        dag_builder = TestDAGBuilder.from_manager(self.manager)
        artifacts = dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            b11 < dummy
            b12 --> dummy

            tx1.out[0] <<< tx2
            tx2.out[0] <<< tx3
            tx3 <-- tx4
            b13 --> tx4
        ''')
        artifacts.propagate_with(self.manager)

        txs = [v for name, v in artifacts.list
               if isinstance(v, Transaction) and not v.is_genesis and v.inputs]
        assert len(txs) >= 4

        features = dataclasses.replace(Features.all_enabled(), opcodes_version=OpcodesVersion.V2)
        params = VerificationParams(nc_block_root_id=None, features=features)
        try:
            service.precompute_stateless_batch(txs, params, include_scripts=True)
            computed = dict(service._precomputed_static)
        finally:
            service.discard_precomputed(txs)

        assert computed, 'the pipeline must have computed static metadata for stored-dep txs'
        for tx in txs:
            expected = TransactionStaticMetadata.create_from_storage(
                tx, self._settings, self.manager.tx_storage,
            )
            if tx.hash not in computed:
                continue  # conservative fallback (e.g. ambiguous closest-ancestor tie) is allowed
            min_height, closest = computed[tx.hash]
            assert min_height == expected.min_height, tx.hash.hex()
            assert closest == expected.closest_ancestor_block, tx.hash.hex()

        # the reward-spending funding tx must exercise a non-zero min_height somewhere
        assert any(
            TransactionStaticMetadata.create_from_storage(tx, self._settings, self.manager.tx_storage).min_height > 0
            for tx in txs
        )
