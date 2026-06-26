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

"""The feature gate `TransactionVerifier.verify_token_amount_version`, which runs in storage-less basic
verify.

The gate rejects a tx whose token amount version exceeds the version the feature allows, so it is a pure
function of the tx's version and `params.features.token_amount_version` (V1 when the feature is inactive,
V2 when active). Each test drives that truth table directly. The transactions themselves are built and
fully verified through the DAG builder, so the V1/V2 fixtures are real, valid vertices.

If any test here fails because of a production bug, the bug is not fixed here: the failing assertion is
kept, annotated with a comment explaining the production defect, and left failing. See the test plan in
`test_token_amount_version.py` for this convention.
"""

from __future__ import annotations

import dataclasses
import re

import pytest

from hathor.feature_activation.utils import Features
from hathor.transaction import Transaction
from hathor.verification.verification_params import VerificationParams
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathorlib.exceptions import TxValidationError
from hathorlib.token_amount_version import TokenAmountVersion


class TestTokenAmountVersionVerification(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()

        from hathor.simulator.patches import SimulatorCpuMiningService
        from hathor.simulator.simulator import _build_vertex_verifiers

        builder = self.get_builder() \
            .set_vertex_verifiers_builder(_build_vertex_verifiers) \
            .set_cpu_mining_service(SimulatorCpuMiningService())

        self.manager = self.create_peer_from_builder(builder)
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)
        self.tx_verifier = self.manager.verification_service.verifiers.tx

        # The feature is enabled in unittests.yml, so both fixtures pass full verification when propagated.
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            b10 < dummy

            b1.out[0] <<< tx_v1
            tx_v1.out[0] = 100 HTR

            b2.out[0] <<< tx_v2
            tx_v2.out[0] = 100 HTR
            tx_v2.token_amount_version = V2

            b11 < tx_v1
            b12 < tx_v2
            tx_v1 <-- tx_v2 <-- b13
        ''')
        artifacts.propagate_with(self.manager)
        self.tx_v1, self.tx_v2 = artifacts.get_typed_vertices(('tx_v1', 'tx_v2'), Transaction)

        assert self.tx_v1.get_token_amount_version() == TokenAmountVersion.V1
        assert self.tx_v2.get_token_amount_version() == TokenAmountVersion.V2

    @staticmethod
    def _params(feature_version: TokenAmountVersion) -> VerificationParams:
        """Verification params whose only relevant field is the version the feature allows."""
        features = dataclasses.replace(Features.all_enabled(), token_amount_version=feature_version)
        return VerificationParams(nc_block_root_id=None, features=features)

    def test_v1_tx_accepted_when_feature_inactive(self) -> None:
        """The gate never rejects V1: with the feature inactive (1 > 1 is false) the V1 tx passes the gate,
        and it passed full verification when propagated."""
        self.tx_verifier.verify_token_amount_version(self.tx_v1, self._params(TokenAmountVersion.V1))
        assert self.tx_v1.get_metadata().validation.is_valid()
        assert self.tx_v1.get_metadata().voided_by is None

    def test_v1_tx_accepted_when_feature_active(self) -> None:
        """Activation never forces V2: with the feature active (1 > 2 is false) the V1 tx is still
        accepted, preserving backward compatibility."""
        self.tx_verifier.verify_token_amount_version(self.tx_v1, self._params(TokenAmountVersion.V2))
        assert self.tx_v1.get_metadata().validation.is_valid()
        assert self.tx_v1.get_metadata().voided_by is None

    def test_v2_tx_rejected_when_feature_inactive(self) -> None:
        """The core gating case: with the feature inactive a V2 tx is rejected with the exact
        `TxValidationError('invalid token amount version: V2')`."""
        with pytest.raises(TxValidationError, match=re.escape('invalid token amount version: V2')):
            self.tx_verifier.verify_token_amount_version(self.tx_v2, self._params(TokenAmountVersion.V1))

    def test_v2_tx_accepted_when_feature_active(self) -> None:
        """The boundary equality accepts: with the feature active (2 > 2 is false) the V2 tx passes the
        gate, and it passed full verification when propagated."""
        self.tx_verifier.verify_token_amount_version(self.tx_v2, self._params(TokenAmountVersion.V2))
        assert self.tx_v2.get_metadata().validation.is_valid()
        assert self.tx_v2.get_metadata().voided_by is None
