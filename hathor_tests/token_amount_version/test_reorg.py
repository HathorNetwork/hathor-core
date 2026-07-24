# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Consensus reorg handling for the token amount version V2 feature.

When a reorg moves the best chain below the `TOKEN_AMOUNT_V2` activation height, the feature deactivates and
every V2 transaction that was valid under the old (active) chain becomes invalid. The consensus algorithm
enforces this through `_token_amount_v2_rule`, applied to mempool transactions during the reorg
re-verification pass (`_compute_vertices_that_became_invalid`). The rule is selective: V2 transactions are
removal-eligible when the feature is inactive, while V1 transactions are always kept.

These tests drive the rule both directly (calling `_token_amount_v2_rule` on built V1/V2 transactions) and
end-to-end through the manager, mining a chain past activation with `FEATURE_ACTIVATION` criteria and then
reorging onto a heavier side chain below the activation height. They mirror the feature-reorg coverage in
`hathor_tests/nanocontracts/test_feature_activations.py`.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from hathor.daa import DAAFactory, TestMode
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.criteria import Criteria
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.feature_activation.settings import Settings as FeatureSettings
from hathor.transaction import Block, Transaction
from hathor.transaction.validation_state import ValidationState
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathorlib.conf.settings import FeatureSetting
from hathorlib.token_amount_version import TokenAmountVersion

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings
    from hathor.dag_builder.artifacts import DAGArtifacts


class TestReorgTokenAmountV2(unittest.TestCase):
    """Consensus reorg handling: deactivating the feature invalidates V2 transactions (`_token_amount_v2_rule`)."""

    def _prepare(self, settings: HathorSettings) -> None:
        """Build a manager (with all-weight DAA so a heavier side chain can be forced) and its helpers."""
        daa_factory = DAAFactory(settings=settings, test_mode=TestMode.TEST_ALL_WEIGHT)
        builder = self.get_builder(settings).set_daa_factory(daa_factory)
        self.manager = self.create_peer_from_builder(builder)
        self.consensus = self.manager.consensus_algorithm
        self.feature_service = self.manager.feature_service
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def _prepare_with_feature_activation(self) -> None:
        """Build a manager where `TOKEN_AMOUNT_V2` is gated by feature-activation criteria.

        With `evaluation_interval=4`, `default_threshold=3`, `start_height=4` and support signaling on blocks
        5, 6, 7, the feature is DEFINED before height 4, STARTED at 4, LOCKED_IN at 8, and ACTIVE at 12.
        """
        feature_settings = FeatureSettings(
            evaluation_interval=4,
            default_threshold=3,
            features={
                Feature.TOKEN_AMOUNT_V2: Criteria(
                    bit=0,
                    start_height=4,
                    timeout_height=12,
                    signal_support_by_default=True,
                    version='0.0.0',
                ),
            },
        )
        settings = self._settings.model_copy(update=dict(
            ENABLE_TOKEN_AMOUNT_V2=FeatureSetting.FEATURE_ACTIVATION,
            FEATURE_ACTIVATION=feature_settings,
        ))
        self._prepare(settings)

    def _propagate_to_active(self, artifacts: DAGArtifacts) -> None:
        """Propagate the main chain up to block 12, where `TOKEN_AMOUNT_V2` is ACTIVE."""
        artifacts.propagate_with(self.manager, up_to='b12')
        b12 = artifacts.get_typed_vertex('b12', Block)
        assert self.feature_service.get_state(block=b12, feature=Feature.TOKEN_AMOUNT_V2) == FeatureState.ACTIVE

    def _reset_vertex(self, vertex: Transaction) -> None:
        """Detach a vertex's cached metadata and child links so it can be relayed to the mempool again."""
        assert vertex.storage is not None
        vertex._metadata = None
        for child in vertex.get_children():
            vertex.storage.vertex_children.remove_child(vertex, child)

    def _build_v1_and_v2_txs(self) -> tuple[Transaction, Transaction]:
        """Build and propagate one V1 and one V2 transaction (feature enabled throughout)."""
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            b10 < dummy

            b1.out[0] <<< v1tx
            v1tx.out[0] = 1.00 HTR

            b2.out[0] <<< v2tx
            v2tx.out[0] = 1.00 HTR
            v2tx.token_amount_version = V2

            b12 < v1tx
            b12 < v2tx
            v1tx <-- b13
            v2tx <-- b13
        ''')
        artifacts.propagate_with(self.manager)
        v1tx = artifacts.get_typed_vertex('v1tx', Transaction)
        v2tx = artifacts.get_typed_vertex('v2tx', Transaction)
        assert v1tx.get_token_amount_version() == TokenAmountVersion.V1
        assert v2tx.get_token_amount_version() == TokenAmountVersion.V2
        return v1tx, v2tx

    def test_rule_active_is_noop(self) -> None:
        """Call `_token_amount_v2_rule(tx, is_active=True)` for a V1 and a V2 tx; assert both return True. Pins that
        an active feature never invalidates anything."""
        self._prepare(self._settings)
        v1tx, v2tx = self._build_v1_and_v2_txs()

        assert self.consensus._token_amount_v2_rule(v1tx, is_active=True) is True
        assert self.consensus._token_amount_v2_rule(v2tx, is_active=True) is True

    def test_rule_inactive_rejects_v2_allows_v1(self) -> None:
        """Call the rule with `is_active=False`: a V2 tx returns False (removal-eligible), a V1 tx returns True.
        Pins selective removal of only V2 txs."""
        self._prepare(self._settings)
        v1tx, v2tx = self._build_v1_and_v2_txs()

        assert self.consensus._token_amount_v2_rule(v1tx, is_active=False) is True
        assert self.consensus._token_amount_v2_rule(v2tx, is_active=False) is False

    def test_reorg_below_activation_removes_v2_tx(self) -> None:
        """Confirm a V2 tx while ACTIVE, then reorg to a heavier side chain whose new best block is below the
        activation height; assert the V2 tx becomes INVALID, is removed from storage, and is absent from the
        mempool tips. Direct analogue of other feature-reorg tests."""
        self._prepare_with_feature_activation()
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            blockchain b10 a[11..11]
            b10 < dummy < b11

            b5.signal_bits = 1
            b6.signal_bits = 1
            b7.signal_bits = 1

            b1.out[0] <<< v2tx
            v2tx.out[0] = 1.00 HTR
            v2tx.token_amount_version = V2

            b12 < v2tx
            v2tx <-- b13
            b13 < a11
            a11.weight = 20
        ''')
        v2tx = artifacts.get_typed_vertex('v2tx', Transaction)
        assert v2tx.get_token_amount_version() == TokenAmountVersion.V2

        self._propagate_to_active(artifacts)
        artifacts.propagate_with(self.manager, up_to='v2tx')
        assert v2tx.get_metadata().validation == ValidationState.FULL
        assert v2tx.get_metadata().voided_by is None

        artifacts.propagate_with(self.manager, up_to='b13')
        assert v2tx.get_metadata().first_block is not None

        # The side chain (best block a11, height 11) is below the activation height (12), so the feature
        # deactivates and the confirmed V2 tx becomes invalid and is removed.
        artifacts.propagate_with(self.manager, up_to='a11')
        assert v2tx.get_metadata().validation == ValidationState.INVALID
        assert not self.manager.tx_storage.transaction_exists(v2tx.hash)
        assert v2tx not in list(self.manager.tx_storage.iter_mempool_tips())

    def test_reorg_below_activation_keeps_v1_tx(self) -> None:
        """In the same deactivating reorg, a V1 tx present in the old chain/mempool remains valid and present after
        the reorg. Pins selectivity."""
        self._prepare_with_feature_activation()
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            blockchain b10 a[11..11]
            b10 < dummy < b11

            b5.signal_bits = 1
            b6.signal_bits = 1
            b7.signal_bits = 1

            b1.out[0] <<< v1tx
            v1tx.out[0] = 1.00 HTR

            b12 < v1tx
            v1tx <-- b13
            b13 < a11
            a11.weight = 20
        ''')
        v1tx = artifacts.get_typed_vertex('v1tx', Transaction)
        assert v1tx.get_token_amount_version() == TokenAmountVersion.V1

        self._propagate_to_active(artifacts)
        artifacts.propagate_with(self.manager, up_to='v1tx')
        artifacts.propagate_with(self.manager, up_to='b13')
        assert v1tx.get_metadata().first_block is not None

        # The same deactivating reorg (best block a11, height 11, below activation) returns the V1 tx to the
        # mempool but never invalidates it: the token-amount-V2 rule only targets V2 vertices.
        artifacts.propagate_with(self.manager, up_to='a11')
        assert v1tx.get_metadata().validation == ValidationState.FULL
        assert v1tx.get_metadata().voided_by is None
        assert self.manager.tx_storage.transaction_exists(v1tx.hash)
        assert v1tx in list(self.manager.tx_storage.iter_mempool_tips())

    def test_reorg_re_activation_re_allows_v2_tx(self) -> None:
        """After a deactivating reorg removes a V2 tx, extend the new chain back above activation, reset and re-relay
        the V2 tx, and assert it is re-accepted. Reorg direction = chain grows back above activation."""
        self._prepare_with_feature_activation()
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..13]
            blockchain b10 a[11..12]
            b10 < dummy < b11

            b5.signal_bits = 1
            b6.signal_bits = 1
            b7.signal_bits = 1

            b1.out[0] <<< v2tx
            v2tx.out[0] = 1.00 HTR
            v2tx.token_amount_version = V2

            b12 < v2tx
            v2tx <-- b13
            b13 < a11
            a11.weight = 20
        ''')
        v2tx = artifacts.get_typed_vertex('v2tx', Transaction)
        a12 = artifacts.get_typed_vertex('a12', Block)
        assert v2tx.get_token_amount_version() == TokenAmountVersion.V2

        self._propagate_to_active(artifacts)
        artifacts.propagate_with(self.manager, up_to='v2tx')
        artifacts.propagate_with(self.manager, up_to='b13')

        # Deactivating reorg to a11 (height 11) removes the V2 tx.
        artifacts.propagate_with(self.manager, up_to='a11')
        assert v2tx.get_metadata().validation == ValidationState.INVALID
        assert not self.manager.tx_storage.transaction_exists(v2tx.hash)

        # Growing the winning chain to a12 (height 12) re-activates the feature.
        artifacts.propagate_with(self.manager, up_to='a12')
        assert self.feature_service.get_state(block=a12, feature=Feature.TOKEN_AMOUNT_V2) == FeatureState.ACTIVE

        self._reset_vertex(v2tx)
        self.manager.vertex_handler.on_new_relayed_vertex(v2tx)
        assert v2tx.get_metadata().validation == ValidationState.FULL
        assert v2tx.get_metadata().voided_by is None
        assert self.manager.tx_storage.transaction_exists(v2tx.hash)
        assert v2tx in list(self.manager.tx_storage.iter_mempool_tips())

    def test_mempool_v2_tx_invalidated_on_deactivating_reorg(self) -> None:
        """An unconfirmed V2 tx in the mempool while ACTIVE is marked INVALID and removed after a reorg whose new
        best block is pre-activation; a V1 mempool tx survives. Pins mempool re-verification."""
        self._prepare_with_feature_activation()
        # A single V1 `funding` tx spends the only reward that is unlocked at the reorg height (block 1's, at
        # height 11) and feeds both mempool txs, so neither is removed by the reward-lock rule at height 11 —
        # isolating the token-amount-V2 rule as the sole cause of removal.
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..12]
            blockchain b10 a[11..11]
            b10 < dummy < b11

            b5.signal_bits = 1
            b6.signal_bits = 1
            b7.signal_bits = 1

            b1.out[0] <<< funding
            funding.out[0] = 1.00 HTR
            funding.out[1] = 1.00 HTR

            funding.out[0] <<< v1tx
            v1tx.out[0] = 1.00 HTR

            funding.out[1] <<< v2tx
            v2tx.out[0] = 1.00 HTR
            v2tx.token_amount_version = V2

            b12 < funding
            funding < v1tx
            funding < v2tx
            v1tx < a11
            v2tx < a11
            a11.weight = 20
        ''')
        v1tx = artifacts.get_typed_vertex('v1tx', Transaction)
        v2tx = artifacts.get_typed_vertex('v2tx', Transaction)
        assert v1tx.get_token_amount_version() == TokenAmountVersion.V1
        assert v2tx.get_token_amount_version() == TokenAmountVersion.V2

        self._propagate_to_active(artifacts)
        artifacts.propagate_with(self.manager, up_to_before='a11')

        # Both txs are unconfirmed mempool tips while the feature is ACTIVE.
        assert v1tx.get_metadata().validation == ValidationState.FULL
        assert v2tx.get_metadata().validation == ValidationState.FULL
        assert v1tx.get_metadata().first_block is None
        assert v2tx.get_metadata().first_block is None

        # Deactivating reorg (best block a11, height 11): the V2 mempool tx is invalidated and removed, the V1
        # mempool tx survives.
        artifacts.propagate_with(self.manager, up_to='a11')
        assert v2tx.get_metadata().validation == ValidationState.INVALID
        assert not self.manager.tx_storage.transaction_exists(v2tx.hash)
        assert v2tx not in list(self.manager.tx_storage.iter_mempool_tips())

        assert v1tx.get_metadata().validation == ValidationState.FULL
        assert v1tx.get_metadata().voided_by is None
        assert self.manager.tx_storage.transaction_exists(v1tx.hash)
        assert v1tx in list(self.manager.tx_storage.iter_mempool_tips())
