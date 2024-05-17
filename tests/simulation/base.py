from typing import Optional

from hathor.builder import SyncSupportLevel
from hathor.manager import HathorManager
from hathor.simulator import Simulator
from hathor.types import VertexId
from tests import unittest


class SimulatorTestCase(unittest.TestCase):
    __test__ = False

    seed_config: Optional[int] = None

    def setUp(self) -> None:
        super().setUp()

        self.simulator = Simulator(self.seed_config)
        self.simulator.start()

        print('-'*30)
        print('Simulation seed config:', self.simulator.seed)
        print('-'*30)

    def tearDown(self) -> None:
        self.simulator.stop()
        super().tearDown()

    def create_peer(  # type: ignore[override]
        self,
        enable_sync_v1: bool | None = None,
        enable_sync_v2: bool | None = None,
        soft_voided_tx_ids: set[VertexId] = set(),
        simulator: Simulator | None = None
    ) -> HathorManager:
        if enable_sync_v1 is None:
            assert hasattr(self, '_enable_sync_v1'), ('`_enable_sync_v1` has no default by design, either set one on '
                                                      'the test class or pass `enable_sync_v1` by argument')
            enable_sync_v1 = self._enable_sync_v1
        if enable_sync_v2 is None:
            assert hasattr(self, '_enable_sync_v2'), ('`_enable_sync_v2` has no default by design, either set one on '
                                                      'the test class or pass `enable_sync_v2` by argument')
            enable_sync_v2 = self._enable_sync_v2
        assert enable_sync_v1 or enable_sync_v2, 'enable at least one sync version'
        sync_v1_support = SyncSupportLevel.ENABLED if enable_sync_v1 else SyncSupportLevel.DISABLED
        sync_v2_support = SyncSupportLevel.ENABLED if enable_sync_v2 else SyncSupportLevel.DISABLED
        if simulator is None:
            simulator = self.simulator

        builder = simulator.get_default_builder() \
            .set_peer_id(self.get_random_peer_id_from_pool(rng=simulator.rng)) \
            .set_soft_voided_tx_ids(soft_voided_tx_ids) \
            .set_sync_v1_support(sync_v1_support) \
            .set_sync_v2_support(sync_v2_support)

        return simulator.create_peer(builder)
