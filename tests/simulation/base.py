from typing import Optional

from hathor.simulator import Simulator
from tests import unittest


class SimulatorTestCase(unittest.TestCase):
    __test__ = False

    seed_config: Optional[int] = None

    def setUp(self):
        super().setUp()

        self.simulator = Simulator(self.seed_config)
        self.simulator.start()

        print('-'*30)
        print('Simulation seed config:', self.simulator.seed)
        print('-'*30)

    def tearDown(self):
        self.simulator.stop()
        super().tearDown()

    def create_peer(self, enable_sync_v1=None, enable_sync_v2=None, soft_voided_tx_ids=None, simulator=None):
        if enable_sync_v1 is None:
            assert hasattr(self, '_enable_sync_v1'), ('`_enable_sync_v1` has no default by design, either set one on '
                                                      'the test class or pass `enable_sync_v1` by argument')
            enable_sync_v1 = self._enable_sync_v1
        if enable_sync_v2 is None:
            assert hasattr(self, '_enable_sync_v2'), ('`_enable_sync_v2` has no default by design, either set one on '
                                                      'the test class or pass `enable_sync_v2` by argument')
            enable_sync_v2 = self._enable_sync_v2
        assert enable_sync_v1 or enable_sync_v2, 'enable at least one sync version'
        if simulator is None:
            simulator = self.simulator
        return simulator.create_peer(
            peer_id=self.get_random_peer_id_from_pool(rng=simulator.rng),
            soft_voided_tx_ids=soft_voided_tx_ids,
            enable_sync_v1=enable_sync_v1,
            enable_sync_v2=enable_sync_v2,
        )
