from typing import Optional

from hathor.manager import HathorManager
from hathor.simulator import Simulator
from hathor.types import VertexId
from hathor_tests import unittest


class SimulatorTestCase(unittest.TestCase):
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
        soft_voided_tx_ids: set[VertexId] = set(),
        simulator: Simulator | None = None
    ) -> HathorManager:
        if simulator is None:
            simulator = self.simulator

        builder = simulator.get_default_builder() \
            .set_peer(self.get_random_peer_from_pool(rng=simulator.rng)) \
            .set_soft_voided_tx_ids(soft_voided_tx_ids)

        return simulator.create_peer(builder)
