from unittest.mock import MagicMock, Mock, call

from hathor.sysctl import HathorManagerSysctl
from hathor_tests.simulation.base import SimulatorTestCase


class HathorManagerSysctlTestCase(SimulatorTestCase):
    __test__ = True

    def test_profiler(self):
        manager = self.create_peer()
        sysctl = HathorManagerSysctl(manager)

        status = sysctl.get('profiler.status')
        self.assertEqual(status, (0, 0))

        manager.start_profiler = Mock(wraps=manager.start_profiler)
        self.assertEqual(manager.start_profiler.call_count, 0)
        sysctl.unsafe_set('profiler.start', False)
        self.assertEqual(manager.start_profiler.call_count, 1)

        manager.reactor.advance(100)
        status = sysctl.get('profiler.status')
        self.assertEqual(status, (1, 100))

        manager.stop_profiler = Mock(wraps=manager.stop_profiler)
        manager.profiler = MagicMock()  # prevents a call to profiler.dump_stats()
        self.assertEqual(manager.stop_profiler.call_count, 0)
        sysctl.unsafe_set('profiler.stop', '/path/to/dump')
        self.assertEqual(manager.stop_profiler.call_count, 1)
        self.assertEqual(manager.stop_profiler.call_args, call(save_to='/path/to/dump',))

        status = sysctl.get('profiler.status')
        self.assertEqual(status, (0, 0))
