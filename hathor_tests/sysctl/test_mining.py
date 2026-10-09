#  Copyright 2024 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from hathor.sysctl import MiningManagerSysctl
from hathor.sysctl.exception import SysctlException
from hathor_tests.simulation.base import SimulatorTestCase


class MiningManagerSysctlTestCase(SimulatorTestCase):
    __test__ = True

    def test_submission_delay(self) -> None:
        manager = self.create_peer()
        sysctl = MiningManagerSysctl(manager)

        self.assertEqual(sysctl.get('submission_delay'), 0.0)

        sysctl.unsafe_set('submission_delay', 1.5)
        self.assertEqual(manager.mining_submission_delay, 1.5)
        self.assertEqual(sysctl.get('submission_delay'), 1.5)

        with self.assertRaises(SysctlException):
            sysctl.unsafe_set('submission_delay', -1)
        # value is unchanged after a rejected set
        self.assertEqual(manager.mining_submission_delay, 1.5)

    def test_ignore_submissions(self) -> None:
        manager = self.create_peer()
        sysctl = MiningManagerSysctl(manager)

        self.assertEqual(sysctl.get('ignore_submissions'), False)

        sysctl.unsafe_set('ignore_submissions', True)
        self.assertTrue(manager.ignore_mining_submissions)
        self.assertEqual(sysctl.get('ignore_submissions'), True)

        sysctl.unsafe_set('ignore_submissions', False)
        self.assertFalse(manager.ignore_mining_submissions)
