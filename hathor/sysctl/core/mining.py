# Copyright 2024 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from hathor.manager import HathorManager
from hathor.sysctl.exception import SysctlException
from hathor.sysctl.sysctl import Sysctl, signal_handler_safe


class MiningManagerSysctl(Sysctl):
    """Runtime controls for block submission (orphan-block mitigation, internal-issues#535)."""

    def __init__(self, manager: HathorManager) -> None:
        super().__init__()
        self.manager = manager
        self.register(
            'submission_delay',
            self.get_submission_delay,
            self.set_submission_delay,
        )
        self.register(
            'ignore_submissions',
            self.get_ignore_submissions,
            self.set_ignore_submissions,
        )

    def get_submission_delay(self) -> float:
        """Return the delay (in seconds) applied before processing a submitted block."""
        return self.manager.mining_submission_delay

    @signal_handler_safe
    def set_submission_delay(self, value: float) -> None:
        """Change the delay (in seconds) applied before processing a submitted block."""
        if value < 0:
            raise SysctlException('value must be >= 0')
        self.manager.mining_submission_delay = value

    def get_ignore_submissions(self) -> bool:
        """Return whether all block submissions are being rejected."""
        return self.manager.ignore_mining_submissions

    @signal_handler_safe
    def set_ignore_submissions(self, value: bool) -> None:
        """Enable or disable rejecting all block submissions (operational kill switch)."""
        self.manager.ignore_mining_submissions = value
