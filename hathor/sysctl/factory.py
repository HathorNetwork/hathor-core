# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from twisted.internet.protocol import Factory

from hathor.sysctl.protocol import SysctlProtocol
from hathor.sysctl.runner import SysctlRunner


class SysctlFactory(Factory):
    def __init__(self, runner: SysctlRunner) -> None:
        self.runner = runner

    def buildProtocol(self, addr):
        return SysctlProtocol(self.runner)
