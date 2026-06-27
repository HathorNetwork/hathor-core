# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from twisted.internet.testing import MemoryReactorClock


class TestMemoryReactorClock(MemoryReactorClock):
    __test__ = False

    def run(self):
        """
        We have to override MemoryReactor.run() because the original Twisted implementation weirdly calls stop() inside
        run(), and we need the reactor running during our tests.
        """
        self.running = True
