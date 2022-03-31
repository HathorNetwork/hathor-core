# Copyright 2021 Hathor Labs
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

from argparse import Namespace

from hathor.cli.run_node import RunNode


class QuickTest(RunNode):

    def register_resources(self, args: Namespace) -> None:
        self.log.info('patching on_new_tx to quit on success')
        orig_on_new_tx = self.manager.on_new_tx

        def patched_on_new_tx(*args, **kwargs):
            res = orig_on_new_tx(*args, **kwargs)
            if res:
                self.log.info('sucessfully added a tx, exit now')
                self.manager.connections.disconnect_all_peers(force=True)
                self.reactor.stop()
            return res
        self.manager.on_new_tx = patched_on_new_tx

        timeout = 300
        self.log.info('exit with error code if it take too long', timeout=timeout)

        def exit_with_error():
            import sys
            self.log.error('took too long to get a tx, exit with error')
            self.manager.connections.disconnect_all_peers(force=True)
            self.reactor.stop()
            sys.exit(1)
        self.reactor.callLater(timeout, exit_with_error)


def main():
    QuickTest().run()
