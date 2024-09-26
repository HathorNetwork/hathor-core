#  Copyright 2024 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from twisted.internet.defer import Deferred

from hathor.multiprocess.process_rpc import IpcConnection
from hathor.p2p.sync_v2.sync_process_rpc import MyIpcInterface, RequestB
from hathor.reactor import initialize_global_reactor, get_global_reactor


async def run_sub(subprocess_rpc: IpcConnection) -> None:
    response = await subprocess_rpc.call(RequestB(b='sub1'))
    response = await subprocess_rpc.call(RequestB(b='sub2'))


async def run_main() -> None:
    main_reactor = get_global_reactor()
    main_rpc = IpcConnection.fork(
        main_reactor=main_reactor,
        target=run_sub,
        subprocess_name='sub',
        main_interface=MyIpcInterface(),
        subprocess_interface=MyIpcInterface(),
    )
    response = await main_rpc.call(RequestB(b='main3'))
    response = await main_rpc.call(RequestB(b='main4'))


if __name__ == '__main__':
    reactor = initialize_global_reactor()
    reactor.callWhenRunning(lambda: Deferred.fromCoroutine(run_main()))
    reactor.run()
