#  Copyright 2023 Hathor Labs
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

from unittest.mock import Mock

from hathor.conf.get_settings import get_global_settings
from hathor_cli.events_simulator.event_forwarding_websocket_factory import EventForwardingWebsocketFactory
from hathor_cli.events_simulator.events_simulator import create_parser, execute
from hathor_tests.test_memory_reactor_clock import TestMemoryReactorClock


def test_events_simulator() -> None:
    parser = create_parser()
    args = parser.parse_args(['--scenario', 'ONLY_LOAD'])
    reactor = TestMemoryReactorClock()

    execute(args, reactor)
    reactor.advance(1)

    factory = EventForwardingWebsocketFactory(
        simulator=Mock(),
        peer_id='test_peer_id',
        settings=get_global_settings(),
        reactor=reactor,
        event_storage=Mock()
    )
    protocol = factory.buildProtocol(Mock())

    assert protocol is not None
