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

import os
from argparse import ArgumentParser, Namespace

from autobahn.twisted.resource import WebSocketResource
from structlog import get_logger
from twisted.web.resource import Resource
from twisted.web.server import Site

DEFAULT_PORT = 8080

logger = get_logger()


def create_parser() -> ArgumentParser:
    from hathor.cli.events_simulator.scenario import Scenario
    from hathor.cli.util import create_parser

    parser = create_parser()
    possible_scenarios = [scenario.name for scenario in Scenario]

    parser.add_argument('--scenario', help=f'One of {possible_scenarios}', type=str, required=True)
    parser.add_argument('--port', help='Port to run the WebSocket server', type=int, default=DEFAULT_PORT)
    parser.add_argument('--seed', help='The seed used to create simulated events', type=int)

    return parser


def execute(args: Namespace) -> None:
    from hathor.conf import UNITTESTS_SETTINGS_FILEPATH
    os.environ['HATHOR_CONFIG_YAML'] = UNITTESTS_SETTINGS_FILEPATH
    from hathor.cli.events_simulator.event_forwarding_websocket_factory import EventForwardingWebsocketFactory
    from hathor.cli.events_simulator.scenario import Scenario
    from hathor.simulator import Simulator
    from hathor.util import reactor

    try:
        scenario = Scenario[args.scenario]
    except KeyError as e:
        possible_scenarios = [scenario.name for scenario in Scenario]
        raise ValueError(f'Invalid scenario "{args.scenario}". Choose one of {possible_scenarios}') from e

    log = logger.new()
    simulator = Simulator(args.seed)
    simulator.start()
    builder = simulator.get_default_builder() \
        .disable_full_verification() \
        .enable_event_queue()

    manager = simulator.create_peer(builder)
    event_ws_factory = manager._event_manager._event_ws_factory
    assert event_ws_factory is not None

    forwarding_ws_factory = EventForwardingWebsocketFactory(
        simulator=simulator,
        reactor=reactor,
        event_storage=event_ws_factory._event_storage
    )

    manager._event_manager._event_ws_factory = forwarding_ws_factory

    root = Resource()
    api = Resource()
    root.putChild(b'v1a', api)
    api.putChild(b'event_ws', WebSocketResource(forwarding_ws_factory))
    site = Site(root)

    log.info('Started simulating events', scenario=args.scenario, seed=simulator.seed)

    forwarding_ws_factory.start(stream_id='simulator')
    scenario.simulate(simulator, manager)
    reactor.listenTCP(args.port, site)
    reactor.run()


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
