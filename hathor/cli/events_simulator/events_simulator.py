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

from argparse import ArgumentParser, Namespace

DEFAULT_PORT = 8080


def create_parser() -> ArgumentParser:
    from hathor.cli.events_simulator.scenario import Scenario
    from hathor.cli.util import create_parser

    parser = create_parser()
    possible_scenarios = [scenario.name for scenario in Scenario]

    parser.add_argument('--scenario', help=f'One of {possible_scenarios}', type=str, required=True)
    parser.add_argument('--port', help='Port to run the WebSocket server', type=int, default=DEFAULT_PORT)

    return parser


def execute(args: Namespace) -> None:
    from hathor.cli.events_simulator.scenario import Scenario
    from hathor.event.storage import EventMemoryStorage
    from hathor.event.websocket import EventWebsocketFactory
    from hathor.util import reactor

    try:
        scenario = Scenario[args.scenario]
    except KeyError as e:
        possible_scenarios = [scenario.name for scenario in Scenario]
        raise ValueError(f'Invalid scenario "{args.scenario}". Choose one of {possible_scenarios}') from e

    storage = EventMemoryStorage()

    for event in scenario.value:
        storage.save_event(event)

    factory = EventWebsocketFactory(reactor, storage)

    factory.start()
    reactor.listenTCP(args.port, factory)
    reactor.run()


def main():
    parser = create_parser()
    args = parser.parse_args()
    execute(args)
