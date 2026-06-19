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

from pathlib import Path
from unittest.mock import Mock

import pytest

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


def test_execute_with_external_file(tmp_path: 'Path') -> None:
    """execute() works end-to-end when --file is used instead of --scenario."""
    scenario_code = 'def simulate(simulator, manager):\n    simulator.run(60)\n'
    scenario_path = tmp_path / 'my_scenario.py'
    scenario_path.write_text(scenario_code)

    parser = create_parser()
    args = parser.parse_args(['--file', str(scenario_path)])
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


def test_execute_with_external_file_and_custom_function(tmp_path: 'Path') -> None:
    """execute() uses the function named by --function when --file is provided."""
    scenario_code = 'def my_fn(simulator, manager):\n    simulator.run(60)\n'
    scenario_path = tmp_path / 'my_scenario.py'
    scenario_path.write_text(scenario_code)

    parser = create_parser()
    args = parser.parse_args(['--file', str(scenario_path), '--function', 'my_fn'])
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
    assert factory.buildProtocol(Mock()) is not None


def test_parser_rejects_scenario_and_file_together() -> None:
    """argparse enforces that --scenario and --file are mutually exclusive."""
    parser = create_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(['--scenario', 'ONLY_LOAD', '--file', './my_scenario.py'])


def test_execute_rejects_function_without_file() -> None:
    """execute() raises ValueError when --function is given without --file."""
    parser = create_parser()
    args = parser.parse_args(['--scenario', 'ONLY_LOAD', '--function', 'my_fn'])
    reactor = TestMemoryReactorClock()
    with pytest.raises(ValueError, match='--function can only be used together with --file'):
        execute(args, reactor)


def test_events_simulator_shielded_outputs_scenario_smoke() -> None:
    """execute() runs the built-in SHIELDED_OUTPUTS scenario end-to-end."""
    parser = create_parser()
    args = parser.parse_args(['--scenario', 'SHIELDED_OUTPUTS'])
    reactor = TestMemoryReactorClock()

    execute(args, reactor)
    reactor.advance(1)

    factory = EventForwardingWebsocketFactory(
        simulator=Mock(),
        peer_id='test_peer_id',
        settings=get_global_settings(),
        reactor=reactor,
        event_storage=Mock(),
    )
    assert factory.buildProtocol(Mock()) is not None


def test_shielded_outputs_scenario_produces_accepted_shielded_tx() -> None:
    """The scenario produces a shielded tx that the node accepts."""
    from hathor.conf.settings import FeatureSetting
    from hathor.simulator import Simulator
    from hathor.transaction import Transaction
    from hathor_cli.events_simulator.scenario import Scenario, simulate_shielded_outputs

    settings = get_global_settings().model_copy(update={
        'ENABLE_SHIELDED_TRANSACTIONS': FeatureSetting.ENABLED,
        'REWARD_SPEND_MIN_BLOCKS': Scenario.SHIELDED_OUTPUTS.get_reward_spend_min_blocks(),
    })
    simulator = Simulator(12345)
    simulator.start()
    try:
        builder = simulator.get_default_builder().set_settings(settings)
        manager = simulator.create_peer(builder)
        artifacts = simulate_shielded_outputs(simulator, manager)

        assert artifacts is not None
        shielded = [
            v for _, v in artifacts.list
            if isinstance(v, Transaction) and v.has_shielded_outputs()
        ]
        assert shielded, 'scenario produced no shielded tx'
        tx = shielded[0]
        assert not tx.get_metadata().voided_by
        assert len(tx.shielded_outputs) >= 2
    finally:
        simulator.stop()
