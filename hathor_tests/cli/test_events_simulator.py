# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

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
