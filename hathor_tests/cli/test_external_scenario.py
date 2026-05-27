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

import pytest

_VALID_SIMULATE = '''\
def simulate(simulator, manager):
    simulator.run(60)
'''

_VALID_SIMULATE_WITH_SETTINGS = '''\
REWARD_SPEND_MIN_BLOCKS = 1

def simulate(simulator, manager):
    simulator.run(60)
'''

_CUSTOM_FUNCTION = '''\
def my_fn(simulator, manager):
    simulator.run(60)
'''

_WRONG_SETTINGS_TYPE = '''\
REWARD_SPEND_MIN_BLOCKS = "one"

def simulate(simulator, manager):
    pass
'''


@pytest.fixture
def scenario_file(tmp_path):
    """A minimal valid scenario file using the default function name."""
    f = tmp_path / 'my_scenario.py'
    f.write_text(_VALID_SIMULATE)
    return f


def test_loads_default_function_and_reward_spend(scenario_file):
    from unittest.mock import Mock
    from hathor_cli.events_simulator.external_scenario import ExternalScenario
    scenario = ExternalScenario(str(scenario_file))
    assert scenario.get_reward_spend_min_blocks() == 10
    # Verify function was actually loaded and is callable
    scenario.simulate(Mock(), Mock())


def test_custom_reward_spend_min_blocks(tmp_path):
    from hathor_cli.events_simulator.external_scenario import ExternalScenario
    f = tmp_path / 'scenario.py'
    f.write_text(_VALID_SIMULATE_WITH_SETTINGS)
    scenario = ExternalScenario(str(f))
    assert scenario.get_reward_spend_min_blocks() == 1


def test_custom_function_name(tmp_path):
    from unittest.mock import Mock
    from hathor_cli.events_simulator.external_scenario import ExternalScenario
    f = tmp_path / 'scenario.py'
    f.write_text(_CUSTOM_FUNCTION)
    # _CUSTOM_FUNCTION only defines my_fn (no simulate), so ExternalScenario with
    # default function_name would raise ValueError — this also implicitly tests that
    # the constructor correctly uses the provided function_name instead of falling back
    scenario = ExternalScenario(str(f), function_name='my_fn')
    assert scenario.get_reward_spend_min_blocks() == 10
    scenario.simulate(Mock(), Mock())


def test_file_not_found():
    from hathor_cli.events_simulator.external_scenario import ExternalScenario
    with pytest.raises(ValueError, match='External scenario file not found: /nonexistent/path.py'):
        ExternalScenario('/nonexistent/path.py')


def test_function_not_found(scenario_file):
    from hathor_cli.events_simulator.external_scenario import ExternalScenario
    with pytest.raises(ValueError, match="Function 'missing_fn' not found in"):
        ExternalScenario(str(scenario_file), function_name='missing_fn')


def test_invalid_reward_spend_min_blocks_type(tmp_path):
    from hathor_cli.events_simulator.external_scenario import ExternalScenario
    f = tmp_path / 'scenario.py'
    f.write_text(_WRONG_SETTINGS_TYPE)
    with pytest.raises(ValueError, match='REWARD_SPEND_MIN_BLOCKS must be an int, got str'):
        ExternalScenario(str(f))
