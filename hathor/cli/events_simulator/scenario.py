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

from enum import Enum

from hathor.cli.events_simulator.scenarios.only_load_events import ONLY_LOAD_EVENTS
from hathor.cli.events_simulator.scenarios.reorg_events import REORG_EVENTS
from hathor.cli.events_simulator.scenarios.single_chain_blocks_and_transactions_events import (
    SINGLE_CHAIN_BLOCKS_AND_TRANSACTIONS_EVENTS,
)
from hathor.cli.events_simulator.scenarios.single_chain_one_block_events import SINGLE_CHAIN_ONE_BLOCK_EVENTS


class Scenario(Enum):
    """
    NOTE: The lists of events used in each scenario's enum value below were obtained from the tests in
    tests.event.test_simulation.TestEventSimulation
    """
    ONLY_LOAD = ONLY_LOAD_EVENTS
    SINGLE_CHAIN_ONE_BLOCK = SINGLE_CHAIN_ONE_BLOCK_EVENTS
    SINGLE_CHAIN_BLOCKS_AND_TRANSACTIONS = SINGLE_CHAIN_BLOCKS_AND_TRANSACTIONS_EVENTS
    REORG = REORG_EVENTS
