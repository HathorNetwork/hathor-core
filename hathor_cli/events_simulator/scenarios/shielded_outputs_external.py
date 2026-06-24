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

"""Example external scenario: a transaction with shielded outputs.

Run with:
    poetry run hathor-cli events_simulator \\
        --file hathor_cli/events_simulator/scenarios/shielded_outputs_external.py

Requires ENABLE_SHIELDED_TRANSACTIONS, which the events simulator enables by default.
"""

# The events simulator reads this to set REWARD_SPEND_MIN_BLOCKS for the run.
REWARD_SPEND_MIN_BLOCKS = 10


def simulate(simulator, manager):
    from hathor.simulator.utils import create_dag_builder

    dag_builder = create_dag_builder(manager)
    artifacts = dag_builder.build_from_str('''
        blockchain genesis b[1..50]
        b1.out[0] <<< tx1
        b30 < tx1
        b30 < dummy

        tx1.out[0] = 100 HTR [wallet1]
        tx1.sout[0] = 30 HTR [wallet2]
        tx1.sout[1] = 20 HTR [wallet3] [full-shielded]
    ''')
    artifacts.propagate_with(manager)
    simulator.run(60)

    return artifacts
