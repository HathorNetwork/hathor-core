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

from hathor.dag_builder.tokenizer import TokenType
from hathorlib.transaction.shielded_tx_output import OutputMode


def test_set_shielded_output_populates_node() -> None:
    from hathor.dag_builder.builder import DAGBuilder

    # set_shielded_output only touches the in-memory node graph, so we can call it
    # on a bare DAGBuilder instance constructed without running __init__.
    builder = DAGBuilder.__new__(DAGBuilder)
    builder._nodes = {}

    builder.set_shielded_output('tx1', 0, 30, 'HTR', ['[wallet1]'])
    builder.set_shielded_output('tx1', 1, 10, 'HTR', ['[wallet2]', '[full-shielded]'])

    node = builder._nodes['tx1']
    assert len(node.shielded_outputs) == 2

    s0 = node.shielded_outputs[0]
    assert s0 is not None
    assert (s0.amount, s0.token, s0.mode) == (30, 'HTR', OutputMode.AMOUNT_ONLY)

    s1 = node.shielded_outputs[1]
    assert s1 is not None
    assert (s1.amount, s1.token, s1.mode) == (10, 'HTR', OutputMode.FULLY_SHIELDED)


def test_parse_tokens_dispatches_shielded_output() -> None:
    from hathor.dag_builder.builder import DAGBuilder

    builder = DAGBuilder.__new__(DAGBuilder)
    builder._nodes = {}

    tokens = [(TokenType.SHIELDED_OUTPUT, ('tx1', 0, 30, 'HTR', ['[wallet1]']))]
    builder.parse_tokens(iter(tokens))

    node = builder._nodes['tx1']
    assert node.shielded_outputs[0].mode == OutputMode.AMOUNT_ONLY
