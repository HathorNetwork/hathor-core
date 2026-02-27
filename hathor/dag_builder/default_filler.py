# Copyright 2024 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

from collections import defaultdict

from hathor.conf.settings import HathorSettings
from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.dag_builder.builder import DAGBuilder, DAGInput, DAGNode, DAGNodeType, DAGOutput
from hathor.transaction.token_info import TokenVersion
from hathor.transaction.util import get_deposit_token_deposit_amount


class DefaultFiller:
    """This filler applies a strategy to complete a DAG.

    The strategy is to create a dummy transaction that spends from the genesis block
    and has one output for each transaction that needs HTR tokens.

    For custom tokens, it creates an output on the TokenCreationTransaction of the token
    for each transaction that needs that custom token.
    """

    def __init__(self, builder: DAGBuilder, settings: HathorSettings, daa: DifficultyAdjustmentAlgorithm) -> None:
        self._builder = builder
        self._settings = settings
        self._daa = daa

        # create the dummy and genesis nodes before builder.build() is called
        genesis_block = self._get_or_create_node('genesis_block', default_type=DAGNodeType.Genesis)
        if len(genesis_block.outputs) == 0:
            genesis_block.outputs.append(DAGOutput(self._settings.GENESIS_TOKENS, 'HTR', {}))
        self._get_or_create_node('genesis_1', default_type=DAGNodeType.Genesis)
        self._get_or_create_node('genesis_2', default_type=DAGNodeType.Genesis)
        self._get_or_create_node('dummy', default_type=DAGNodeType.Transaction)

    def _get_node(self, name: str) -> DAGNode:
        """Get a node."""
        return self._builder._get_node(name)

    def _get_or_create_node(self, name: str, *, default_type: DAGNodeType = DAGNodeType.Unknown) -> DAGNode:
        """Get a node."""
        return self._builder._get_or_create_node(name, default_type=default_type)

    @staticmethod
    def get_next_index(outputs: list[DAGOutput | None]) -> int:
        """Return the next index to place a new output.

        If all slots are full, it creates a new slot at the end."""
        for i, txout in enumerate(outputs):
            if txout is None:
                return i
        outputs.append(None)
        return len(outputs) - 1

    def fill_parents(self, node: DAGNode, *, target: int = 2, candidates: list[str] | None = None) -> None:
        """Fill parents of a vertex.

        Note: We shouldn't use the DAG transactions because it would confirm them, violating the DAG description."""
        # What's the best way to fill the parents?
        # Should we use dummy transactions so it is unrelated to the other transactions?
        if node.type == DAGNodeType.Genesis:
            return
        if len(node.parents) >= target:
            return

        if not candidates:
            candidates = [
                'genesis_1',
                'genesis_2',
            ]
        for pi in candidates:
            if len(node.parents) >= target:
                break
            node.parents.add(pi)

    def find_txin(self, amount: int, token: str) -> DAGInput:
        """Create a DAGInput for an amount of tokens."""
        if token == 'HTR':
            dummy = self._get_node('dummy')
            dummy.inputs.add(DAGInput('genesis_block', 0))
            self.fill_parents(dummy)

            # TODO no more than 255 inputs
            index = self.get_next_index(dummy.outputs)
            dummy.outputs[index] = DAGOutput(amount, token, {'_origin': 'f1'})
            return DAGInput('dummy', index)

        else:
            token_node = self._get_or_create_node(token)
            index = self.get_next_index(token_node.outputs)
            token_node.outputs[index] = DAGOutput(amount, token, {'_origin': 'f2'})
            return DAGInput(token, index)

    def calculate_balance(self, node: DAGNode) -> dict[str, int]:
        """Calculate the balance for each token in a node.

        balance = sum(outputs) - sum(inputs)
        """
        ins: defaultdict[str, int] = defaultdict(int)
        for tx_name, index in node.inputs:
            node2 = self._get_or_create_node(tx_name)
            txout = node2.outputs[index]
            assert txout is not None
            ins[txout.token] += txout.amount

        outs: defaultdict[str, int] = defaultdict(int)
        for txout in node.outputs:
            assert txout is not None
            outs[txout.token] += txout.amount

        keys = set(ins.keys()) | set(outs.keys()) | set(node.balances.keys())
        balance = {}
        for key in keys:
            balance[key] = outs.get(key, 0) - ins.get(key, 0)

        return balance

    def _account_for_shielded_fee(self, node: DAGNode) -> None:
        """Subtract shielded output fees from the node's HTR balance."""
        fee = 0
        for txout in node.outputs:
            if txout is None:
                continue
            _, _, attrs = txout
            if attrs.get('full-shielded'):
                fee += self._settings.FEE_PER_FULL_SHIELDED_OUTPUT
            elif attrs.get('shielded'):
                fee += self._settings.FEE_PER_AMOUNT_SHIELDED_OUTPUT
        if fee > 0:
            node.balances['HTR'] = node.balances.get('HTR', 0) - fee

    def balance_node_inputs_and_outputs(self, node: DAGNode) -> None:
        """Balance the inputs and outputs of a node."""
        balance = self.calculate_balance(node)

        for key, diff in balance.items():
            target = node.balances.get(key, 0)
            diff -= target
            if diff < 0:
                index = self.get_next_index(node.outputs)
                node.outputs[index] = DAGOutput(abs(diff), key, {'_origin': 'f3'})
            elif diff > 0:
                txin = self.find_txin(diff, key)
                node.inputs.add(txin)

    def run(self) -> None:
        """Run the filler."""
        for node in self._builder._nodes.values():
            if node.type == DAGNodeType.Unknown:
                node.type = DAGNodeType.Transaction

        for node in self._builder._nodes.values():
            if node.type == DAGNodeType.Genesis:
                continue
            if node.name == 'dummy':
                continue
            if not node.inputs and not node.outputs:
                if node.type == DAGNodeType.Block:
                    continue
                node.outputs.append(DAGOutput(1, 'HTR', {'_origin': 'f4'}))
            for i in range(len(node.outputs)):
                txout = node.outputs[i]
                if txout is None:
                    node.outputs[i] = DAGOutput(1, 'HTR', {'_origin': 'f5'})
                elif txout.amount == 0:
                    assert not txout.token
                    assert not txout.attrs
                    node.outputs[i] = DAGOutput(1, 'HTR', {'_origin': 'f6'})

        tokens = []
        for node in list(self._builder.topological_sorting()):
            match node.type:
                case DAGNodeType.Genesis:
                    # do nothing
                    pass

                case DAGNodeType.Block:
                    if len(node.inputs) > 0:
                        raise ValueError

                    if len(node.outputs) > 1:
                        raise ValueError

                    blk_count = 0
                    txs_count = 0
                    parent_blk: DAGNode | None = None
                    for pi in node.parents:
                        pi_node = self._get_or_create_node(pi)
                        if pi_node.type == DAGNodeType.Block:
                            blk_count += 1
                            assert parent_blk is None
                            parent_blk = pi_node
                        else:
                            txs_count += 1

                    candidates: list[str] = []
                    if blk_count == 0:
                        node.parents.add('genesis_block')
                    else:
                        assert parent_blk is not None
                        candidates = [
                            x
                            for x in parent_blk.parents
                            if x != 'genesis_block' and self._get_node(x).type is not DAGNodeType.Block
                        ]

                    self.fill_parents(node, target=3, candidates=candidates)
                    assert len(node.parents) == 3

                    balance = self.calculate_balance(node)
                    assert set(balance.keys()).issubset({'HTR'})
                    diff = balance.get('HTR', 0)

                    target = self._daa.get_tokens_issued_per_block(1)  # TODO Use the actual height.
                    assert diff >= 0
                    assert diff <= target

                    if diff < target:
                        node.outputs.append(DAGOutput(target - diff, 'HTR', {'_origin': 'f7'}))

                case DAGNodeType.Transaction:
                    if node.name == 'dummy':
                        continue

                    self.fill_parents(node)
                    self._account_for_shielded_fee(node)
                    self.balance_node_inputs_and_outputs(node)

                case DAGNodeType.OnChainBlueprint:
                    self.fill_parents(node)
                    self.balance_node_inputs_and_outputs(node)

                case DAGNodeType.Token:
                    tokens.append(node.name)
                    self.fill_parents(node)

                case _:
                    raise NotImplementedError(node.type)

        for token in tokens:
            node = self._get_or_create_node(token)

            if 'token_id' in node.attrs:
                # Skip token creation when `token_id` is provided.
                continue

            balance = self.calculate_balance(node)
            assert set(balance.keys()).issubset({'HTR', token})

            token_version = node.get_attr_token_version()
            htr_deposit: int

            match token_version:
                case TokenVersion.NATIVE:
                    raise AssertionError
                case TokenVersion.DEPOSIT:
                    htr_deposit = get_deposit_token_deposit_amount(self._settings, balance[token])
                case TokenVersion.FEE:
                    htr_deposit = 0

            htr_balance = balance.get('HTR', 0)

            # target = sum(outputs) - sum(inputs)
            # <0 means deposit
            # >0 means withdrawal
            htr_target = node.balances.get('HTR', 0) - htr_deposit

            diff = htr_balance - htr_target

            if diff < 0:
                index = self.get_next_index(node.outputs)
                node.outputs[index] = DAGOutput(-diff, 'HTR', {'_origin': 'f8'})

            elif diff > 0:
                txin = self.find_txin(diff, 'HTR')
                node.inputs.add(txin)

        if 'dummy' in self._builder._nodes:
            node = self._get_node('dummy')
            balance = self.calculate_balance(node)
            if not balance:
                del self._builder._nodes['dummy']
            else:
                assert set(balance.keys()) == {'HTR'}
                diff = balance.get('HTR', 0)

                assert diff <= 0

                if diff < 0:
                    index = self.get_next_index(node.outputs)
                    node.outputs[index] = DAGOutput(-diff, 'HTR', {})

                for node in self._builder._nodes.values():
                    if node.type == DAGNodeType.Block:
                        continue
                    if node.type == DAGNodeType.Genesis:
                        continue
                    if node.name == 'dummy':
                        continue
                    self._builder.add_deps(node.name, 'dummy')
