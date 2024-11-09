from __future__ import annotations

from collections import defaultdict
from math import ceil

from hathor.dag_builder.builder import DAGBuilder, DAGInput, DAGNode, DAGOutput


class DefaultFiller:
    def __init__(self, builder: DAGBuilder, settings, daa) -> None:
        self._builder = builder
        self._settings = settings
        self._latest_transactions: list[str] = []
        self._daa = daa

    def _get_node(self, name, *, default_type='unknown'):
        return self._builder._get_node(name, default_type=default_type)

    @staticmethod
    def get_next_index(outputs: list[DAGOutput]) -> int:
        for i, txout in enumerate(outputs):
            if txout is None:
                return i
        outputs.append(None)
        return len(outputs) - 1

    def fill_parents(self, node: DAGNode, *, target: int = 2) -> None:
        # What's the best way to fill the parents?
        # Should we use dummy transactions so it is unrelated to the other transactions?
        # Should we use an attribute to choose the selection criteria?
        if node.type == 'genesis':
            return
        if len(node.parents) >= target:
            return
        candidates = [
            'genesis_1',
            'genesis_2',
        ]
        for pi in candidates:
            if len(node.parents) >= target:
                break
            node.parents.add(pi)

    def find_txin(self, amount: int, token: str) -> DAGInput:
        if token == 'HTR':
            dummy = self._get_node('dummy', default_type='transaction')
            dummy.inputs.add(DAGInput('genesis_block', 0))
            self.fill_parents(dummy)

            # TODO no more than 255 inputs
            index = self.get_next_index(dummy.outputs)
            dummy.outputs[index] = DAGOutput(amount, token, [])
            return DAGInput('dummy', index)

        else:
            token_node = self._get_node(token)
            index = self.get_next_index(token_node.outputs)
            token_node.outputs[index] = DAGOutput(amount, token, [])
            return DAGInput(token, index)

    def calculate_balance(self, node: DAGNode) -> dict[str, int]:
        ins = defaultdict(int)
        for tx_name, index in node.inputs:
            node2 = self._get_node(tx_name)
            txout = node2.outputs[index]
            ins[txout.token] += txout.amount

        outs = defaultdict(int)
        for txout in node.outputs:
            outs[txout.token] += txout.amount

        keys = set(ins.keys()) | set(outs.keys())
        balance = {}
        for key in keys:
            balance[key] = outs.get(key, 0) - ins.get(key, 0)

        return balance

    def balance_node(self, node: DAGNode) -> None:
        balance = self.calculate_balance(node)

        for key, diff in balance.items():
            # =0 balance
            # <0 need output
            # >0 need input
            if diff < 0:
                index = self.get_next_index(node.outputs)
                node.outputs[index] = DAGOutput(abs(diff), key, [])
            elif diff > 0:
                txin = self.find_txin(diff, key)
                node.inputs.add(txin)

    def run(self):
        genesis_block = self._get_node('genesis_block', default_type='genesis')
        if len(genesis_block.outputs) == 0:
            genesis_block.outputs.append(DAGOutput(self._settings.GENESIS_TOKENS, 'HTR', []))
        self._get_node('genesis_1', default_type='genesis')
        self._get_node('genesis_2', default_type='genesis')
        self._latest_transactions = [
            'genesis_1',
            'genesis_2',
        ]

        for node in self._builder._nodes.values():
            if node.type != 'transaction':
                continue
            if node.name == 'dummy':
                continue
            if not node.inputs and not node.outputs:
                node.outputs.append(DAGOutput(1, 'HTR', []))

        tokens = []
        for node in list(self._builder.topological_sorting()):
            if node.type == 'genesis':
                continue

            if node.type == 'block':
                if len(node.inputs) > 0:
                    raise ValueError

                if len(node.outputs) > 1:
                    raise ValueError

                blk_count = 0
                txs_count = 0
                for pi in node.parents:
                    pi_node = self._get_node(pi)
                    if pi_node.type == 'block':
                        blk_count += 1
                    else:
                        txs_count += 1

                if blk_count == 0:
                    node.parents.add('genesis_block')

                self.fill_parents(node, target=3)

                assert len(node.parents) == 3

                balance = self.calculate_balance(node)
                assert set(balance.keys()).issubset({'HTR'})
                diff = balance.get('HTR', 0)

                target = self._daa.get_tokens_issued_per_block(1)  # TODO Use the actual height.
                assert diff >= 0
                assert diff <= target

                if diff < target:
                    node.outputs.append(DAGOutput(target - diff, 'HTR', []))

            elif node.type == 'transaction':
                self.fill_parents(node)

                self.balance_node(node)
                self._latest_transactions.append(node.name)

            elif node.type == 'token':
                tokens.append(node.name)
                self.fill_parents(node)

        for token in tokens:
            node = self._get_node(token)

            balance = self.calculate_balance(node)
            assert set(balance.keys()).issubset({'HTR', token})

            htr_minimum = ceil(balance[token] / 100)
            htr_balance = -balance.get('HTR', 0)

            if htr_balance > htr_minimum:
                index = self.get_next_index(node.outputs)
                node.outputs[index] = DAGOutput(htr_balance - htr_minimum, 'HTR', [])

            elif htr_balance < htr_minimum:
                txin = self.find_txin(htr_minimum - htr_balance, 'HTR')
                node.inputs.add(txin)

        if 'dummy' in self._builder._nodes:
            node = self._get_node('dummy')
            balance = self.calculate_balance(node)
            assert set(balance.keys()) == {'HTR'}
            diff = balance.get('HTR', 0)

            if diff < 0:
                index = self.get_next_index(node.outputs)
                node.outputs[index] = DAGOutput(-diff, 'HTR', [])
