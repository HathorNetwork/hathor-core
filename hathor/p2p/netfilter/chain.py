# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from hathor.p2p.netfilter.context import NetfilterContext
    from hathor.p2p.netfilter.rule import NetfilterRule
    from hathor.p2p.netfilter.table import NetfilterTable
    from hathor.p2p.netfilter.targets import NetfilterTarget


class NetfilterChain:
    """Chain of rules to be processed at a given point of the code."""
    def __init__(self, name: str, policy: 'NetfilterTarget'):
        """Initialize the chain."""
        self.name = name
        self.table: Optional['NetfilterTable'] = None
        self.rules: list['NetfilterRule'] = []
        self.policy = policy

    def to_json(self) -> dict[str, Any]:
        return {
            'name': self.name,
            'table': self.table.to_json() if self.table else None,
            'policy': self.policy.to_json()
        }

    def add_rule(self, rule: 'NetfilterRule') -> 'NetfilterChain':
        """Add a new rule to this chain."""
        self.rules.append(rule)
        rule.chain = self
        return self

    def delete_rule(self, uuid: str) -> bool:
        """Delete a rule from this chain.
           Returns a bool that shows if the rule has been removed
        """
        for rule in self.rules:
            if rule.uuid == uuid:
                self.rules.remove(rule)
                return True

        return False

    def process(self, context: 'NetfilterContext') -> 'NetfilterTarget':
        """Process the rules of this chain."""
        for rule in self.rules:
            target = rule.get_target_if_match(context)
            if target is None:
                continue
            target.execute(rule, context)
            if target.terminate:
                return target
        return self.policy
