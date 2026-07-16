# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import TYPE_CHECKING, Any, Optional
from uuid import uuid4

if TYPE_CHECKING:
    from hathor.p2p.netfilter.chain import NetfilterChain
    from hathor.p2p.netfilter.context import NetfilterContext
    from hathor.p2p.netfilter.matches import NetfilterMatch
    from hathor.p2p.netfilter.targets import NetfilterTarget


class NetfilterRule:
    """Rule that has a match and a target."""
    def __init__(self, match: 'NetfilterMatch', target: 'NetfilterTarget'):
        self.chain: Optional['NetfilterChain'] = None
        self.match = match
        self.target = target

        # UUID used to find the rule, in order to delete it
        self.uuid = str(uuid4())

    def to_json(self) -> dict[str, Any]:
        return {
            'uuid': self.uuid,
            'chain': self.chain.to_json() if self.chain else None,
            'target': self.target.to_json(),
            'match': self.match.to_json()
        }

    def get_target_if_match(self, context: 'NetfilterContext') -> Optional['NetfilterTarget']:
        if not self.match.match(context):
            return None
        return self.target
