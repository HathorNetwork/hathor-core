# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
