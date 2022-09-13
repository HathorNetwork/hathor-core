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

from typing import TYPE_CHECKING, Any, Dict, Optional

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

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, NetfilterRule):
            return NotImplemented

        self_chain_name = self.chain.name if self.chain else None
        other_chain_name = other.chain.name if other.chain else None
        return self_chain_name == other_chain_name and self.match == other.match and self.target == other.target

    def to_json(self) -> Dict[str, Any]:
        data: Dict[str, Any] = {}

        if self.chain:
            data['chain'] = self.chain.name

        data_target: Dict[str, Any] = {}
        data_target['type'] = type(self.target).__name__
        data_target['parameters'] = self.target.__dict__
        data['target'] = data_target

        data_match: Dict[str, Any] = {}
        data_match['type'] = type(self.match).__name__
        data_match['parameters'] = self.match.__dict__
        data['match'] = data_match

        return data

    def get_target_if_match(self, context: 'NetfilterContext') -> Optional['NetfilterTarget']:
        if not self.match.match(context):
            return None
        return self.target
