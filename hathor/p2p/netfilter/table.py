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

from typing import TYPE_CHECKING, Dict

if TYPE_CHECKING:
    from hathor.p2p.netfilter.chain import NetfilterChain


class NetfilterTable:
    """Table that contains one or more chains."""
    def __init__(self, name: str):
        self.name = name
        self.chains: Dict[str, 'NetfilterChain'] = {}

    def add_chain(self, chain: 'NetfilterChain') -> 'NetfilterChain':
        """Add a new chain to the table."""
        if chain.name in self.chains:
            raise ValueError('Chain {} already exists in table {}'.format(chain.name, self.name))
        self.chains[chain.name] = chain
        chain.table = self
        return chain

    def get_chain(self, name: str) -> 'NetfilterChain':
        """Get the chain with `name`."""
        if name not in self.chains:
            raise KeyError('Chain {} does not exist in table {}'.format(name, self.name))
        return self.chains[name]
