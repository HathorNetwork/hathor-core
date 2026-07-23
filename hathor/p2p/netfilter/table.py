# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hathor.p2p.netfilter.chain import NetfilterChain


class NetfilterTable:
    """Table that contains one or more chains."""
    def __init__(self, name: str):
        self.name = name
        self.chains: dict[str, 'NetfilterChain'] = {}

    def to_json(self) -> dict[str, Any]:
        return {'name': self.name}

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
