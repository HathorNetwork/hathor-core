# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor.p2p.netfilter.chain import NetfilterChain
from hathor.p2p.netfilter.table import NetfilterTable
from hathor.p2p.netfilter.targets import NetfilterAccept

filter_table = NetfilterTable('filter')
filter_table.add_chain(NetfilterChain('pre_conn', policy=NetfilterAccept()))
filter_table.add_chain(NetfilterChain('post_hello', policy=NetfilterAccept()))
filter_table.add_chain(NetfilterChain('post_peerid', policy=NetfilterAccept()))

tables = {
    'filter': filter_table,
}


def get_table(name):
    """Get table `name` of the netfilter."""
    if name not in tables:
        raise KeyError('Table {} does not exists'.format(name))
    return tables[name]
