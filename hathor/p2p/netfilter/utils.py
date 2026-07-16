# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from hathor.p2p.netfilter import get_table
from hathor.p2p.netfilter.matches import NetfilterMatchPeerId
from hathor.p2p.netfilter.rule import NetfilterRule
from hathor.p2p.netfilter.targets import NetfilterReject


def add_peer_id_blacklist(peer_id_blacklist: list[str]) -> None:
    """ Add a list of peer ids to a blacklist using netfilter reject
    """
    post_peerid = get_table('filter').get_chain('post_peerid')

    for peer_id in peer_id_blacklist:
        if not peer_id:
            continue
        match = NetfilterMatchPeerId(peer_id)
        rule = NetfilterRule(match, NetfilterReject())
        post_peerid.add_rule(rule)
