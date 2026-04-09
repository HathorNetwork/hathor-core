# Copyright 2021 Hathor Labs
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
