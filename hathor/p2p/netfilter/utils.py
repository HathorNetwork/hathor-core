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

# Global mapping to track peer_id -> rule UUID for blacklist management
_peer_id_to_rule_uuid: dict[str, str] = {}


def add_blacklist_peers(peer_ids: str | list[str]) -> list[str]:
    """Add peer(s) to the blacklist.

    Args:
        peer_ids: A single peer_id string or a list of peer_id strings

    Returns:
        List of peer_ids that were successfully added (not already blacklisted)
    """
    if isinstance(peer_ids, str):
        peer_ids = [peer_ids]

    post_peerid = get_table('filter').get_chain('post_peerid')
    added_peers: list[str] = []

    for peer_id in peer_ids:
        if not peer_id:
            continue

        # Skip if already blacklisted
        if peer_id in _peer_id_to_rule_uuid:
            continue

        match = NetfilterMatchPeerId(peer_id)
        rule = NetfilterRule(match, NetfilterReject())
        post_peerid.add_rule(rule)
        _peer_id_to_rule_uuid[peer_id] = rule.uuid
        added_peers.append(peer_id)

    return added_peers


def remove_blacklist_peers(peer_ids: str | list[str]) -> list[str]:
    """Remove peer(s) from the blacklist.

    Args:
        peer_ids: A single peer_id string or a list of peer_id strings

    Returns:
        List of peer_ids that were successfully removed
    """
    if isinstance(peer_ids, str):
        peer_ids = [peer_ids]

    post_peerid = get_table('filter').get_chain('post_peerid')
    removed_peers: list[str] = []

    for peer_id in peer_ids:
        if not peer_id:
            continue

        rule_uuid = _peer_id_to_rule_uuid.get(peer_id)
        if rule_uuid is None:
            continue

        if post_peerid.delete_rule(rule_uuid):
            del _peer_id_to_rule_uuid[peer_id]
            removed_peers.append(peer_id)

    return removed_peers


def list_blacklist_peers() -> list[str]:
    """List all currently blacklisted peer_ids.

    Returns:
        List of blacklisted peer_id strings
    """
    return list(_peer_id_to_rule_uuid.keys())


def add_peer_id_blacklist(peer_id_blacklist: list[str]) -> None:
    """Add a list of peer ids to a blacklist using netfilter reject.

    This is a legacy function that wraps add_blacklist_peers for backward compatibility.
    """
    add_blacklist_peers(peer_id_blacklist)
