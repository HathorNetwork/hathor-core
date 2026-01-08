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

from enum import Enum
from typing import Optional

from structlog import get_logger

from hathor.p2p.peer_id import PeerId
from hathor.p2p.utils import parse_file

logger = get_logger()


class WhitelistPolicy(Enum):
    """Policy types for whitelist behavior."""
    ALLOW_ALL = 'allow-all'
    ONLY_WHITELISTED_PEERS = 'only-whitelisted-peers'


def parse_whitelist(text: str, *, header: Optional[str] = None) -> set[PeerId]:
    """ Parses the list of whitelist peer ids

    Example:

    parse_whitelist('''hathor-whitelist
# node1
 2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367

2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367

# node3
G2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367
2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367
''')
    {'2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367'}

    """
    lines = parse_file(text, header=header)
    return {PeerId(line.split()[0]) for line in lines}


def parse_whitelist_with_policy(
    text: str,
    *,
    header: Optional[str] = None
) -> tuple[set[PeerId], WhitelistPolicy]:
    """Parses the whitelist file and extracts both peer IDs and policy.

    The policy line (optional) must appear in the header, before any peer IDs.
    Format: policy: <policy-type>

    Policy types:
        - allow-all: Allow connections from any peer
        - only-whitelisted-peers: Only allow connections from listed peers (default)

    Example:

    parse_whitelist_with_policy('''hathor-whitelist
policy: allow-all
''')
    (set(), WhitelistPolicy.ALLOW_ALL)

    parse_whitelist_with_policy('''hathor-whitelist
# This whitelist only allows specific peers
policy: only-whitelisted-peers
2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367
''')
    ({'2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367'}, WhitelistPolicy.ONLY_WHITELISTED_PEERS)

    parse_whitelist_with_policy('''hathor-whitelist
2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367
''')
    ({'2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367'}, WhitelistPolicy.ONLY_WHITELISTED_PEERS)
    """
    lines = parse_file(text, header=header)
    policy = WhitelistPolicy.ONLY_WHITELISTED_PEERS  # default

    peer_lines: list[str] = []

    for line in lines:
        if line.startswith('policy:'):
            if len(peer_lines) > 0:
                raise ValueError('policy must be defined in the header, before any peer IDs')
            policy_value = line.split(':', 1)[1].strip().lower()
            try:
                policy = WhitelistPolicy(policy_value)
            except ValueError:
                raise ValueError(f'invalid whitelist policy: {policy_value}')
        else:
            peer_lines.append(line)

    peers = {p for line in peer_lines if (p := _safe_parse_peer_id(line)) is not None}
    return peers, policy


def _safe_parse_peer_id(line: str) -> PeerId | None:
    """Safely parse a peer ID from a whitelist line.

    Returns the PeerId if valid, or None if parsing fails.
    Logs a warning for invalid peer IDs.
    """
    try:
        return PeerId(line.split()[0])
    except (ValueError, IndexError) as e:
        logger.warning('Invalid peer ID in whitelist', line=line, error=str(e))
        return None
