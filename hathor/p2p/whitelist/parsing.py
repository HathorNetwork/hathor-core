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

from structlog import get_logger

from hathor.p2p.peer_id import PeerId

logger = get_logger()

WHITELIST_HEADER = 'hathor-whitelist'


class WhitelistPolicy(Enum):
    """Policy types for whitelist behavior."""
    ALLOW_ALL = 'allow-all'
    ONLY_WHITELISTED_PEERS = 'only-whitelisted-peers'


def parse_whitelist_with_policy(text: str) -> tuple[set[PeerId], WhitelistPolicy]:
    """Parses the whitelist file and extracts both peer IDs and policy.

    The policy line (optional) must appear in the header, before any peer IDs.
    Format: # policy: <policy-type>

    Both ``# policy:`` and ``#policy:`` (with or without space) are accepted.
    The comment-style prefix ensures backwards compatibility — older parsers
    will skip the line as a comment.

    Policy types:
        - allow-all: Allow connections from any peer
        - only-whitelisted-peers: Only allow connections from listed peers (default)

    Examples:

    >>> parse_whitelist_with_policy('hathor-whitelist\\n# policy: allow-all\\n')
    (set(), <WhitelistPolicy.ALLOW_ALL: 'allow-all'>)

    >>> peers, policy = parse_whitelist_with_policy(
    ...     'hathor-whitelist\\n'
    ...     '# policy: only-whitelisted-peers\\n'
    ...     '2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367\\n'
    ... )
    >>> policy
    <WhitelistPolicy.ONLY_WHITELISTED_PEERS: 'only-whitelisted-peers'>
    >>> len(peers)
    1

    >>> peers, policy = parse_whitelist_with_policy(
    ...     'hathor-whitelist\\n'
    ...     '2ffdfbbfd6d869a0742cff2b054af1cf364ae4298660c0e42fa8b00a66a30367\\n'
    ... )
    >>> policy
    <WhitelistPolicy.ONLY_WHITELISTED_PEERS: 'only-whitelisted-peers'>
    >>> len(peers)
    1
    """
    lines = text.splitlines()
    _header = lines.pop(0)
    if _header != WHITELIST_HEADER:
        raise ValueError('invalid header')

    policy = WhitelistPolicy.ONLY_WHITELISTED_PEERS  # default
    peer_lines: list[str] = []

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith('#'):
            comment_body = line.lstrip('#').lstrip()
            if comment_body.startswith('policy:'):
                if len(peer_lines) > 0:
                    raise ValueError('policy must be defined in the header, before any peer IDs')
                policy_value = comment_body.split(':', 1)[1].strip().lower()
                try:
                    policy = WhitelistPolicy(policy_value)
                except ValueError:
                    raise ValueError(f'invalid whitelist policy: {policy_value}')
            continue
        else:
            peer_lines.append(line)

    peers = {p for line in peer_lines if (p := _parse_peer_id_lossy(line)) is not None}

    if policy == WhitelistPolicy.ALLOW_ALL and peers:
        logger.warning('whitelist has allow-all policy but also lists peer IDs', num_peers=len(peers))

    return peers, policy


def _parse_peer_id_lossy(line: str) -> PeerId | None:
    """Parse a peer ID from a whitelist line, returning None on failure.

    Returns the PeerId if valid, or None if parsing fails.
    """
    try:
        return PeerId(line.split()[0])
    except (ValueError, IndexError):
        logger.warning('failed to parse peer id from whitelist line', line=line)
        return None
