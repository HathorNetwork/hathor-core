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

import os
from typing import TYPE_CHECKING

from hathor.p2p.whitelist.file_whitelist import FilePeersWhitelist
from hathor.p2p.whitelist.peers_whitelist import PeersWhitelist
from hathor.p2p.whitelist.url_whitelist import URLPeersWhitelist
from hathor.reactor import ReactorProtocol as Reactor

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings

# Whitelist specification constants
WHITELIST_SPEC_DEFAULT = 'default'
WHITELIST_SPEC_HATHORLABS = 'hathorlabs'
WHITELIST_SPEC_NONE = 'none'
WHITELIST_SPEC_DISABLED = 'disabled'


def create_peers_whitelist(
    reactor: Reactor,
    whitelist_spec: str,
    settings: 'HathorSettings',
) -> 'PeersWhitelist | None':
    """Factory function to create PeersWhitelist from a specification string.

    Args:
        reactor: The Twisted reactor
        whitelist_spec: Whitelist specification - can be 'default', 'hathorlabs', 'none', 'disabled',
                a file path, or a URL
        settings: Hathor settings containing WHITELIST_URL

    Returns:
        PeersWhitelist instance or None if disabled
    """
    peers_whitelist: PeersWhitelist | None = None
    spec_lower = whitelist_spec.lower().strip()

    if spec_lower in (WHITELIST_SPEC_DEFAULT, WHITELIST_SPEC_HATHORLABS):
        peers_whitelist = URLPeersWhitelist(reactor, str(settings.WHITELIST_URL), True)
    elif spec_lower in (WHITELIST_SPEC_NONE, WHITELIST_SPEC_DISABLED):
        peers_whitelist = None
    elif os.path.isfile(whitelist_spec):
        peers_whitelist = FilePeersWhitelist(reactor, whitelist_spec)
    elif whitelist_spec.startswith('/') or whitelist_spec.startswith('.'):
        raise ValueError(f'whitelist file not found: {whitelist_spec}')
    else:
        # URLPeersWhitelist class rejects non-url paths.
        peers_whitelist = URLPeersWhitelist(reactor, whitelist_spec, True)

    return peers_whitelist
