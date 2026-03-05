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
from enum import StrEnum, unique
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from hathor.p2p.whitelist.file_whitelist import FilePeersWhitelist
from hathor.p2p.whitelist.peers_whitelist import PeersWhitelist
from hathor.p2p.whitelist.url_whitelist import URLPeersWhitelist
from hathor.reactor import ReactorProtocol as Reactor

if TYPE_CHECKING:
    from hathor.conf.settings import HathorSettings


@unique
class WhitelistSpec(StrEnum):
    DEFAULT = 'default'
    HATHORLABS = 'hathorlabs'
    NONE = 'none'
    DISABLED = 'disabled'


def _looks_like_url(spec: str) -> bool:
    parsed = urlparse(spec)
    return parsed.scheme in ('http', 'https')


def create_peers_whitelist(
    reactor: Reactor,
    whitelist_spec: str,
    settings: 'HathorSettings',
    *,
    allow_unsafe_http: bool = False,
) -> 'PeersWhitelist | None':
    """Factory function to create PeersWhitelist from a specification string.

    Args:
        reactor: The Twisted reactor
        whitelist_spec: Whitelist specification - can be 'default', 'hathorlabs', 'none', 'disabled',
                a file path, or a URL
        settings: Hathor settings containing WHITELIST_URL
        allow_unsafe_http: Whether to allow non-HTTPS URLs (default: False, secure by default)

    Returns:
        PeersWhitelist instance or None if disabled
    """
    peers_whitelist: PeersWhitelist | None = None
    spec_lower = whitelist_spec.lower().strip()

    if spec_lower in (WhitelistSpec.DEFAULT, WhitelistSpec.HATHORLABS):
        peers_whitelist = URLPeersWhitelist(reactor, str(settings.WHITELIST_URL), allow_unsafe_http=allow_unsafe_http)
    elif spec_lower in (WhitelistSpec.NONE, WhitelistSpec.DISABLED):
        peers_whitelist = None
    elif _looks_like_url(whitelist_spec):
        peers_whitelist = URLPeersWhitelist(reactor, whitelist_spec, allow_unsafe_http=allow_unsafe_http)
    elif os.path.isfile(whitelist_spec):
        peers_whitelist = FilePeersWhitelist(reactor, whitelist_spec)
    else:
        raise ValueError(f'whitelist spec is not a URL and file does not exist: {whitelist_spec}')

    return peers_whitelist
