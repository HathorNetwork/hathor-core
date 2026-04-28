# Copyright 2026 Hathor Labs
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

from typing import Any, cast

from twisted.internet import threads
from twisted.internet.defer import Deferred

from hathor.p2p.whitelist.parsing import parse_whitelist_with_policy
from hathor.p2p.whitelist.peers_whitelist import PeersWhitelist
from hathor.reactor import ReactorProtocol as Reactor


class FilePeersWhitelist(PeersWhitelist):
    def __init__(self, reactor: Reactor, path: str) -> None:
        super().__init__(reactor)
        self._path = path

    def path(self) -> str:
        return self._path

    def source(self) -> str | None:
        """Return the file path as the whitelist source."""
        return self._path

    def refresh(self) -> Deferred[None]:
        return self.update()

    def _read_and_parse(self) -> tuple:
        """Read and parse the whitelist file. Runs in a worker thread so both
        I/O and the potentially expensive parse stay off the reactor.
        """
        with open(self._path, 'r', encoding='utf-8') as fp:
            content = fp.read()
        return parse_whitelist_with_policy(content)

    def _apply_parsed(self, parsed: tuple) -> None:
        new_whitelist, new_policy = parsed
        self._apply_whitelist_update(new_whitelist, new_policy)

    def _handle_read_error(self, failure: Any) -> None:
        """Handle errors when reading or parsing the whitelist file."""
        self._on_update_failure()
        error = failure.value
        if isinstance(error, FileNotFoundError):
            self.log.warning('Whitelist file not found, keeping existing whitelist', path=self._path)
        elif isinstance(error, PermissionError):
            self.log.warning('Permission denied reading whitelist file, keeping existing whitelist', path=self._path)
        elif isinstance(error, ValueError):
            self.log.error('Failed to parse whitelist file content', path=self._path, error=str(error))
        else:
            self.log.error(
                'Failed to read whitelist file',
                path=self._path,
                error_type=type(error).__name__,
                error=str(error),
            )

    def _unsafe_update(self) -> Deferred[None]:
        """
            Implementation of base class function.
            Reads and parses the file in a worker thread to avoid blocking the
            reactor. The re-entrancy guard in PeersWhitelist.update() already
            prevents parallel parses per whitelist instance.
        """
        d: Deferred[tuple] = threads.deferToThread(self._read_and_parse)
        d.addCallback(self._apply_parsed)
        d.addErrback(self._handle_read_error)
        # Cast to Deferred[None] since callbacks transform the result
        return cast(Deferred[None], d)
