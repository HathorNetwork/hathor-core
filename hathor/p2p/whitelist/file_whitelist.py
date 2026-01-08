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
        return self._unsafe_update()

    def _read_file(self) -> str:
        """Read the whitelist file. Runs in a thread to avoid blocking."""
        with open(self._path, 'r', encoding='utf-8') as fp:
            return fp.read()

    def _process_content(self, content: str) -> None:
        """Process the whitelist file content after reading."""
        try:
            new_whitelist, new_policy = parse_whitelist_with_policy(content)
        except ValueError as e:
            self.log.error('Failed to parse whitelist file content', path=self._path, error=str(e))
            self._on_update_failure()
            return
        except Exception:
            self.log.exception('Unexpected error parsing whitelist file', path=self._path)
            self._on_update_failure()
            return

        self._apply_whitelist_update(new_whitelist, new_policy)

    def _handle_read_error(self, failure: Any) -> None:
        """Handle errors when reading the whitelist file."""
        self._on_update_failure()
        error = failure.value
        if isinstance(error, FileNotFoundError):
            self.log.warning('Whitelist file not found, keeping existing whitelist', path=self._path)
        elif isinstance(error, PermissionError):
            self.log.warning('Permission denied reading whitelist file, keeping existing whitelist', path=self._path)
        else:
            self.log.error('Failed to read whitelist file', path=self._path, error=str(error))

    def _unsafe_update(self) -> Deferred[None]:
        """
            Implementation of base class function.
            Reads the file in the class path using a thread to avoid blocking.
        """
        d: Deferred[str] = threads.deferToThread(self._read_file)
        d.addCallback(self._process_content)
        d.addErrback(self._handle_read_error)
        # Cast to Deferred[None] since callbacks transform the result
        return cast(Deferred[None], d)
