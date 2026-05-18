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

"""Tests for the canonical header-ordering rule enforced by VertexVerifier.

Headers within a vertex must appear in strictly-ascending VertexHeaderId
byte order. This is a malleability guard: it removes the freedom to
serialize the same logical transaction in multiple byte forms.
"""

from unittest.mock import MagicMock, patch

import pytest

from hathor.conf.settings import HathorSettings
from hathor.transaction.exceptions import HeaderNotSupported
from hathor.transaction.headers import FeeHeader, NanoHeader
from hathor.verification.vertex_verifier import VertexVerifier


class TestCanonicalHeaderOrder:
    """Headers must be sorted by VertexHeaderId value (ascending)."""

    def test_canonical_order_accepted(self) -> None:
        """Headers in ascending order by VertexHeaderId should pass."""
        settings = MagicMock(spec=HathorSettings)
        verifier = VertexVerifier(settings=settings, reactor=MagicMock(), feature_service=MagicMock())

        # NanoHeader is 0x10, FeeHeader is 0x11 — ascending.
        nano = NanoHeader.__new__(NanoHeader)
        fee = FeeHeader.__new__(FeeHeader)

        vertex = MagicMock()
        vertex.headers = [nano, fee]
        vertex.get_maximum_number_of_headers = MagicMock(return_value=3)

        params = MagicMock()

        with patch.object(VertexVerifier, 'get_allowed_headers', return_value={NanoHeader, FeeHeader}):
            # Should not raise
            verifier.verify_headers(vertex, params)

    def test_non_canonical_order_rejected(self) -> None:
        """Headers NOT in ascending order should be rejected."""
        settings = MagicMock(spec=HathorSettings)
        verifier = VertexVerifier(settings=settings, reactor=MagicMock(), feature_service=MagicMock())

        # Wrong order: FeeHeader (0x11) before NanoHeader (0x10).
        nano = NanoHeader.__new__(NanoHeader)
        fee = FeeHeader.__new__(FeeHeader)

        vertex = MagicMock()
        vertex.headers = [fee, nano]
        vertex.get_maximum_number_of_headers = MagicMock(return_value=3)

        params = MagicMock()

        with patch.object(VertexVerifier, 'get_allowed_headers', return_value={NanoHeader, FeeHeader}):
            with pytest.raises(HeaderNotSupported, match='[Oo]rder'):
                verifier.verify_headers(vertex, params)

    def test_single_header_always_ok(self) -> None:
        """A single header is always in canonical order (vacuously)."""
        settings = MagicMock(spec=HathorSettings)
        verifier = VertexVerifier(settings=settings, reactor=MagicMock(), feature_service=MagicMock())

        nano = NanoHeader.__new__(NanoHeader)

        vertex = MagicMock()
        vertex.headers = [nano]
        vertex.get_maximum_number_of_headers = MagicMock(return_value=3)

        params = MagicMock()

        with patch.object(VertexVerifier, 'get_allowed_headers', return_value={NanoHeader}):
            # Should not raise
            verifier.verify_headers(vertex, params)

    def test_zero_headers_always_ok(self) -> None:
        """A vertex with no headers is trivially in canonical order."""
        settings = MagicMock(spec=HathorSettings)
        verifier = VertexVerifier(settings=settings, reactor=MagicMock(), feature_service=MagicMock())

        vertex = MagicMock()
        vertex.headers = []
        vertex.get_maximum_number_of_headers = MagicMock(return_value=3)

        params = MagicMock()

        with patch.object(VertexVerifier, 'get_allowed_headers', return_value=set()):
            # Should not raise
            verifier.verify_headers(vertex, params)

    def test_header_id_classmethod(self) -> None:
        """Concrete subclasses expose the right 1-byte header ID."""
        assert FeeHeader.get_header_id() == b'\x11'
        assert NanoHeader.get_header_id() == b'\x10'
