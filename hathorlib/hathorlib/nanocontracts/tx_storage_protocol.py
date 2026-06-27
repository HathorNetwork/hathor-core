# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Optional, Protocol

from hathorlib.token_info import TokenDescription


class NCTransactionStorageProtocol(Protocol):
    def get_token_description(self, token_uid: bytes) -> Optional[TokenDescription]: ...
