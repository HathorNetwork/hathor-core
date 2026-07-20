# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

"""Selection of the token amount version used for nano contract field storage.

This module is a leaf: it only depends on `hathorlib.token_amount_version`, so both the field
descriptors and the NCType factories can import it eagerly at module load.
"""

from __future__ import annotations

from hathorlib.token_amount_version import TokenAmountVersion

FORCE_LEGACY_FIELDS: bool = False


def get_storage_token_amount_version() -> TokenAmountVersion:
    """Return the token amount version used for field storage (de)serialization.

    Storage serialization is global: every contract's trie data uses the same encodings, regardless of the
    contract's own token amount version, which only governs runtime behavior such as argument and return
    value serialization. `FORCE_LEGACY_FIELDS` switches the whole storage layer to the legacy V1 encodings,
    and is used only in tests, to ensure the migration works.
    """
    return TokenAmountVersion.V1 if FORCE_LEGACY_FIELDS else TokenAmountVersion.V2
