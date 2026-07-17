# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

# Re-export from hathorlib for backward compatibility
from hathorlib.nanocontracts.faux_immutable import (  # noqa: F401
    ALLOW_DUNDER_ATTR,
    ALLOW_INHERITANCE_ATTR,
    SKIP_VALIDATION_ATTR,
    FauxImmutable,
    FauxImmutableMeta,
    __set_faux_immutable__,
    create_with_shell,
)
