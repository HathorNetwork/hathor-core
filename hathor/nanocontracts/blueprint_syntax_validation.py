# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

# Re-export from hathorlib for backward compatibility
from hathorlib.nanocontracts.blueprint_syntax_validation import (  # noqa: F401
    validate_has_ctx_arg,
    validate_has_not_ctx_arg,
    validate_has_self_arg,
    validate_method_types,
)
