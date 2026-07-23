# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

# Re-export from hathorlib for backward compatibility
from hathorlib.serialization.adapters.generic_adapter import *  # noqa: F401,F403
from hathorlib.serialization.adapters.generic_adapter import (  # noqa: F401
    GenericDeserializerAdapter,
    GenericSerializerAdapter,
)
