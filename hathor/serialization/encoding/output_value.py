# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

# Re-export from hathorlib for backward compatibility
from hathorlib.serialization.encoding.output_value import *  # noqa: F401,F403
from hathorlib.serialization.encoding.output_value import (  # noqa: F401
    MAX_OUTPUT_VALUE_32,
    MAX_OUTPUT_VALUE_64,
    encode_output_value,
)
