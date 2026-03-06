# Re-export from hathorlib for backward compatibility
from hathorlib.serialization.adapters.max_bytes import *  # noqa: F401,F403
from hathorlib.serialization.adapters.max_bytes import (  # noqa: F401
    MaxBytesDeserializer,
    MaxBytesExceededError,
    MaxBytesSerializer,
)
