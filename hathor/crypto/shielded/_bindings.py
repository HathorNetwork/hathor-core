"""Import the native Rust module with graceful fallback."""

from typing import Any

__all__ = ['_lib', 'AVAILABLE']

_lib: Any = None
AVAILABLE: bool = False

try:
    import hathor_ct_crypto
    _lib = hathor_ct_crypto
    AVAILABLE = True
except ImportError:
    pass
