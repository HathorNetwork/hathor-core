# Copyright 2024 Hathor Labs
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

"""Portable sandbox exception types that work with or without sandbox Python.

When running on CPython with sandbox support (python -V shows '-sandbox' suffix),
these are the actual sandbox exceptions from builtins. When running on standard
CPython, these are stub classes that maintain the same inheritance hierarchy.

This allows code to import and catch sandbox exceptions without requiring the
actual sandbox Python build.

Usage:
    from hathor.nanocontracts.sandbox.exceptions import SandboxError, SandboxRuntimeError

    try:
        # code that might raise sandbox exceptions
    except SandboxError:
        # catches any sandbox exception (SandboxError is the base class)

    # You can also check with isinstance:
    if isinstance(exc, SandboxError):
        # handles any sandbox exception
"""

from hathor.nanocontracts.sandbox.constants import SANDBOX_AVAILABLE

if SANDBOX_AVAILABLE:
    # Import the real sandbox exceptions from builtins
    from builtins import (  # type: ignore[attr-defined]
        SandboxError,
        SandboxMemoryError,
        SandboxOverflowError,
        SandboxRuntimeError,
        SandboxTypeError,
    )
else:
    # Define stub classes for non-sandbox Python builds
    # These maintain the same inheritance hierarchy as the real exceptions
    class SandboxError(Exception):  # type: ignore[no-redef]
        """Base class for all sandbox-related exceptions."""
        pass

    class SandboxRuntimeError(SandboxError):  # type: ignore[no-redef]
        """Raised when sandbox execution limits are exceeded (max_operations, max_iterations)."""
        pass

    class SandboxMemoryError(SandboxError):  # type: ignore[no-redef]
        """Raised when sandbox memory limits are exceeded."""
        pass

    class SandboxOverflowError(SandboxError):  # type: ignore[no-redef]
        """Raised when sandbox detects integer overflow."""
        pass

    class SandboxTypeError(SandboxError):  # type: ignore[no-redef]
        """Raised when sandbox detects disallowed type usage (e.g., float, complex)."""
        pass

__all__ = [
    'SandboxError',
    'SandboxRuntimeError',
    'SandboxMemoryError',
    'SandboxOverflowError',
    'SandboxTypeError',
]
