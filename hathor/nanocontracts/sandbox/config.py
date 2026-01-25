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

# mypy: disable-error-code="attr-defined"

"""CPython sandbox configuration for nano contracts execution."""

from __future__ import annotations

import sys
from dataclasses import dataclass

from hathor.nanocontracts.sandbox.constants import BLUEPRINT_FILENAME


@dataclass(frozen=True)
class SandboxConfig:
    """Immutable configuration for CPython sandbox limits.

    This dataclass holds all sandbox limit settings that are enforced
    during blueprint execution. Being frozen ensures thread-safety and
    prevents accidental modifications.

    Attributes:
        enabled: Whether sandbox protection is enabled. When False, apply() is a no-op.
        max_int_digits: Maximum digits allowed in integers (~10^N)
        max_str_length: Maximum string length in characters
        max_bytes_length: Maximum bytes length
        max_list_size: Maximum number of items in a list
        max_dict_size: Maximum number of entries in a dict
        max_set_size: Maximum number of items in a set
        max_tuple_size: Maximum number of items in a tuple
        max_operations: Maximum AST-level operations per execution (requires PyCF_SANDBOX_COUNT)
        max_iterations: Maximum iterator steps per execution scope
        max_recursion_depth: Maximum recursion depth
        allow_float: Whether float type is allowed
        allow_complex: Whether complex type is allowed
        allow_dunder_access: Whether __dunder__ attribute access is allowed
        allow_io: Whether I/O operations are allowed
        allow_class_creation: Whether class definitions are allowed
        allow_magic_methods: Whether magic method definitions are allowed
        allow_metaclasses: Whether metaclass usage is allowed (use whitelist instead)
        allow_unsafe: Whether unsafe operations (compile, gc introspection) are allowed
        count_iterations_as_operations: Whether to count iterations as operations
        frozen_mode: Whether frozen mode is enabled
        auto_mutable: Whether auto_mutable mode is enabled
    """

    # Master switch for sandbox protection
    enabled: bool = True

    # Size limits (prevent DoS via large objects)
    max_int_digits: int = 100           # ~10^900, prevents huge integer DoS
    max_str_length: int = 1_000_000     # 1M chars
    max_bytes_length: int = 1_000_000   # 1M bytes
    max_list_size: int = 100_000        # 100K items
    max_dict_size: int = 100_000        # 100K entries
    max_set_size: int = 100_000         # 100K items
    max_tuple_size: int = 100_000       # 100K items

    # Execution limits (scoped to blueprint code)
    max_operations: int = 1_000_000     # 1M operations (AST-level counting)
    max_iterations: int = 10_000_000    # 10M iterations (catches C builtins)
    max_recursion_depth: int = 100      # Recursion limit

    # Type restrictions (security hardening)
    allow_float: bool = False
    allow_complex: bool = False

    # Security restrictions
    allow_dunder_access: bool = False   # Block __dunder__ attribute access
    allow_io: bool = False              # Block file, socket, fd operations

    # Class creation controls
    allow_class_creation: bool = True   # Allow class definitions
    allow_magic_methods: bool = False   # Restrict magic method definitions
    allow_metaclasses: bool = False     # Restrict metaclasses; use whitelist instead

    # Unsafe operations (blocks compile(), gc introspection)
    allow_unsafe: bool = False

    # Operation counting mode
    count_iterations_as_operations: bool = True

    # Frozen mode settings
    frozen_mode: bool = True
    auto_mutable: bool = True

    # Specialized opcodes (CPython 3.11+ adaptive specialization)
    allow_specialized_opcodes: bool = False

    def apply(self) -> None:
        """Apply this configuration to the CPython sandbox.

        IMPORTANT: This method only sets configuration values. It does NOT
        change the sandbox enable/suspend state. The caller is responsible
        for managing sandbox state via enable()/suspend()/resume().

        This method explicitly sets ALL config parameters to ensure consistent
        behavior regardless of any previously set defaults.

        If enabled=False, this method is a no-op (Null Object pattern).
        """
        if not self.enabled:
            return

        sys.sandbox.set_config(
            # Size limits
            max_int_digits=self.max_int_digits,
            max_str_length=self.max_str_length,
            max_bytes_length=self.max_bytes_length,
            max_list_size=self.max_list_size,
            max_dict_size=self.max_dict_size,
            max_set_size=self.max_set_size,
            max_tuple_size=self.max_tuple_size,
            # Execution limits
            max_operations=self.max_operations,
            max_iterations=self.max_iterations,
            max_recursion_depth=self.max_recursion_depth,
            # Type restrictions
            allow_float=self.allow_float,
            allow_complex=self.allow_complex,
            # Security restrictions
            allow_dunder_access=self.allow_dunder_access,
            allow_io=self.allow_io,
            allow_class_creation=self.allow_class_creation,
            allow_magic_methods=self.allow_magic_methods,
            allow_metaclasses=self.allow_metaclasses,
            allow_unsafe=self.allow_unsafe,
            count_iterations_as_operations=self.count_iterations_as_operations,
        )

        # Set frozen mode and auto_mutable via properties
        sys.sandbox.frozen_mode = self.frozen_mode
        sys.sandbox.auto_mutable = self.auto_mutable

        # Enable opcode restrictions for defense in depth.
        # This mirrors the OCB AST-level restrictions at the bytecode level.
        # New opcodes in future Python versions are blocked by default (allowlist approach).
        from hathor.nanocontracts.sandbox.allowlist import get_allowed_opcodes
        sys.sandbox.opcode_restrict_mode = True
        sys.sandbox.allowed_opcodes = get_allowed_opcodes()

        # Enable import restrictions for defense in depth.
        # Even if someone bypasses the custom __import__ builtin, the sandbox blocks unauthorized imports.
        from hathor.nanocontracts.sandbox.allowlist import get_sandbox_allowed_imports, get_sandbox_allowed_modules
        sys.sandbox.import_restrict_mode = True
        sys.sandbox.allowed_imports = get_sandbox_allowed_imports()

        # Enable module access restrictions for additional defense in depth.
        # Even if sandboxed code gets a reference to a disallowed module, the sandbox blocks its usage.
        sys.sandbox.module_access_restrict_mode = True
        sys.sandbox.allowed_modules = get_sandbox_allowed_modules()

        # Whitelist the Blueprint metaclass so Blueprints can be created
        # This is required when allow_metaclasses=False
        from hathor.nanocontracts.blueprint import _BlueprintBase
        sys.sandbox.allowed_metaclasses = frozenset({_BlueprintBase})

        # Register the blueprint filename for scope tracking (idempotent)
        sys.sandbox.add_filename(BLUEPRINT_FILENAME)

        # Set specialized opcodes permission (CPython 3.11+ adaptive specialization)
        sys.sandbox.allow_specialized_opcodes = self.allow_specialized_opcodes

    def check_available(self) -> None:
        """Raise if enabled but sys.sandbox not available."""
        if self.enabled and not hasattr(sys, 'sandbox'):
            from hathor.nanocontracts.exception import SandboxRequiredButNotAvailable
            raise SandboxRequiredButNotAvailable()

    def enable(self) -> None:
        """Enable sandbox. No-op if disabled."""
        if not self.enabled:
            return
        sys.sandbox.enable()

    def reset(self) -> None:
        """Reset sandbox (suspend + clear). No-op if disabled."""
        if not self.enabled:
            return
        sys.sandbox.reset()

    def reset_counts(self) -> None:
        """Reset sandbox counters. No-op if disabled."""
        if not self.enabled:
            return
        sys.sandbox.reset_counts()

    def get_counts(self) -> dict[str, int]:
        """Get sandbox counters. Returns empty dict if disabled."""
        if not self.enabled:
            return {}
        return sys.sandbox.get_counts()

    def set_mutable(self, obj: object) -> None:
        """Mark object as mutable in frozen mode. No-op if disabled."""
        if not self.enabled:
            return
        sys.sandbox.set_mutable(obj)

    def assert_active(self) -> None:
        """Assert sandbox is enabled and not suspended. No-op if disabled."""
        if not self.enabled:
            return
        assert sys.sandbox.enabled, "Sandbox must be enabled"
        assert not sys.sandbox.suspended, "Sandbox must not be suspended for limits to be enforced"


# Disabled configuration singleton (Null Object pattern)
# Use this instead of None to indicate sandbox is disabled
DISABLED_CONFIG = SandboxConfig(enabled=False)

# Default configuration for blueprint loading (consensus-critical)
# Uses lower operation limit for blueprint loading
DEFAULT_CONFIG_LOADING = SandboxConfig(
    max_operations=100_000,  # 100K operations for loading
)

# Default configuration for method execution (consensus-critical)
# Uses standard operation limits
DEFAULT_CONFIG_EXECUTION = SandboxConfig()  # 1M ops, 10M iters (class defaults)

# Default configuration for API view methods (local, not consensus-critical)
# Uses higher limits for flexibility but keeps security restrictions
DEFAULT_CONFIG_API = SandboxConfig(
    max_operations=10_000_000,   # 10M operations
    max_iterations=100_000_000,  # 100M iterations
)
