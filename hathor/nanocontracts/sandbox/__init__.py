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

"""CPython sandbox configuration and utilities for nano contracts.

This package provides all sandbox-related functionality for nano contract execution:
- Configuration (SandboxConfig, DISABLED_CONFIG, DEFAULT_CONFIG_LOADING,
  DEFAULT_CONFIG_EXECUTION, DEFAULT_CONFIG_API)
- Execution counters (SandboxCounts, SandboxCounters)
- Exception types (SandboxError, SandboxRuntimeError, etc.)
- Allowlists (ALLOWED_OPCODES, get_allowed_imports_dict)
- Runtime configuration loading (SandboxAPIConfigLoader)
- Executor factory (MeteredExecutorFactory)
"""

from hathor.nanocontracts.sandbox.allowlist import (
    ALLOWED_OPCODES,
    get_allowed_imports_dict,
    get_allowed_opcodes,
    get_sandbox_allowed_imports,
    get_sandbox_allowed_modules,
)
from hathor.nanocontracts.sandbox.config import (
    DEFAULT_CONFIG_API,
    DEFAULT_CONFIG_EXECUTION,
    DEFAULT_CONFIG_LOADING,
    DISABLED_CONFIG,
    DisabledSandboxConfig,
    SandboxConfig,
)
from hathor.nanocontracts.sandbox.config_loader import SandboxAPIConfigLoader
from hathor.nanocontracts.sandbox.constants import BLUEPRINT_FILENAME, SANDBOX_AVAILABLE, PyCF_SANDBOX_COUNT
from hathor.nanocontracts.sandbox.counts import SandboxCounters, SandboxCounts
from hathor.nanocontracts.sandbox.exceptions import (
    SandboxError,
    SandboxMemoryError,
    SandboxOverflowError,
    SandboxRuntimeError,
    SandboxTypeError,
)
from hathor.nanocontracts.sandbox.executor_factory import MeteredExecutorFactory

__all__ = [
    # Config
    'SandboxConfig',
    'DISABLED_CONFIG',
    'DisabledSandboxConfig',
    'DEFAULT_CONFIG_LOADING',
    'DEFAULT_CONFIG_EXECUTION',
    'DEFAULT_CONFIG_API',
    # Counts
    'SandboxCounts',
    'SandboxCounters',
    # Constants
    'BLUEPRINT_FILENAME',
    'PyCF_SANDBOX_COUNT',
    'SANDBOX_AVAILABLE',
    # Exceptions
    'SandboxError',
    'SandboxRuntimeError',
    'SandboxMemoryError',
    'SandboxOverflowError',
    'SandboxTypeError',
    # Config loader
    'SandboxAPIConfigLoader',
    # Executor factory
    'MeteredExecutorFactory',
    # Allowlists
    'ALLOWED_OPCODES',
    'get_allowed_imports_dict',
    'get_allowed_opcodes',
    'get_sandbox_allowed_imports',
    'get_sandbox_allowed_modules',
]
