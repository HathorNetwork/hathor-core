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

"""Sysctl commands for managing nano contract sandbox API configuration.

These commands allow runtime management of the sandbox configuration for API
view method calls. The API config is local to each node (not consensus-critical)
and can be changed at runtime.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from hathor.nanocontracts.sandbox import SandboxAPIConfigLoader
from hathor.sysctl.sysctl import Sysctl

MAX_CONFIG_FILE_PATH_LENGTH = 4096


class SandboxAPISysctl(Sysctl):
    """Sysctl commands for sandbox API configuration management.

    Commands:
        nc_sandbox_api.reload - Reload config from current file
        nc_sandbox_api.set_file - Change config file path and load it
        nc_sandbox_api.status - Get current status and config
        nc_sandbox_api.disable - Disable sandbox for API views
        nc_sandbox_api.allowed_opcodes - Get allowed opcode names (read-only)
        nc_sandbox_api.allowed_imports - Get allowed import strings (read-only)
        nc_sandbox_api.allowed_modules - Get allowed module names (read-only)
        nc_sandbox_api.allowed_metaclasses - Get allowed metaclass names (read-only)
    """

    def __init__(self, loader: SandboxAPIConfigLoader) -> None:
        """Initialize the sysctl with an existing config loader.

        Args:
            loader: An existing SandboxAPIConfigLoader instance to use.
        """
        super().__init__()

        self._loader = loader

        # Register sysctl commands
        self.register(
            'reload',
            None,
            self.set_reload,
        )
        self.register(
            'set_file',
            None,
            self.set_file,
        )
        self.register(
            'status',
            self.get_status,
            None,
        )
        self.register(
            'disable',
            None,
            self.set_disable,
        )
        self.register(
            'allowed_opcodes',
            self.get_allowed_opcodes,
            None,
        )
        self.register(
            'allowed_imports',
            self.get_allowed_imports,
            None,
        )
        self.register(
            'allowed_modules',
            self.get_allowed_modules,
            None,
        )
        self.register(
            'allowed_metaclasses',
            self.get_allowed_metaclasses,
            None,
        )

    @property
    def loader(self) -> SandboxAPIConfigLoader:
        """Access to the config loader."""
        return self._loader

    def set_reload(self) -> None:
        """Reload the API sandbox configuration from current file."""
        self._loader.reload()

    def set_file(self, file: str) -> None:
        """Change the API sandbox config file and load it.

        Args:
            file: Path to the new config file.

        Raises:
            ValueError: If the path is too long, not absolute, or not a regular file.
            FileNotFoundError: If the file does not exist.
        """
        if len(file) > MAX_CONFIG_FILE_PATH_LENGTH:
            raise ValueError(f'Config file path too long (max {MAX_CONFIG_FILE_PATH_LENGTH} chars)')
        path = Path(file)
        if not path.is_absolute():
            raise ValueError(f'Config file path must be absolute: {file}')
        if path.exists() and not path.is_file():
            raise ValueError(f'Config file path is not a regular file: {file}')
        success = self._loader.set_file(file)
        if not success:
            raise FileNotFoundError(f'File not found: {file}')

    def get_status(self) -> dict[str, Any]:
        """Get current API sandbox configuration status.

        Returns:
            dict with:
                - file: current file path or None
                - enabled: whether sandbox is enabled
                - config: current config values (if enabled) or None
        """
        import dataclasses

        config = self._loader.config
        config_dict = None
        if config is not None:
            config_dict = dataclasses.asdict(config)
            config_dict['enabled'] = config.is_enabled

        return {
            'file': str(self._loader.config_file) if self._loader.config_file else None,
            'enabled': config is not None,
            'config': config_dict
        }

    def set_disable(self) -> None:
        """Disable API sandbox entirely."""
        self._loader.disable()

    def get_allowed_opcodes(self) -> list[str]:
        """Get the sorted list of allowed opcode names."""
        from hathor.nanocontracts.sandbox.allowlist import ALLOWED_OPCODES
        return sorted(ALLOWED_OPCODES)

    def get_allowed_imports(self) -> list[str]:
        """Get the sorted list of allowed import strings (module.attribute)."""
        from hathor.nanocontracts.sandbox.allowlist import get_sandbox_allowed_imports
        return sorted(get_sandbox_allowed_imports())

    def get_allowed_modules(self) -> list[str]:
        """Get the sorted list of allowed module names."""
        from hathor.nanocontracts.sandbox.allowlist import get_sandbox_allowed_modules
        return sorted(get_sandbox_allowed_modules())

    def get_allowed_metaclasses(self) -> list[str]:
        """Get the list of allowed metaclass names."""
        from hathor.nanocontracts.blueprint import _BlueprintBase
        return [_BlueprintBase.__qualname__]
