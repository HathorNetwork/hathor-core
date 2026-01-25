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

"""Loader for external API sandbox configuration from YAML files.

This module provides a loader that manages API sandbox configuration from external
YAML files. The API config is local to each node (not consensus-critical) and
can be reloaded at runtime via sysctl commands.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from structlog import get_logger

from hathor.nanocontracts.sandbox.config import DEFAULT_CONFIG_API, DISABLED_CONFIG, SandboxConfig

logger = get_logger()


class SandboxAPIConfigLoader:
    """Loads and manages API sandbox configuration from external YAML file.

    API view sandbox configuration is local to each node (not consensus-critical)
    and can be changed at runtime via sysctl commands. This class handles:
    - Loading config from YAML files
    - Runtime reloading
    - Graceful handling of missing/invalid files

    Example usage:
        loader = SandboxAPIConfigLoader('/etc/hathor/sandbox_api_config.yaml')
        config = loader.config  # Get current config
        loader.reload()  # Reload from file
        loader.set_file('/path/to/new_config.yaml')  # Change file and load
        loader.disable()  # Disable sandbox for API views
    """

    __slots__ = ('_config_file', '_current_config')

    def __init__(self, config_file: Path | str | None = None) -> None:
        """Initialize the loader.

        Args:
            config_file: Path to YAML config file, or None to start with disabled config.
        """
        self._config_file: Path | None = Path(config_file) if config_file else None
        self._current_config: SandboxConfig = DISABLED_CONFIG
        self._load_config()

    def _load_config(self) -> None:
        """Load config from file. Sets DISABLED_CONFIG if file doesn't exist or is invalid."""
        if self._config_file is None or not self._config_file.exists():
            self._current_config = DISABLED_CONFIG
            return

        try:
            import yaml

            with open(self._config_file) as f:
                data: dict[str, Any] = yaml.safe_load(f) or {}

            api_view = data.get('api_view', {})
            if not api_view.get('enabled', True):
                self._current_config = DISABLED_CONFIG
                logger.info('sandbox API config disabled via config file', file=str(self._config_file))
                return

            # Build config from YAML values with defaults from DEFAULT_CONFIG_API
            self._current_config = SandboxConfig(
                # Size limits (use DEFAULT_CONFIG_API values as defaults)
                max_int_digits=api_view.get('max_int_digits', DEFAULT_CONFIG_API.max_int_digits),
                max_str_length=api_view.get('max_str_length', DEFAULT_CONFIG_API.max_str_length),
                max_bytes_length=api_view.get('max_bytes_length', DEFAULT_CONFIG_API.max_bytes_length),
                max_list_size=api_view.get('max_list_size', DEFAULT_CONFIG_API.max_list_size),
                max_dict_size=api_view.get('max_dict_size', DEFAULT_CONFIG_API.max_dict_size),
                max_set_size=api_view.get('max_set_size', DEFAULT_CONFIG_API.max_set_size),
                max_tuple_size=api_view.get('max_tuple_size', DEFAULT_CONFIG_API.max_tuple_size),
                # Execution limits (higher for API views)
                max_operations=api_view.get('max_operations', DEFAULT_CONFIG_API.max_operations),
                max_iterations=api_view.get('max_iterations', DEFAULT_CONFIG_API.max_iterations),
                max_recursion_depth=api_view.get('max_recursion_depth', DEFAULT_CONFIG_API.max_recursion_depth),
                # Type restrictions
                allow_float=api_view.get('allow_float', DEFAULT_CONFIG_API.allow_float),
                allow_complex=api_view.get('allow_complex', DEFAULT_CONFIG_API.allow_complex),
                # Security restrictions
                allow_dunder_access=api_view.get('allow_dunder_access', DEFAULT_CONFIG_API.allow_dunder_access),
                allow_io=api_view.get('allow_io', DEFAULT_CONFIG_API.allow_io),
                allow_class_creation=api_view.get('allow_class_creation', DEFAULT_CONFIG_API.allow_class_creation),
                allow_magic_methods=api_view.get('allow_magic_methods', DEFAULT_CONFIG_API.allow_magic_methods),
                allow_metaclasses=api_view.get('allow_metaclasses', DEFAULT_CONFIG_API.allow_metaclasses),
                allow_unsafe=api_view.get('allow_unsafe', DEFAULT_CONFIG_API.allow_unsafe),
                count_iterations_as_operations=api_view.get(
                    'count_iterations_as_operations', DEFAULT_CONFIG_API.count_iterations_as_operations
                ),
                frozen_mode=api_view.get('frozen_mode', DEFAULT_CONFIG_API.frozen_mode),
                auto_mutable=api_view.get('auto_mutable', DEFAULT_CONFIG_API.auto_mutable),
            )
            logger.info(
                'sandbox API config loaded',
                file=str(self._config_file),
                max_operations=self._current_config.max_operations,
                max_iterations=self._current_config.max_iterations,
            )
        except Exception as e:
            logger.warning('failed to load sandbox API config, keeping previous config', file=str(self._config_file),
                           error=str(e))
            # Keep previous config on error

    def reload(self) -> bool:
        """Reload config from current file. Returns True if config changed."""
        old_config = self._current_config
        self._load_config()
        changed = self._current_config != old_config
        if changed:
            logger.info('sandbox API config reloaded and changed', file=str(self._config_file))
        return changed

    def set_file(self, config_file: Path | str | None) -> bool:
        """Change config file path and reload. Returns True if successful.

        Args:
            config_file: New config file path, or None to disable.

        Returns:
            True if file was loaded successfully (or disabled), False if file not found.
        """
        if config_file is not None:
            new_path = Path(config_file)
            if not new_path.exists():
                logger.warning('sandbox API config file not found', file=str(config_file))
                return False
            self._config_file = new_path
        else:
            self._config_file = None

        self._load_config()
        return True

    def disable(self) -> None:
        """Disable API sandbox (set config to DISABLED_CONFIG)."""
        self._current_config = DISABLED_CONFIG
        logger.info('sandbox API config disabled')

    @property
    def config(self) -> SandboxConfig:
        """Current API sandbox config."""
        return self._current_config

    @property
    def config_file(self) -> Path | None:
        """Current config file path."""
        return self._config_file
