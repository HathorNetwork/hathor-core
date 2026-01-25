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


def _validated_int(data: dict[str, Any], key: str, default: int) -> int:
    """Get an integer value from a dict, with type and range validation.

    Returns the default if the value is missing, not an int, or negative.
    """
    value = data.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool):
        logger.warning('invalid type for sandbox config field, using default', key=key, value=value, default=default)
        return default
    if value < 0:
        logger.warning('negative value for sandbox config field, using default', key=key, value=value, default=default)
        return default
    return value


def _validated_bool(data: dict[str, Any], key: str, default: bool) -> bool:
    """Get a boolean value from a dict, with type validation.

    Returns the default if the value is missing or not a bool.
    """
    value = data.get(key, default)
    if not isinstance(value, bool):
        logger.warning('invalid type for sandbox config field, using default', key=key, value=value, default=default)
        return default
    return value


class SandboxAPIConfigLoader:
    """Loads and manages API sandbox configuration.

    API view sandbox configuration is local to each node (not consensus-critical)
    and can be changed at runtime via sysctl commands. This class handles:
    - Using a default config from settings (NC_SANDBOX_CONFIG_API)
    - Loading config from YAML files (optional, for runtime override)
    - Runtime reloading
    - Graceful handling of missing/invalid files

    Example usage:
        # With default config from settings
        loader = SandboxAPIConfigLoader(default_config=settings.NC_SANDBOX_CONFIG_API)
        config = loader.config  # Get current config (from default)

        # With runtime file override
        loader = SandboxAPIConfigLoader(
            default_config=settings.NC_SANDBOX_CONFIG_API,
            config_file='/etc/hathor/sandbox_api_config.yaml'
        )

        loader.reload()  # Reload from file
        loader.set_file('/path/to/new_config.yaml')  # Change file and load
        loader.disable()  # Disable sandbox for API views
    """

    __slots__ = ('_config_file', '_current_config', '_default_config')

    def __init__(
        self,
        default_config: SandboxConfig | None = None,
        config_file: Path | str | None = None,
    ) -> None:
        """Initialize the loader.

        Args:
            default_config: Default SandboxConfig from settings (NC_SANDBOX_CONFIG_API).
                           None means API sandbox is disabled by default.
            config_file: Optional path to YAML config file for runtime override.
        """
        self._default_config: SandboxConfig | None = default_config
        self._config_file: Path | None = Path(config_file) if config_file else None
        self._current_config: SandboxConfig = DISABLED_CONFIG
        self._load_config()

    def _load_config(self) -> None:
        """Load config from file, or fall back to default config.

        Priority:
        1. If config file exists, load from file
        2. Otherwise, use default_config if provided
        3. Otherwise, use DISABLED_CONFIG
        """
        if self._config_file is None or not self._config_file.exists():
            # No file, use default config (which may be None, meaning disabled)
            if self._default_config is not None:
                self._current_config = self._default_config
                logger.info('sandbox API using default config from settings')
            else:
                self._current_config = DISABLED_CONFIG
                logger.info('sandbox API disabled (no config file or default config)')
            return

        try:
            import yaml

            with open(self._config_file) as f:
                data: dict[str, Any] = yaml.safe_load(f) or {}

            api_view = data.get('api_view', {})
            if not isinstance(api_view, dict):
                raise ValueError(f"'api_view' must be a mapping, got {type(api_view).__name__}")

            if not api_view.get('enabled', True):
                self._current_config = DISABLED_CONFIG
                logger.info('sandbox API config disabled via config file', file=str(self._config_file))
                return

            # Build config from YAML values with validated defaults from DEFAULT_CONFIG_API
            self._current_config = SandboxConfig(
                # Size limits
                max_int_digits=_validated_int(api_view, 'max_int_digits', DEFAULT_CONFIG_API.max_int_digits),
                max_str_length=_validated_int(api_view, 'max_str_length', DEFAULT_CONFIG_API.max_str_length),
                max_bytes_length=_validated_int(api_view, 'max_bytes_length', DEFAULT_CONFIG_API.max_bytes_length),
                max_list_size=_validated_int(api_view, 'max_list_size', DEFAULT_CONFIG_API.max_list_size),
                max_dict_size=_validated_int(api_view, 'max_dict_size', DEFAULT_CONFIG_API.max_dict_size),
                max_set_size=_validated_int(api_view, 'max_set_size', DEFAULT_CONFIG_API.max_set_size),
                max_tuple_size=_validated_int(api_view, 'max_tuple_size', DEFAULT_CONFIG_API.max_tuple_size),
                # Execution limits
                max_operations=_validated_int(api_view, 'max_operations', DEFAULT_CONFIG_API.max_operations),
                max_iterations=_validated_int(api_view, 'max_iterations', DEFAULT_CONFIG_API.max_iterations),
                max_recursion_depth=_validated_int(
                    api_view, 'max_recursion_depth', DEFAULT_CONFIG_API.max_recursion_depth
                ),
                # Type restrictions
                allow_float=_validated_bool(api_view, 'allow_float', DEFAULT_CONFIG_API.allow_float),
                allow_complex=_validated_bool(api_view, 'allow_complex', DEFAULT_CONFIG_API.allow_complex),
                # Security restrictions
                allow_dunder_access=_validated_bool(
                    api_view, 'allow_dunder_access', DEFAULT_CONFIG_API.allow_dunder_access
                ),
                allow_io=_validated_bool(api_view, 'allow_io', DEFAULT_CONFIG_API.allow_io),
                allow_class_creation=_validated_bool(
                    api_view, 'allow_class_creation', DEFAULT_CONFIG_API.allow_class_creation
                ),
                allow_magic_methods=_validated_bool(
                    api_view, 'allow_magic_methods', DEFAULT_CONFIG_API.allow_magic_methods
                ),
                allow_metaclasses=_validated_bool(api_view, 'allow_metaclasses', DEFAULT_CONFIG_API.allow_metaclasses),
                allow_unsafe=_validated_bool(api_view, 'allow_unsafe', DEFAULT_CONFIG_API.allow_unsafe),
                count_iterations_as_operations=_validated_bool(
                    api_view, 'count_iterations_as_operations', DEFAULT_CONFIG_API.count_iterations_as_operations
                ),
                frozen_mode=_validated_bool(api_view, 'frozen_mode', DEFAULT_CONFIG_API.frozen_mode),
                auto_mutable=_validated_bool(api_view, 'auto_mutable', DEFAULT_CONFIG_API.auto_mutable),
            )
            logger.info(
                'sandbox API config loaded',
                file=str(self._config_file),
                max_operations=self._current_config.max_operations,
                max_iterations=self._current_config.max_iterations,
            )
        except (ValueError, TypeError, KeyError) as e:
            logger.error(
                'failed to load sandbox API config, keeping previous config',
                file=str(self._config_file),
                error=str(e),
            )
        except Exception:
            logger.exception(
                'unexpected error loading sandbox API config, keeping previous config',
                file=str(self._config_file),
            )

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

    @property
    def default_config(self) -> SandboxConfig | None:
        """Default config from settings."""
        return self._default_config
