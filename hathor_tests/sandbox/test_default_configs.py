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

"""Tests for sandbox DEFAULT_CONFIG instances and DISABLED_CONFIG."""

import unittest

from hathor.nanocontracts.sandbox import (
    DEFAULT_CONFIG_API,
    DEFAULT_CONFIG_EXECUTION,
    DEFAULT_CONFIG_LOADING,
    DISABLED_CONFIG,
    DisabledSandboxConfig,
    SandboxConfig,
)


class TestDefaultConfigs(unittest.TestCase):
    """Tests for the default sandbox configuration instances."""

    def test_disabled_config_has_is_enabled_false(self) -> None:
        """DISABLED_CONFIG should have is_enabled=False."""
        self.assertFalse(DISABLED_CONFIG.is_enabled)

    def test_disabled_config_is_sandbox_config(self) -> None:
        """DISABLED_CONFIG should be a DisabledSandboxConfig instance."""
        self.assertIsInstance(DISABLED_CONFIG, SandboxConfig)
        self.assertIsInstance(DISABLED_CONFIG, DisabledSandboxConfig)

    def test_default_config_loading_values(self) -> None:
        """DEFAULT_CONFIG_LOADING should have correct values."""
        self.assertTrue(DEFAULT_CONFIG_LOADING.is_enabled)
        self.assertEqual(DEFAULT_CONFIG_LOADING.max_operations, 100_000)
        self.assertEqual(DEFAULT_CONFIG_LOADING.max_iterations, 10_000_000)  # class default
        self.assertFalse(DEFAULT_CONFIG_LOADING.allow_dunder_access)  # class default

    def test_default_config_execution_values(self) -> None:
        """DEFAULT_CONFIG_EXECUTION should have correct values (class defaults)."""
        self.assertTrue(DEFAULT_CONFIG_EXECUTION.is_enabled)
        self.assertEqual(DEFAULT_CONFIG_EXECUTION.max_operations, 1_000_000)  # class default
        self.assertEqual(DEFAULT_CONFIG_EXECUTION.max_iterations, 10_000_000)  # class default
        self.assertFalse(DEFAULT_CONFIG_EXECUTION.allow_dunder_access)  # class default

    def test_default_config_api_values(self) -> None:
        """DEFAULT_CONFIG_API should have correct values for API views."""
        self.assertTrue(DEFAULT_CONFIG_API.is_enabled)
        self.assertEqual(DEFAULT_CONFIG_API.max_operations, 10_000_000)
        self.assertEqual(DEFAULT_CONFIG_API.max_iterations, 100_000_000)
        self.assertFalse(DEFAULT_CONFIG_API.allow_dunder_access)  # dunders never allowed

    def test_configs_are_frozen(self) -> None:
        """All config instances should be frozen (immutable)."""
        configs = [
            DISABLED_CONFIG,
            DEFAULT_CONFIG_LOADING,
            DEFAULT_CONFIG_EXECUTION,
            DEFAULT_CONFIG_API,
        ]
        for config in configs:
            with self.assertRaises(Exception):  # FrozenInstanceError or AttributeError
                config.max_operations = 999  # type: ignore[misc]

    def test_disabled_config_apply_is_noop(self) -> None:
        """DISABLED_CONFIG.apply() should be a no-op (not raise)."""
        # This should not raise even without sys.sandbox available
        DISABLED_CONFIG.apply()

    def test_loading_has_lower_ops_than_execution(self) -> None:
        """Loading config should have lower operation limit than execution."""
        self.assertLess(
            DEFAULT_CONFIG_LOADING.max_operations,
            DEFAULT_CONFIG_EXECUTION.max_operations
        )

    def test_api_has_higher_ops_than_execution(self) -> None:
        """API config should have higher operation limit than execution."""
        self.assertGreater(
            DEFAULT_CONFIG_API.max_operations,
            DEFAULT_CONFIG_EXECUTION.max_operations
        )

    def test_api_has_higher_iterations_than_execution(self) -> None:
        """API config should have higher iteration limit than execution."""
        self.assertGreater(
            DEFAULT_CONFIG_API.max_iterations,
            DEFAULT_CONFIG_EXECUTION.max_iterations
        )


if __name__ == '__main__':
    unittest.main()
