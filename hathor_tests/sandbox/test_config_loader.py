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

"""Tests for SandboxAPIConfigLoader."""

import tempfile
import unittest
from pathlib import Path

from hathor.nanocontracts.sandbox import DEFAULT_CONFIG_API, DISABLED_CONFIG, SandboxAPIConfigLoader


class SandboxAPIConfigLoaderTest(unittest.TestCase):
    """Tests for the SandboxAPIConfigLoader class."""

    def test_init_with_disabled_config(self) -> None:
        """Test initializing with DISABLED_CONFIG."""
        loader = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG)
        self.assertFalse(loader.config.is_enabled)  # DISABLED_CONFIG
        self.assertIsNone(loader.config_file)
        self.assertEqual(loader.default_config, DISABLED_CONFIG)

    def test_init_with_default_config(self) -> None:
        """Test initializing with a default config."""
        loader = SandboxAPIConfigLoader(default_config=DEFAULT_CONFIG_API)
        self.assertEqual(loader.config, DEFAULT_CONFIG_API)
        self.assertIsNone(loader.config_file)
        self.assertEqual(loader.default_config, DEFAULT_CONFIG_API)

    def test_init_with_nonexistent_file(self) -> None:
        """Test initializing with a nonexistent file falls back to default config."""
        loader = SandboxAPIConfigLoader(
            default_config=DEFAULT_CONFIG_API,
            config_file='/path/that/does/not/exist.yaml'
        )
        # Falls back to default config when file doesn't exist
        self.assertEqual(loader.config, DEFAULT_CONFIG_API)
        self.assertEqual(loader.config_file, Path('/path/that/does/not/exist.yaml'))

    def test_init_with_nonexistent_file_disabled_default(self) -> None:
        """Test initializing with a nonexistent file and DISABLED_CONFIG returns DISABLED_CONFIG."""
        loader = SandboxAPIConfigLoader(
            default_config=DISABLED_CONFIG,
            config_file='/path/that/does/not/exist.yaml',
        )
        self.assertFalse(loader.config.is_enabled)  # DISABLED_CONFIG
        self.assertEqual(loader.config_file, Path('/path/that/does/not/exist.yaml'))

    def test_load_from_valid_yaml(self) -> None:
        """Test loading config from a valid YAML file."""
        yaml_content = """
api_view:
  enabled: true
  max_operations: 5000000
  max_iterations: 50000000
  max_int_digits: 200
  max_str_length: 500000
  max_bytes_length: 500000
  max_list_size: 50000
  max_dict_size: 50000
  max_set_size: 50000
  max_tuple_size: 50000
  allow_float: true
  allow_complex: true
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            temp_path = f.name

        try:
            loader = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG, config_file=temp_path)
            self.assertIsNotNone(loader.config)
            config = loader.config
            assert config is not None
            self.assertEqual(config.max_operations, 5000000)
            self.assertEqual(config.max_iterations, 50000000)
            self.assertEqual(config.max_int_digits, 200)
            self.assertEqual(config.max_str_length, 500000)
            self.assertEqual(config.max_bytes_length, 500000)
            self.assertEqual(config.max_list_size, 50000)
            self.assertEqual(config.max_dict_size, 50000)
            self.assertEqual(config.max_set_size, 50000)
            self.assertEqual(config.max_tuple_size, 50000)
            self.assertTrue(config.allow_float)
            self.assertTrue(config.allow_complex)
        finally:
            Path(temp_path).unlink()

    def test_load_with_disabled_config(self) -> None:
        """Test loading config that's explicitly disabled."""
        yaml_content = """
api_view:
  enabled: false
  max_operations: 5000000
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            temp_path = f.name

        try:
            loader = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG, config_file=temp_path)
            self.assertFalse(loader.config.is_enabled)  # DisabledSandboxConfig
        finally:
            Path(temp_path).unlink()

    def test_load_with_empty_file(self) -> None:
        """Test loading from an empty YAML file."""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write('')
            f.flush()
            temp_path = f.name

        try:
            loader = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG, config_file=temp_path)
            # Empty file should load with default values since api_view section doesn't exist
            self.assertIsNotNone(loader.config)
        finally:
            Path(temp_path).unlink()

    def test_load_with_defaults(self) -> None:
        """Test loading with minimal config uses defaults."""
        yaml_content = """
api_view:
  enabled: true
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            temp_path = f.name

        try:
            loader = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG, config_file=temp_path)
            self.assertIsNotNone(loader.config)
            config = loader.config
            assert config is not None
            # Check defaults are used
            self.assertEqual(config.max_operations, 10_000_000)  # Default for API views
            self.assertEqual(config.max_iterations, 100_000_000)  # Default for API views
            self.assertEqual(config.max_int_digits, 100)  # Default
        finally:
            Path(temp_path).unlink()

    def test_reload_functionality(self) -> None:
        """Test reload() method reloads config from file."""
        yaml_content_v1 = """
api_view:
  enabled: true
  max_operations: 1000000
"""
        yaml_content_v2 = """
api_view:
  enabled: true
  max_operations: 2000000
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content_v1)
            f.flush()
            temp_path = f.name

        try:
            loader = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG, config_file=temp_path)
            self.assertIsNotNone(loader.config)
            assert loader.config is not None
            self.assertEqual(loader.config.max_operations, 1000000)

            # Modify the file
            with open(temp_path, 'w') as f:
                f.write(yaml_content_v2)

            # Reload and check
            changed = loader.reload()
            self.assertTrue(changed)
            self.assertIsNotNone(loader.config)
            assert loader.config is not None
            self.assertEqual(loader.config.max_operations, 2000000)
        finally:
            Path(temp_path).unlink()

    def test_reload_no_change(self) -> None:
        """Test reload() returns False when config hasn't changed."""
        yaml_content = """
api_view:
  enabled: true
  max_operations: 1000000
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            temp_path = f.name

        try:
            loader = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG, config_file=temp_path)
            changed = loader.reload()
            self.assertFalse(changed)  # No change
        finally:
            Path(temp_path).unlink()

    def test_disable_functionality(self) -> None:
        """Test disable() sets config to DISABLED_CONFIG."""
        yaml_content = """
api_view:
  enabled: true
  max_operations: 1000000
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            temp_path = f.name

        try:
            loader = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG, config_file=temp_path)
            self.assertTrue(loader.config.is_enabled)

            loader.disable()
            self.assertFalse(loader.config.is_enabled)
        finally:
            Path(temp_path).unlink()

    def test_set_file_changes_file(self) -> None:
        """Test set_file() changes the config file and reloads."""
        yaml_content_1 = """
api_view:
  enabled: true
  max_operations: 1000000
"""
        yaml_content_2 = """
api_view:
  enabled: true
  max_operations: 3000000
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f1:
            f1.write(yaml_content_1)
            f1.flush()
            temp_path_1 = f1.name

        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f2:
            f2.write(yaml_content_2)
            f2.flush()
            temp_path_2 = f2.name

        try:
            loader = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG, config_file=temp_path_1)
            self.assertIsNotNone(loader.config)
            assert loader.config is not None
            self.assertEqual(loader.config.max_operations, 1000000)

            # Change to new file
            success = loader.set_file(temp_path_2)
            self.assertTrue(success)
            self.assertIsNotNone(loader.config)
            assert loader.config is not None
            self.assertEqual(loader.config.max_operations, 3000000)
        finally:
            Path(temp_path_1).unlink()
            Path(temp_path_2).unlink()

    def test_set_file_nonexistent_returns_false(self) -> None:
        """Test set_file() returns False for nonexistent file."""
        yaml_content = """
api_view:
  enabled: true
  max_operations: 1000000
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            temp_path = f.name

        try:
            loader = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG, config_file=temp_path)
            original_config = loader.config

            # Try to set a nonexistent file
            success = loader.set_file('/path/that/does/not/exist.yaml')
            self.assertFalse(success)
            # Config should remain unchanged
            self.assertEqual(loader.config, original_config)
        finally:
            Path(temp_path).unlink()

    def test_set_file_to_none_uses_default(self) -> None:
        """Test set_file(None) falls back to default config."""
        yaml_content = """
api_view:
  enabled: true
  max_operations: 1000000
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            temp_path = f.name

        try:
            # Create loader with default config and file override
            loader = SandboxAPIConfigLoader(
                default_config=DEFAULT_CONFIG_API,
                config_file=temp_path
            )
            # Config comes from file
            self.assertEqual(loader.config.max_operations, 1000000)

            # Setting file to None should fall back to default config
            success = loader.set_file(None)
            self.assertTrue(success)
            self.assertEqual(loader.config, DEFAULT_CONFIG_API)
            self.assertIsNone(loader.config_file)
        finally:
            Path(temp_path).unlink()

    def test_set_file_to_none_with_no_default_disables(self) -> None:
        """Test set_file(None) with no default config uses DISABLED_CONFIG."""
        yaml_content = """
api_view:
  enabled: true
  max_operations: 1000000
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            temp_path = f.name

        try:
            # Create loader with no default config
            loader = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG, config_file=temp_path)
            self.assertTrue(loader.config.is_enabled)

            success = loader.set_file(None)
            self.assertTrue(success)
            self.assertFalse(loader.config.is_enabled)  # DISABLED_CONFIG
            self.assertIsNone(loader.config_file)
        finally:
            Path(temp_path).unlink()

    def test_invalid_yaml_keeps_previous_config(self) -> None:
        """Test that invalid YAML keeps the previous config."""
        yaml_content_valid = """
api_view:
  enabled: true
  max_operations: 1000000
"""
        yaml_content_invalid = """
api_view:
  enabled: [[[invalid yaml
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content_valid)
            f.flush()
            temp_path = f.name

        try:
            loader = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG, config_file=temp_path)
            self.assertIsNotNone(loader.config)
            assert loader.config is not None
            original_max_ops = loader.config.max_operations

            # Overwrite with invalid YAML
            with open(temp_path, 'w') as f:
                f.write(yaml_content_invalid)

            # Reload should keep previous config
            loader.reload()
            self.assertIsNotNone(loader.config)
            assert loader.config is not None
            self.assertEqual(loader.config.max_operations, original_max_ops)
        finally:
            Path(temp_path).unlink()

    def test_path_type_flexibility(self) -> None:
        """Test that loader accepts both str and Path objects."""
        yaml_content = """
api_view:
  enabled: true
  max_operations: 5000000
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            temp_path = f.name

        try:
            # Test with string
            loader_str = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG, config_file=temp_path)
            self.assertIsNotNone(loader_str.config)

            # Test with Path
            loader_path = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG, config_file=Path(temp_path))
            self.assertIsNotNone(loader_path.config)

            # Both should have same config
            assert loader_str.config is not None
            assert loader_path.config is not None
            self.assertEqual(loader_str.config.max_operations, loader_path.config.max_operations)
        finally:
            Path(temp_path).unlink()


class SandboxAPIConfigLoaderValidationTest(unittest.TestCase):
    """Tests for YAML config validation (Pydantic strict validation).

    With Pydantic validation, any invalid field rejects the entire config
    (keeping the previous config). This is stricter than per-field fallback
    but provides clearer error messages and consistent behavior.
    """

    def test_string_value_for_int_field_rejects_config(self) -> None:
        """Test that a string value for an int field rejects the entire config."""
        yaml_content = """
api_view:
  enabled: true
  max_operations: "unlimited"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            temp_path = f.name

        try:
            loader = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG, config_file=temp_path)
            # Validation fails → keeps initial DISABLED_CONFIG
            self.assertFalse(loader.config.is_enabled)
        finally:
            Path(temp_path).unlink()

    def test_negative_value_for_int_field_rejects_config(self) -> None:
        """Test that a negative value for an int field rejects the entire config."""
        yaml_content = """
api_view:
  enabled: true
  max_operations: -1
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            temp_path = f.name

        try:
            loader = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG, config_file=temp_path)
            # Validation fails → keeps initial DISABLED_CONFIG
            self.assertFalse(loader.config.is_enabled)
        finally:
            Path(temp_path).unlink()

    def test_bool_value_for_int_field_rejects_config(self) -> None:
        """Test that a boolean value for an int field rejects the config (strict mode)."""
        yaml_content = """
api_view:
  enabled: true
  max_operations: true
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            temp_path = f.name

        try:
            loader = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG, config_file=temp_path)
            # Validation fails → keeps initial DISABLED_CONFIG
            self.assertFalse(loader.config.is_enabled)
        finally:
            Path(temp_path).unlink()

    def test_string_value_for_bool_field_rejects_config(self) -> None:
        """Test that a string value for a bool field rejects the config."""
        yaml_content = """
api_view:
  enabled: true
  allow_float: "yes"
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            temp_path = f.name

        try:
            loader = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG, config_file=temp_path)
            # Validation fails → keeps initial DISABLED_CONFIG
            self.assertFalse(loader.config.is_enabled)
        finally:
            Path(temp_path).unlink()

    def test_int_value_for_bool_field_rejects_config(self) -> None:
        """Test that an int value for a bool field rejects the config (strict mode)."""
        yaml_content = """
api_view:
  enabled: true
  allow_float: 1
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            temp_path = f.name

        try:
            loader = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG, config_file=temp_path)
            # Validation fails → keeps initial DISABLED_CONFIG
            self.assertFalse(loader.config.is_enabled)
        finally:
            Path(temp_path).unlink()

    def test_api_view_as_list_keeps_previous_config(self) -> None:
        """Test that api_view as a list (not dict) keeps previous config."""
        yaml_content = """
api_view:
  - enabled
  - max_operations
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            temp_path = f.name

        try:
            loader = SandboxAPIConfigLoader(
                default_config=DEFAULT_CONFIG_API,
                config_file=temp_path,
            )
            # api_view is a list, not a dict → ValueError → keeps previous config (DISABLED_CONFIG at init)
            self.assertFalse(loader.config.is_enabled)
        finally:
            Path(temp_path).unlink()

    def test_zero_value_for_int_field_accepted(self) -> None:
        """Test that zero is a valid value for int fields."""
        yaml_content = """
api_view:
  enabled: true
  max_operations: 0
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            temp_path = f.name

        try:
            loader = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG, config_file=temp_path)
            self.assertEqual(loader.config.max_operations, 0)
        finally:
            Path(temp_path).unlink()

    def test_invalid_fields_reject_entire_config(self) -> None:
        """Test that any invalid field rejects the entire config."""
        yaml_content = """
api_view:
  enabled: true
  max_operations: "bad"
  max_int_digits: 500
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            temp_path = f.name

        try:
            loader = SandboxAPIConfigLoader(default_config=DISABLED_CONFIG, config_file=temp_path)
            # Validation fails → keeps initial DISABLED_CONFIG (entire config rejected)
            self.assertFalse(loader.config.is_enabled)
        finally:
            Path(temp_path).unlink()


if __name__ == '__main__':
    unittest.main()
