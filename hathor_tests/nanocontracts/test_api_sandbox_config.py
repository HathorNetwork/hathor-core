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

"""Tests for API sandbox config integration."""

import dataclasses
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from hathor.builder import BuildArtifacts, Builder
from hathor.builder.sysctl_builder import SysctlBuilder
from hathor.nanocontracts.sandbox import SandboxAPIConfigLoader
from hathor.nanocontracts.sandbox.config import SandboxConfig
from hathor.sysctl.nanocontracts.sandbox_api import SandboxAPISysctl


class BuildArtifactsSandboxConfigTest(unittest.TestCase):
    """Tests for BuildArtifacts containing sandbox_api_config_loader."""

    def test_build_artifacts_has_sandbox_api_config_loader_field(self) -> None:
        """Test that BuildArtifacts has the sandbox_api_config_loader field."""
        # Check the field exists in the NamedTuple
        self.assertIn('sandbox_api_config_loader', BuildArtifacts._fields)

    def test_build_artifacts_allows_none_loader(self) -> None:
        """Test that BuildArtifacts can have None for sandbox_api_config_loader."""
        # Create a minimal mock artifacts to check the field
        artifacts = BuildArtifacts(
            peer=Mock(),
            settings=Mock(),
            rng=Mock(),
            reactor=Mock(),
            manager=Mock(),
            p2p_manager=Mock(),
            pubsub=Mock(),
            consensus=Mock(),
            tx_storage=Mock(),
            feature_service=Mock(),
            bit_signaling_service=Mock(),
            indexes=Mock(),
            wallet=None,
            rocksdb_storage=Mock(),
            stratum_factory=None,
            sandbox_api_config_loader=None,
        )
        self.assertIsNone(artifacts.sandbox_api_config_loader)

    def test_build_artifacts_allows_loader_instance(self) -> None:
        """Test that BuildArtifacts can have a SandboxAPIConfigLoader instance."""
        loader = SandboxAPIConfigLoader(None)
        artifacts = BuildArtifacts(
            peer=Mock(),
            settings=Mock(),
            rng=Mock(),
            reactor=Mock(),
            manager=Mock(),
            p2p_manager=Mock(),
            pubsub=Mock(),
            consensus=Mock(),
            tx_storage=Mock(),
            feature_service=Mock(),
            bit_signaling_service=Mock(),
            indexes=Mock(),
            wallet=None,
            rocksdb_storage=Mock(),
            stratum_factory=None,
            sandbox_api_config_loader=loader,
        )
        self.assertIs(artifacts.sandbox_api_config_loader, loader)


class SysctlBuilderSandboxConfigTest(unittest.TestCase):
    """Tests for SysctlBuilder using artifacts' sandbox_api_config_loader."""

    def test_sysctl_builder_uses_artifacts_loader(self) -> None:
        """Test that SysctlBuilder uses the loader from artifacts."""
        # Create a mock loader
        loader = SandboxAPIConfigLoader(None)

        # Create mock artifacts with the loader
        mock_settings = Mock()
        mock_settings.ENABLE_NANO_CONTRACTS = True
        mock_manager = Mock()
        mock_manager.websocket_factory = None

        artifacts = BuildArtifacts(
            peer=Mock(),
            settings=mock_settings,
            rng=Mock(),
            reactor=Mock(),
            manager=mock_manager,
            p2p_manager=Mock(),
            pubsub=Mock(),
            consensus=Mock(),
            tx_storage=Mock(),
            feature_service=Mock(),
            bit_signaling_service=Mock(),
            indexes=Mock(),
            wallet=None,
            rocksdb_storage=Mock(),
            stratum_factory=None,
            sandbox_api_config_loader=loader,
        )

        # Build sysctl
        sysctl_builder = SysctlBuilder(artifacts)
        sysctl = sysctl_builder.build()

        # The nc_sandbox_api child should exist
        nc_sandbox_api = sysctl._children.get('nc_sandbox_api')
        self.assertIsNotNone(nc_sandbox_api)

        # The sysctl's loader should be the same instance from artifacts
        from hathor.sysctl.nanocontracts import SandboxAPISysctl
        self.assertIsInstance(nc_sandbox_api, SandboxAPISysctl)
        assert isinstance(nc_sandbox_api, SandboxAPISysctl)  # for mypy
        self.assertIs(nc_sandbox_api.loader, loader)

    def test_sysctl_builder_skips_sysctl_when_no_loader(self) -> None:
        """Test that SysctlBuilder doesn't create nc_sandbox_api sysctl when loader is None."""
        # Create mock artifacts without loader
        mock_settings = Mock()
        mock_settings.ENABLE_NANO_CONTRACTS = True
        mock_manager = Mock()
        mock_manager.websocket_factory = None

        artifacts = BuildArtifacts(
            peer=Mock(),
            settings=mock_settings,
            rng=Mock(),
            reactor=Mock(),
            manager=mock_manager,
            p2p_manager=Mock(),
            pubsub=Mock(),
            consensus=Mock(),
            tx_storage=Mock(),
            feature_service=Mock(),
            bit_signaling_service=Mock(),
            indexes=Mock(),
            wallet=None,
            rocksdb_storage=Mock(),
            stratum_factory=None,
            sandbox_api_config_loader=None,
        )

        # Build sysctl
        sysctl_builder = SysctlBuilder(artifacts)
        sysctl = sysctl_builder.build()

        # The nc_sandbox_api child should NOT exist
        nc_sandbox_api = sysctl._children.get('nc_sandbox_api')
        self.assertIsNone(nc_sandbox_api)

    def test_sysctl_builder_skips_sysctl_when_nano_disabled(self) -> None:
        """Test that SysctlBuilder doesn't create nc_sandbox_api when nano is disabled."""
        loader = SandboxAPIConfigLoader(None)

        mock_settings = Mock()
        mock_settings.ENABLE_NANO_CONTRACTS = False  # Nano contracts disabled
        mock_manager = Mock()
        mock_manager.websocket_factory = None

        artifacts = BuildArtifacts(
            peer=Mock(),
            settings=mock_settings,
            rng=Mock(),
            reactor=Mock(),
            manager=mock_manager,
            p2p_manager=Mock(),
            pubsub=Mock(),
            consensus=Mock(),
            tx_storage=Mock(),
            feature_service=Mock(),
            bit_signaling_service=Mock(),
            indexes=Mock(),
            wallet=None,
            rocksdb_storage=Mock(),
            stratum_factory=None,
            sandbox_api_config_loader=loader,
        )

        # Build sysctl
        sysctl_builder = SysctlBuilder(artifacts)
        sysctl = sysctl_builder.build()

        # The nc_sandbox_api child should NOT exist
        nc_sandbox_api = sysctl._children.get('nc_sandbox_api')
        self.assertIsNone(nc_sandbox_api)


class BuilderSandboxConfigLoaderTest(unittest.TestCase):
    """Tests for Builder creating sandbox_api_config_loader."""

    def test_builder_get_or_create_sandbox_api_config_loader_returns_none_when_disabled(self) -> None:
        """Test that _get_or_create_sandbox_api_config_loader returns None when nano is disabled."""
        mock_settings = Mock()
        mock_settings.ENABLE_NANO_CONTRACTS = False

        builder = Builder()
        builder._settings = mock_settings

        result = builder._get_or_create_sandbox_api_config_loader()
        self.assertIsNone(result)

    def test_builder_get_or_create_sandbox_api_config_loader_creates_loader_with_no_config(self) -> None:
        """Test that _get_or_create_sandbox_api_config_loader creates loader even with no default config.

        When nano contracts are enabled, a loader is always created. If no default config is set,
        the loader uses DISABLED_CONFIG.
        """
        mock_settings = Mock()
        mock_settings.ENABLE_NANO_CONTRACTS = True
        mock_settings.NC_SANDBOX_CONFIG_API = None  # No default config

        builder = Builder()
        builder._settings = mock_settings

        result = builder._get_or_create_sandbox_api_config_loader()
        self.assertIsNotNone(result)
        assert result is not None  # for mypy
        self.assertIsInstance(result, SandboxAPIConfigLoader)
        # Config should be DISABLED_CONFIG (enabled=False) when no default config
        self.assertFalse(result.config.enabled)

    def test_builder_get_or_create_sandbox_api_config_loader_with_default_config(self) -> None:
        """Test that _get_or_create_sandbox_api_config_loader creates loader with default config."""
        from hathor.nanocontracts.sandbox import DEFAULT_CONFIG_API

        mock_settings = Mock()
        mock_settings.ENABLE_NANO_CONTRACTS = True
        mock_settings.NC_SANDBOX_CONFIG_API = DEFAULT_CONFIG_API

        builder = Builder()
        builder._settings = mock_settings

        result = builder._get_or_create_sandbox_api_config_loader()
        self.assertIsNotNone(result)
        assert result is not None  # for mypy
        self.assertIsInstance(result, SandboxAPIConfigLoader)
        self.assertEqual(result.config, DEFAULT_CONFIG_API)

    def test_builder_get_or_create_sandbox_api_config_loader_with_file_override(self) -> None:
        """Test that _get_or_create_sandbox_api_config_loader uses file override when specified."""
        from hathor.nanocontracts.sandbox import DEFAULT_CONFIG_API

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
            mock_settings = Mock()
            mock_settings.ENABLE_NANO_CONTRACTS = True
            mock_settings.NC_SANDBOX_CONFIG_API = DEFAULT_CONFIG_API

            builder = Builder()
            builder._settings = mock_settings
            builder._sandbox_api_config_file = temp_path  # Set CLI file path

            result = builder._get_or_create_sandbox_api_config_loader()
            self.assertIsNotNone(result)
            assert result is not None  # for mypy
            self.assertIsInstance(result, SandboxAPIConfigLoader)
            # Config should be from file, not default
            self.assertEqual(result.config.max_operations, 1000000)
        finally:
            Path(temp_path).unlink()

    def test_builder_get_or_create_sandbox_api_config_loader_is_singleton(self) -> None:
        """Test that _get_or_create_sandbox_api_config_loader returns the same instance."""
        from hathor.nanocontracts.sandbox import DEFAULT_CONFIG_API

        mock_settings = Mock()
        mock_settings.ENABLE_NANO_CONTRACTS = True
        mock_settings.NC_SANDBOX_CONFIG_API = DEFAULT_CONFIG_API

        builder = Builder()
        builder._settings = mock_settings

        result1 = builder._get_or_create_sandbox_api_config_loader()
        result2 = builder._get_or_create_sandbox_api_config_loader()
        self.assertIs(result1, result2)


class SandboxAPISysctlGetStatusTest(unittest.TestCase):
    """Tests for SandboxAPISysctl.get_status() completeness and correctness."""

    def test_get_status_contains_all_sandbox_config_fields(self) -> None:
        """Test that get_status() config dict contains all SandboxConfig dataclass fields.

        This test dynamically inspects SandboxConfig fields so it will automatically
        fail if a new field is added without updating get_status().
        """
        loader = SandboxAPIConfigLoader(None)
        sysctl = SandboxAPISysctl(loader)

        status = sysctl.get_status()
        config_dict = status['config']
        self.assertIsNotNone(config_dict)

        expected_fields = {f.name for f in dataclasses.fields(SandboxConfig)}
        actual_fields = set(config_dict.keys())

        missing = expected_fields - actual_fields
        self.assertEqual(missing, set(), f'get_status() is missing SandboxConfig fields: {missing}')

    def test_get_status_returns_correct_values(self) -> None:
        """Test that get_status() returns the correct config values."""
        loader = SandboxAPIConfigLoader(None)
        sysctl = SandboxAPISysctl(loader)

        status = sysctl.get_status()
        config_dict = status['config']
        self.assertIsNotNone(config_dict)

        # Check default values from SandboxConfig (DEFAULT_CONFIG_API used by SandboxAPIConfigLoader)
        config = loader.config
        assert config is not None
        for field in dataclasses.fields(SandboxConfig):
            self.assertEqual(
                config_dict[field.name],
                getattr(config, field.name),
                f'Mismatch for field {field.name}',
            )

    def test_get_status_returns_disabled_config(self) -> None:
        """Test that get_status() returns config with enabled=False when disabled."""
        loader = SandboxAPIConfigLoader(None)
        loader.disable()
        sysctl = SandboxAPISysctl(loader)

        status = sysctl.get_status()
        # disable() sets DISABLED_CONFIG (enabled=False), not None
        self.assertIsNotNone(status['config'])
        self.assertFalse(status['config']['enabled'])


class SandboxAPISysctlFrozensetCommandsTest(unittest.TestCase):
    """Tests for read-only sysctl commands that expose frozenset allowlists."""

    def setUp(self) -> None:
        loader = SandboxAPIConfigLoader(None)
        self.sysctl = SandboxAPISysctl(loader)

    def test_allowed_opcodes_returns_sorted_list_of_strings(self) -> None:
        """Test that get_allowed_opcodes returns a sorted list of strings."""
        result = self.sysctl.get_allowed_opcodes()
        self.assertIsInstance(result, list)
        self.assertTrue(all(isinstance(item, str) for item in result))
        self.assertEqual(result, sorted(result))
        self.assertIn('LOAD_CONST', result)

    def test_allowed_imports_returns_sorted_list_of_strings(self) -> None:
        """Test that get_allowed_imports returns a sorted list of dotted strings."""
        result = self.sysctl.get_allowed_imports()
        self.assertIsInstance(result, list)
        self.assertTrue(all(isinstance(item, str) for item in result))
        self.assertEqual(result, sorted(result))
        self.assertIn('hathor.Blueprint', result)

    def test_allowed_modules_returns_sorted_list_of_strings(self) -> None:
        """Test that get_allowed_modules returns a sorted list of module names."""
        result = self.sysctl.get_allowed_modules()
        self.assertIsInstance(result, list)
        self.assertTrue(all(isinstance(item, str) for item in result))
        self.assertEqual(result, sorted(result))
        self.assertIn('hathor', result)
        self.assertIn('math', result)

    def test_allowed_metaclasses_returns_list_of_strings(self) -> None:
        """Test that get_allowed_metaclasses returns a list of qualname strings."""
        result = self.sysctl.get_allowed_metaclasses()
        self.assertIsInstance(result, list)
        self.assertTrue(all(isinstance(item, str) for item in result))
        self.assertIn('_BlueprintBase', result)


if __name__ == '__main__':
    unittest.main()
