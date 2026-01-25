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

"""Unit tests for sandbox data classes and sysctl path validation."""

import tempfile
import unittest
from pathlib import Path

from hathor.nanocontracts.sandbox import SandboxAPIConfigLoader
from hathor.nanocontracts.sandbox.config import DISABLED_CONFIG, SandboxConfig
from hathor.nanocontracts.sandbox.counts import SandboxCounts, SandboxCounters
from hathor.sysctl.nanocontracts.sandbox_api import SandboxAPISysctl


class SandboxCountsArithmeticTest(unittest.TestCase):
    """Tests for SandboxCounts __sub__ and __bool__."""

    def test_sub_positive_delta(self) -> None:
        """Test subtraction produces correct delta."""
        before = SandboxCounts(operation_count=100, iteration_count=50)
        after = SandboxCounts(operation_count=350, iteration_count=200)
        delta = after - before
        self.assertEqual(delta.operation_count, 250)
        self.assertEqual(delta.iteration_count, 150)

    def test_sub_zero_delta(self) -> None:
        """Test subtraction of equal counts produces zero."""
        counts = SandboxCounts(operation_count=100, iteration_count=50)
        delta = counts - counts
        self.assertEqual(delta.operation_count, 0)
        self.assertEqual(delta.iteration_count, 0)

    def test_bool_true_with_operations(self) -> None:
        """Test that non-zero operation_count is truthy."""
        counts = SandboxCounts(operation_count=1, iteration_count=0)
        self.assertTrue(counts)

    def test_bool_true_with_iterations(self) -> None:
        """Test that non-zero iteration_count is truthy."""
        counts = SandboxCounts(operation_count=0, iteration_count=1)
        self.assertTrue(counts)

    def test_bool_false_when_zero(self) -> None:
        """Test that zero counts is falsy."""
        counts = SandboxCounts()
        self.assertFalse(counts)

    def test_from_dict(self) -> None:
        """Test from_dict constructor."""
        counts = SandboxCounts.from_dict({'operation_count': 42, 'iteration_count': 7})
        self.assertEqual(counts.operation_count, 42)
        self.assertEqual(counts.iteration_count, 7)

    def test_from_dict_with_missing_keys(self) -> None:
        """Test from_dict with missing keys defaults to 0."""
        counts = SandboxCounts.from_dict({})
        self.assertEqual(counts.operation_count, 0)
        self.assertEqual(counts.iteration_count, 0)

    def test_to_dict(self) -> None:
        """Test to_dict round trip."""
        counts = SandboxCounts(operation_count=42, iteration_count=7)
        d = counts.to_dict()
        self.assertEqual(d, {'operation_count': 42, 'iteration_count': 7})

    def test_to_dict_from_dict_round_trip(self) -> None:
        """Test that to_dict/from_dict are inverses."""
        original = SandboxCounts(operation_count=123, iteration_count=456)
        reconstructed = SandboxCounts.from_dict(original.to_dict())
        self.assertEqual(original, reconstructed)

    def test_frozen(self) -> None:
        """Test that SandboxCounts is immutable."""
        counts = SandboxCounts(operation_count=1, iteration_count=2)
        with self.assertRaises(Exception):
            counts.operation_count = 99  # type: ignore[misc]

    def test_capture_without_sandbox(self) -> None:
        """Test capture() returns zero counts when sandbox is not available."""
        # On non-sandbox Python, this should return zero counts without error
        counts = SandboxCounts.capture()
        self.assertEqual(counts.operation_count, 0)
        self.assertEqual(counts.iteration_count, 0)


class SandboxCountersTest(unittest.TestCase):
    """Tests for SandboxCounters lifecycle and assertion guards."""

    def test_initial_state(self) -> None:
        """Test initial state has None for before and after."""
        counters = SandboxCounters()
        self.assertIsNone(counters.before)
        self.assertIsNone(counters.after)

    def test_capture_before(self) -> None:
        """Test capture_before sets before but not after."""
        counters = SandboxCounters()
        counters.capture_before()
        self.assertIsNotNone(counters.before)
        self.assertIsNone(counters.after)

    def test_capture_after_without_before_raises(self) -> None:
        """Test capture_after without capture_before raises AssertionError."""
        counters = SandboxCounters()
        with self.assertRaises(AssertionError, msg="must call capture_before() first"):
            counters.capture_after()

    def test_double_capture_before_raises(self) -> None:
        """Test calling capture_before twice raises AssertionError."""
        counters = SandboxCounters()
        counters.capture_before()
        with self.assertRaises(AssertionError, msg="before counters already captured"):
            counters.capture_before()

    def test_double_capture_after_raises(self) -> None:
        """Test calling capture_after twice raises AssertionError."""
        counters = SandboxCounters()
        counters.capture_before()
        counters.capture_after()
        with self.assertRaises(AssertionError, msg="after counters already captured"):
            counters.capture_after()

    def test_delta_with_incomplete_counters(self) -> None:
        """Test delta returns zero counts when counters are incomplete."""
        counters = SandboxCounters()
        self.assertEqual(counters.delta, SandboxCounts())

        counters.capture_before()
        self.assertEqual(counters.delta, SandboxCounts())

    def test_full_lifecycle(self) -> None:
        """Test full capture_before → capture_after → delta lifecycle."""
        counters = SandboxCounters()
        counters.capture_before()
        counters.capture_after()
        delta = counters.delta
        self.assertIsInstance(delta, SandboxCounts)


class SandboxConfigDisabledTest(unittest.TestCase):
    """Tests for DISABLED_CONFIG no-op behavior."""

    def test_apply_is_noop(self) -> None:
        """DISABLED_CONFIG.apply() should not raise even without sys.sandbox."""
        DISABLED_CONFIG.apply()

    def test_enable_is_noop(self) -> None:
        """DISABLED_CONFIG.enable() should not raise."""
        DISABLED_CONFIG.enable()

    def test_reset_is_noop(self) -> None:
        """DISABLED_CONFIG.reset() should not raise."""
        DISABLED_CONFIG.reset()

    def test_reset_counts_is_noop(self) -> None:
        """DISABLED_CONFIG.reset_counts() should not raise."""
        DISABLED_CONFIG.reset_counts()

    def test_get_counts_returns_empty(self) -> None:
        """DISABLED_CONFIG.get_counts() should return empty dict."""
        self.assertEqual(DISABLED_CONFIG.get_counts(), {})

    def test_set_mutable_is_noop(self) -> None:
        """DISABLED_CONFIG.set_mutable() should not raise."""
        DISABLED_CONFIG.set_mutable(object())

    def test_assert_active_is_noop(self) -> None:
        """DISABLED_CONFIG.assert_active() should not raise."""
        DISABLED_CONFIG.assert_active()

    def test_check_available_noop(self) -> None:
        """DISABLED_CONFIG.check_available() should not raise even without sys.sandbox."""
        DISABLED_CONFIG.check_available()

    def test_enabled_config_check_available_raises_without_sandbox(self) -> None:
        """Enabled config should raise when sys.sandbox is not available."""
        import sys
        if hasattr(sys, 'sandbox'):
            self.skipTest('sys.sandbox is available, cannot test unavailable case')
        config = SandboxConfig()  # enabled=True by default
        from hathor.nanocontracts.exception import SandboxRequiredButNotAvailable
        with self.assertRaises(SandboxRequiredButNotAvailable):
            config.check_available()


class SandboxAPISysctlPathValidationTest(unittest.TestCase):
    """Tests for sysctl set_file() path validation."""

    def setUp(self) -> None:
        self.loader = SandboxAPIConfigLoader(None)
        self.sysctl = SandboxAPISysctl(self.loader)

    def test_set_file_rejects_relative_path(self) -> None:
        """Test that set_file rejects relative paths."""
        with self.assertRaises(ValueError, msg='must be absolute'):
            self.sysctl.set_file('relative/path/config.yaml')

    def test_set_file_rejects_too_long_path(self) -> None:
        """Test that set_file rejects paths exceeding the length limit."""
        long_path = '/tmp/' + 'a' * 5000 + '.yaml'
        with self.assertRaises(ValueError, msg='too long'):
            self.sysctl.set_file(long_path)

    def test_set_file_rejects_directory(self) -> None:
        """Test that set_file rejects a directory path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaises(ValueError, msg='not a regular file'):
                self.sysctl.set_file(tmpdir)

    def test_set_file_nonexistent_raises_file_not_found(self) -> None:
        """Test that set_file raises FileNotFoundError for nonexistent files."""
        with self.assertRaises(FileNotFoundError):
            self.sysctl.set_file('/tmp/nonexistent_sandbox_config_12345.yaml')

    def test_set_file_accepts_valid_absolute_path(self) -> None:
        """Test that set_file accepts a valid absolute path to a YAML file."""
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
            self.sysctl.set_file(temp_path)
            self.assertEqual(self.loader.config.max_operations, 1000000)
        finally:
            Path(temp_path).unlink()


if __name__ == '__main__':
    unittest.main()
