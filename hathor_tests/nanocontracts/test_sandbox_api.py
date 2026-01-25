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

"""
Basic tests for the CPython sandbox API.

These tests verify the raw sandbox API behavior without any hathor-specific code.
They help understand how the sandbox works before integrating it with nanocontracts.
"""

import sys
import unittest


class SandboxAPIBasicTests(unittest.TestCase):
    """Test the basic sandbox API functions."""

    def setUp(self) -> None:
        """Reset sandbox state before each test."""
        # First ensure sandbox is suspended to not interfere with test setup
        if not sys.sandbox.suspended:
            sys.sandbox.suspend()

        # Clear any registered filenames
        sys.sandbox.clear_filenames()
        # Reset limits to permissive defaults (allow_float=True for pytest compatibility)
        sys.sandbox.set_limits(
            max_int_digits=1000,
            max_str_length=10_000_000,
            max_bytes_length=10_000_000,
            max_list_size=1_000_000,
            max_dict_size=1_000_000,
            max_set_size=1_000_000,
            max_tuple_size=1_000_000,
            max_statements=100_000_000,
            max_allocations=100_000_000,
            allow_float=True,  # Allow float for pytest compatibility
            allow_complex=True,
        )

    def tearDown(self) -> None:
        """Clean up sandbox state after each test."""
        # Ensure sandbox is suspended to not interfere with next test
        if not sys.sandbox.suspended:
            sys.sandbox.suspend()

    def test_sandbox_api_exists(self) -> None:
        """Test that the sandbox API functions exist."""
        self.assertTrue(hasattr(sys, 'sandbox'))
        self.assertTrue(hasattr(sys.sandbox, 'set_limits'))
        self.assertTrue(hasattr(sys.sandbox, 'get_limits'))
        self.assertTrue(hasattr(sys.sandbox, 'add_filename'))
        self.assertTrue(hasattr(sys.sandbox, 'remove_filename'))
        self.assertTrue(hasattr(sys.sandbox, 'clear_filenames'))
        self.assertTrue(hasattr(sys.sandbox, 'suspend'))
        self.assertTrue(hasattr(sys.sandbox, 'resume'))
        self.assertTrue(hasattr(sys.sandbox, 'suspended'))
        self.assertTrue(hasattr(sys.sandbox, 'reset_counts'))

    def test_suspend_resume_basic(self) -> None:
        """Test basic suspend/resume functionality."""
        # Initial state after setUp: suspended
        self.assertTrue(sys.sandbox.suspended)

        # Resume
        sys.sandbox.resume()
        self.assertFalse(sys.sandbox.suspended)

        # Suspend
        sys.sandbox.suspend()
        self.assertTrue(sys.sandbox.suspended)

    def test_suspend_resume_is_nested(self) -> None:
        """Test that suspend/resume uses a counter (nested)."""
        # Start from suspended state (count=1 from setUp)
        self.assertTrue(sys.sandbox.suspended)

        # Resume to not suspended
        sys.sandbox.resume()
        self.assertFalse(sys.sandbox.suspended)

        # Multiple suspends
        sys.sandbox.suspend()
        self.assertTrue(sys.sandbox.suspended)
        sys.sandbox.suspend()
        self.assertTrue(sys.sandbox.suspended)
        sys.sandbox.suspend()
        self.assertTrue(sys.sandbox.suspended)

        # Need same number of resumes (3)
        sys.sandbox.resume()
        self.assertTrue(sys.sandbox.suspended)  # Still suspended
        sys.sandbox.resume()
        self.assertTrue(sys.sandbox.suspended)  # Still suspended
        sys.sandbox.resume()
        self.assertFalse(sys.sandbox.suspended)  # Now not suspended

        # Re-suspend for tearDown
        sys.sandbox.suspend()

    def test_statement_limit_enforced(self) -> None:
        """Test that statement limit is enforced for tracked files."""
        filename = '<test-file>'
        # Must set limits while NOT suspended
        sys.sandbox.resume()
        sys.sandbox.set_limits(max_statements=50)
        sys.sandbox.add_filename(filename)
        sys.sandbox.suspend()

        # Compile code with tracked filename (while suspended)
        code = compile('for i in range(100): pass', filename, 'exec')

        # Resume sandbox, reset counters, execute
        sys.sandbox.reset_counts()
        sys.sandbox.resume()
        try:
            # Should raise RuntimeError due to statement limit
            with self.assertRaises(RuntimeError) as cm:
                exec(code, {})
            self.assertIn('limit', str(cm.exception).lower())
        finally:
            sys.sandbox.suspend()

    def test_statement_limit_not_enforced_when_suspended(self) -> None:
        """Test that statement limit is NOT enforced when suspended."""
        filename = '<test-file>'
        # Must set limits while NOT suspended
        sys.sandbox.resume()
        sys.sandbox.set_limits(max_statements=50)
        sys.sandbox.add_filename(filename)
        sys.sandbox.suspend()
        sys.sandbox.reset_counts()

        # Compile code with tracked filename
        code = compile('for i in range(100): pass', filename, 'exec')

        # Should NOT raise because sandbox is suspended
        exec(code, {})  # No exception

    def test_statement_limit_not_enforced_for_untracked_file(self) -> None:
        """Test that statement limit is NOT enforced for untracked files."""
        # Must set limits while NOT suspended
        sys.sandbox.resume()
        sys.sandbox.set_limits(max_statements=50)
        sys.sandbox.add_filename('<tracked-file>')  # Different filename
        sys.sandbox.suspend()

        # Compile code with UNTRACKED filename
        code = compile('for i in range(100): pass', '<untracked-file>', 'exec')

        # Resume sandbox and execute
        sys.sandbox.reset_counts()
        sys.sandbox.resume()
        try:
            # Should NOT raise because file is not tracked
            exec(code, {})  # No exception
        finally:
            sys.sandbox.suspend()

    def test_reset_counters_allows_reuse(self) -> None:
        """Test that resetting counters allows running code again."""
        filename = '<test-file>'
        # Must set limits while NOT suspended
        sys.sandbox.resume()
        sys.sandbox.set_limits(max_statements=100)
        sys.sandbox.add_filename(filename)
        sys.sandbox.suspend()

        code = compile('for i in range(50): pass', filename, 'exec')

        # First run
        sys.sandbox.reset_counts()
        sys.sandbox.resume()
        try:
            exec(code, {})  # Uses ~50 statements
        finally:
            sys.sandbox.suspend()

        # Second run - reset counters allows running again
        sys.sandbox.reset_counts()
        sys.sandbox.resume()
        try:
            exec(code, {})  # Works because counters were reset
        finally:
            sys.sandbox.suspend()


class SandboxAPIIntegrationTests(unittest.TestCase):
    """Test sandbox API integration patterns."""

    def setUp(self) -> None:
        """Reset sandbox state before each test."""
        # Ensure sandbox is suspended first
        if not sys.sandbox.suspended:
            sys.sandbox.suspend()

        sys.sandbox.clear_filenames()
        # Reset to permissive defaults
        sys.sandbox.set_limits(
            max_int_digits=1000,
            max_str_length=10_000_000,
            max_bytes_length=10_000_000,
            max_list_size=1_000_000,
            max_dict_size=1_000_000,
            max_set_size=1_000_000,
            max_tuple_size=1_000_000,
            max_statements=100_000_000,
            max_allocations=100_000_000,
            allow_float=True,
            allow_complex=True,
        )

    def tearDown(self) -> None:
        """Ensure sandbox is suspended after each test."""
        if not sys.sandbox.suspended:
            sys.sandbox.suspend()

    def test_suspend_during_import_pattern(self) -> None:
        """Test the pattern of suspending during imports."""
        # This simulates what should happen during module imports
        filename = '<blueprint>'
        # Must set limits while NOT suspended
        sys.sandbox.resume()
        sys.sandbox.set_limits(max_statements=50)
        sys.sandbox.add_filename(filename)
        sys.sandbox.suspend()

        # "Import" phase - sandbox is suspended
        self.assertTrue(sys.sandbox.suspended)

        # Compile code while suspended (simulates module loading)
        code = compile('for i in range(100): pass', filename, 'exec')

        # Now resume for execution
        sys.sandbox.reset_counts()
        sys.sandbox.resume()
        try:
            # Execute limited code
            with self.assertRaises(RuntimeError):
                exec(code, {})
        finally:
            sys.sandbox.suspend()

    def test_multiple_exec_pattern(self) -> None:
        """Test the pattern of multiple exec calls with suspend/resume."""
        filename = '<blueprint>'
        # Must set limits while NOT suspended
        sys.sandbox.resume()
        sys.sandbox.set_limits(max_statements=100)
        sys.sandbox.add_filename(filename)
        sys.sandbox.suspend()

        code = compile('for i in range(50): pass', filename, 'exec')

        # First exec
        sys.sandbox.reset_counts()
        sys.sandbox.resume()
        try:
            exec(code, {})
        finally:
            sys.sandbox.suspend()

        self.assertTrue(sys.sandbox.suspended)

        # Second exec - should work because counters are reset
        sys.sandbox.reset_counts()
        sys.sandbox.resume()
        try:
            exec(code, {})
        finally:
            sys.sandbox.suspend()

        self.assertTrue(sys.sandbox.suspended)

    def test_set_limits_preserves_filenames(self) -> None:
        """Test that set_limits does NOT clear registered filenames."""
        filename = '<test-file>'
        # Must set limits while NOT suspended
        sys.sandbox.resume()
        sys.sandbox.set_limits(max_statements=50)
        sys.sandbox.add_filename(filename)
        sys.sandbox.suspend()

        code = compile('for i in range(100): pass', filename, 'exec')

        # Verify it works
        sys.sandbox.reset_counts()
        sys.sandbox.resume()
        try:
            with self.assertRaises(RuntimeError):
                exec(code, {})
        finally:
            sys.sandbox.suspend()

        # Call set_limits again (while not suspended)
        sys.sandbox.resume()
        sys.sandbox.set_limits(max_statements=50)
        sys.sandbox.suspend()

        # Should still work - filenames preserved
        sys.sandbox.reset_counts()
        sys.sandbox.resume()
        try:
            with self.assertRaises(RuntimeError):
                exec(code, {})
        finally:
            sys.sandbox.suspend()

    def test_clear_filenames_disables_tracking(self) -> None:
        """Test that clear_filenames disables filename tracking."""
        filename = '<test-file>'
        # Must set limits while NOT suspended
        sys.sandbox.resume()
        sys.sandbox.set_limits(max_statements=50)
        sys.sandbox.add_filename(filename)
        sys.sandbox.suspend()

        code = compile('for i in range(100): pass', filename, 'exec')

        # Verify it works
        sys.sandbox.reset_counts()
        sys.sandbox.resume()
        try:
            with self.assertRaises(RuntimeError):
                exec(code, {})
        finally:
            sys.sandbox.suspend()

        # Clear filenames
        sys.sandbox.clear_filenames()

        # Should NOT raise now - filename not tracked
        sys.sandbox.reset_counts()
        sys.sandbox.resume()
        try:
            exec(code, {})  # No exception
        finally:
            sys.sandbox.suspend()


if __name__ == '__main__':
    unittest.main()
