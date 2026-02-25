# Copyright 2025 Hathor Labs
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

"""Tests for NcDryRun CLI command."""

import io
import sys
import tempfile

from hathor_cli.nc_dry_run import NcDryRun
from hathor_tests import unittest


class NcDryRunParserTest(unittest.TestCase):
    """Test NcDryRun argument parser."""

    def test_parser_block_hash(self):
        """Test parser with --block-hash argument."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cmd = NcDryRun(argv=['--data', temp_dir, '--block-hash', 'abc123'])
            self.assertEqual(cmd._args.block_hash, 'abc123')
            self.assertIsNone(cmd._args.tx_hash)

    def test_parser_tx_hash(self):
        """Test parser with --tx-hash argument."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cmd = NcDryRun(argv=['--data', temp_dir, '--tx-hash', 'def456'])
            self.assertIsNone(cmd._args.block_hash)
            self.assertEqual(cmd._args.tx_hash, 'def456')

    def test_parser_mutually_exclusive(self):
        """Test that --block-hash and --tx-hash are mutually exclusive."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Capture stderr to verify error message
            captured_stderr = io.StringIO()
            old_stderr = sys.stderr
            sys.stderr = captured_stderr
            try:
                with self.assertRaises(SystemExit) as cm:
                    NcDryRun(argv=['--data', temp_dir, '--block-hash', 'abc', '--tx-hash', 'def'])
            finally:
                sys.stderr = old_stderr

            # Argparse exits with code 2 for argument errors
            self.assertEqual(cm.exception.code, 2)
            # Verify error message mentions the mutually exclusive constraint
            stderr_output = captured_stderr.getvalue()
            self.assertIn('not allowed with argument', stderr_output)

    def test_parser_requires_hash(self):
        """Test that either --block-hash or --tx-hash is required."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Capture stderr to verify error message
            captured_stderr = io.StringIO()
            old_stderr = sys.stderr
            sys.stderr = captured_stderr
            try:
                with self.assertRaises(SystemExit) as cm:
                    NcDryRun(argv=['--data', temp_dir])
            finally:
                sys.stderr = old_stderr

            # Argparse exits with code 2 for argument errors
            self.assertEqual(cm.exception.code, 2)
            # Verify error message mentions required arguments
            stderr_output = captured_stderr.getvalue()
            self.assertIn('required', stderr_output.lower())

    def test_parser_format_json(self):
        """Test parser with --format json argument."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cmd = NcDryRun(argv=['--data', temp_dir, '--block-hash', 'abc', '--format', 'json'])
            self.assertEqual(cmd._args.format, 'json')

    def test_parser_format_text(self):
        """Test parser with --format text argument."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cmd = NcDryRun(argv=['--data', temp_dir, '--block-hash', 'abc', '--format', 'text'])
            self.assertEqual(cmd._args.format, 'text')

    def test_parser_include_changes(self):
        """Test parser with --include-changes flag."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cmd = NcDryRun(argv=['--data', temp_dir, '--block-hash', 'abc', '--include-changes'])
            self.assertTrue(cmd._args.include_changes)

    def test_parser_verbose(self):
        """Test parser with --verbose flag."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cmd = NcDryRun(argv=['--data', temp_dir, '--block-hash', 'abc', '--verbose'])
            self.assertTrue(cmd._args.verbose)

    def test_parser_output(self):
        """Test parser with --output argument."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cmd = NcDryRun(argv=['--data', temp_dir, '--block-hash', 'abc', '--output', '/tmp/out.json'])
            self.assertEqual(cmd._args.output, '/tmp/out.json')

    def test_parser_default_format(self):
        """Test that default format is json."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cmd = NcDryRun(argv=['--data', temp_dir, '--block-hash', 'abc'])
            self.assertEqual(cmd._args.format, 'json')

    def test_parser_default_include_changes(self):
        """Test that default include_changes is False."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cmd = NcDryRun(argv=['--data', temp_dir, '--block-hash', 'abc'])
            self.assertFalse(cmd._args.include_changes)

    def test_parser_default_verbose(self):
        """Test that default verbose is False."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cmd = NcDryRun(argv=['--data', temp_dir, '--block-hash', 'abc'])
            self.assertFalse(cmd._args.verbose)


class NcDryRunMethodsTest(unittest.TestCase):
    """Test NcDryRun methods."""

    def test_start_manager_does_nothing(self):
        """Test that start_manager does nothing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cmd = NcDryRun(argv=['--data', temp_dir, '--block-hash', 'abc'])
            # Should not raise
            cmd.start_manager()

    def test_register_signal_handlers_does_nothing(self):
        """Test that register_signal_handlers does nothing."""
        with tempfile.TemporaryDirectory() as temp_dir:
            cmd = NcDryRun(argv=['--data', temp_dir, '--block-hash', 'abc'])
            # Should not raise
            cmd.register_signal_handlers()
