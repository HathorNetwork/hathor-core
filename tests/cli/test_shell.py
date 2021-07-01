import tempfile

import pytest

from hathor.cli.shell import Shell
from tests import unittest

try:
    import rocksdb  # noqa: F401
except ImportError:
    HAS_ROCKSDB = False
else:
    HAS_ROCKSDB = True


class ShellTest(unittest.TestCase):
    # In this case we just want to go through the code to see if it's okay

    def test_shell_execution_memory_storage(self):
        shell = Shell(argv=['--memory-storage'])
        self.assertTrue(shell is not None)

    @pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
    def test_shell_execution_default_storage(self):
        temp_data = tempfile.TemporaryDirectory()
        shell = Shell(argv=['--data', temp_data.name])
        self.assertTrue(shell is not None)
