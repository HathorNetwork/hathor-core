import tempfile
from unittest.mock import Mock

from hathor.cli.db_import import DbImport
from tests import unittest


class TestDbImport(unittest.TestCase):
    def test_db_import(self):
        _, tmp_file = tempfile.mkstemp()
        db_import = DbImport(argv=['--memory-storage', '--import-file', tmp_file], logging_args=Mock())
        assert db_import is not None
