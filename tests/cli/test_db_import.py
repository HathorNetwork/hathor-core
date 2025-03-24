import tempfile

from hathor.cli.db_import import DbImport
from tests import unittest


class TestDbImport(unittest.TestCase):
    def test_db_import(self):
        _, tmp_file = tempfile.mkstemp()
        db_import = DbImport(argv=['--temp-data', '--import-file', tmp_file])
        assert db_import is not None
