import os

from hathor_cli.db_export import DbExport
from hathor_tests import unittest


class TestDbExport(unittest.TestCase):
    def test_db_export(self):
        tmp_dir = self.mkdtemp()
        tmp_file = os.path.join(tmp_dir, 'test_file')
        db_export = DbExport(argv=['--temp-data', '--export-file', tmp_file])
        assert db_export is not None
