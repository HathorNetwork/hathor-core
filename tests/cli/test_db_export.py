import os
from unittest.mock import Mock

from hathor.cli.db_export import DbExport
from tests import unittest


class TestDbExport(unittest.TestCase):
    def test_db_export(self):
        tmp_dir = self.mkdtemp()
        tmp_file = os.path.join(tmp_dir, 'test_file')
        db_export = DbExport(argv=['--memory-storage', '--export-file', tmp_file], logging_args=Mock())
        assert db_export is not None
