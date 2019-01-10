from hathor.cli.grafana_dashboard import create_parser, execute
from tests import unittest


class GrafanaTest(unittest.TestCase):
    def test_generate_grafana(self):
        # This cli we just need to test if it's not raising any error
        parser = create_parser()

        args = parser.parse_args(['Title'])
        execute(args)
