import unittest
from contextlib import redirect_stdout
from io import StringIO

from structlog.testing import capture_logs

from hathor_cli import main


class CliMainTest(unittest.TestCase):
    def test_init(self):
        # basically making sure importing works
        cli = main.CliManager()

        # Help method only prints on the screen
        # So just making sure it has no errors
        f = StringIO()
        with capture_logs():
            with redirect_stdout(f):
                cli.help()
        # Transforming prints str in array
        output = f.getvalue().strip().splitlines()

        # 3 is the number of prints we have without any command
        self.assertTrue(len(output) >= 3)

    def test_help(self):
        import sys

        # basically making sure importing works
        cli = main.CliManager()

        # Help method only prints on the screen
        # So just making sure it has no errors
        f = StringIO()
        with self.assertRaises(SystemExit) as cm:
            with capture_logs():
                with redirect_stdout(f):
                    sys.argv = ['hathor-core', 'run_node', '--help']
                    cli.execute_from_command_line()

        # Must exit with code 0
        self.assertEqual(cm.exception.args[0], 0)

        # Transforming prints str in array
        output = f.getvalue().strip().splitlines()

        # The help output will normally contain at least 80 lines
        self.assertGreaterEqual(len(output), 80)
