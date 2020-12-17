import unittest
from contextlib import redirect_stdout
from io import StringIO

from structlog.testing import capture_logs

from hathor.cli import main


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


if __name__ == '__main__':
    unittest.main()
