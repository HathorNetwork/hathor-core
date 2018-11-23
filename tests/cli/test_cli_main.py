import unittest
from hathor.cli import main


class CliMainTest(unittest.TestCase):
    def test_init(self):
        # basically making sure importing works
        main.CliManager()


if __name__ == '__main__':
    unittest.main()
