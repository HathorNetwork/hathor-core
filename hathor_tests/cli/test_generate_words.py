from contextlib import redirect_stdout
from io import StringIO

from structlog.testing import capture_logs

from hathor_cli.generate_valid_words import create_parser, execute
from hathor_tests import unittest


class GenerateWordsTest(unittest.TestCase):
    def test_generate_words(self):
        parser = create_parser()

        # Default generation of words (24 words in english)
        args = parser.parse_args([])
        f = StringIO()
        with capture_logs():
            with redirect_stdout(f):
                execute(args)
        # Transforming prints str in array
        output = f.getvalue().strip().splitlines()

        self.assertEqual(len(output[0].split(' ')), 24)

        # Generate 18 words
        params = ['--count', '18']
        args = parser.parse_args(params)
        f = StringIO()
        with capture_logs():
            with redirect_stdout(f):
                execute(args)
        # Transforming prints str in array
        output = f.getvalue().strip().splitlines()

        self.assertEqual(len(output[0].split(' ')), 18)

        # Generate 18 japanese words
        params = ['--count', '18', '--language', 'japanese']
        args = parser.parse_args(params)
        f = StringIO()
        with capture_logs():
            with redirect_stdout(f):
                execute(args)
        # Transforming prints str in array
        output = f.getvalue().strip().splitlines()

        # In japanese is more than 18 when I split by space
        self.assertNotEqual(len(output[0].split(' ')), 18)
