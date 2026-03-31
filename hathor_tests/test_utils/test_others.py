#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
# from unittest.mock import patch
import unittest

import pytest

from hathor.util import collect_n, practically_equal, skip_warning


class PracticallyEqualTest(unittest.TestCase):
    def test_practically_equal(self):
        from collections import defaultdict
        a = defaultdict(str)
        b = defaultdict(str)
        # When empty they are equals
        self.assertTrue(practically_equal(a, b))
        a['foo'] = 'bar'
        # They now are different with items
        self.assertFalse(practically_equal(a, b))
        b['foo'] = 'bar'
        # They now are equal with items
        self.assertTrue(practically_equal(a, b))
        a['baz'] = 'zar'
        # They now are different with more items
        self.assertFalse(practically_equal(a, b))


class SkipWarningTest(unittest.TestCase):
    def test_skip_warning(self):
        try:
            @skip_warning
            def func(): ...

            class MyClass:
                @skip_warning
                def func(self): ...
        except Exception:
            pytest.fail("Unexpected error")


class CollectNTest(unittest.TestCase):
    def test_collect_n(self):
        res1 = collect_n(iter(range(10)), 10)
        self.assertEqual(len(res1[0]), 10)
        self.assertFalse(res1[1])

        res2 = collect_n(iter(range(10)), 11)
        self.assertEqual(len(res2[0]), 10)
        self.assertFalse(res2[1])

        res3 = collect_n(iter(range(10)), 9)
        self.assertEqual(len(res3[0]), 9)
        self.assertTrue(res3[1])

    def test_collect_n_neg(self):
        with self.assertRaises(ValueError):
            collect_n(iter(range(10)), -1)
