# Copyright 2026 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

from hathorlib.nanocontracts.rng import NanoRNG


class TestNanoRNG(unittest.TestCase):
    def _get_seed(self) -> bytes:
        return b'\x01' * 32

    def test_init_valid_seed(self) -> None:
        rng = NanoRNG(self._get_seed())
        self.assertIsNotNone(rng)

    def test_init_invalid_seed_length(self) -> None:
        with self.assertRaises(ValueError):
            NanoRNG(b'\x01' * 16)

    def test_randbytes(self) -> None:
        rng = NanoRNG(self._get_seed())
        result = rng.randbytes(16)
        self.assertEqual(len(result), 16)
        self.assertIsInstance(result, bytes)

    def test_randbytes_deterministic(self) -> None:
        rng1 = NanoRNG(self._get_seed())
        rng2 = NanoRNG(self._get_seed())
        self.assertEqual(rng1.randbytes(32), rng2.randbytes(32))

    def test_randbits(self) -> None:
        rng = NanoRNG(self._get_seed())
        result = rng.randbits(8)
        self.assertGreaterEqual(result, 0)
        self.assertLess(result, 256)

    def test_randbelow(self) -> None:
        rng = NanoRNG(self._get_seed())
        for _ in range(20):
            result = rng.randbelow(10)
            self.assertGreaterEqual(result, 0)
            self.assertLess(result, 10)

    def test_randrange(self) -> None:
        rng = NanoRNG(self._get_seed())
        for _ in range(20):
            result = rng.randrange(5, 15)
            self.assertGreaterEqual(result, 5)
            self.assertLess(result, 15)

    def test_randrange_with_step(self) -> None:
        rng = NanoRNG(self._get_seed())
        for _ in range(20):
            result = rng.randrange(0, 20, step=2)
            self.assertEqual(result % 2, 0)
            self.assertGreaterEqual(result, 0)
            self.assertLess(result, 20)

    def test_randint(self) -> None:
        rng = NanoRNG(self._get_seed())
        for _ in range(20):
            result = rng.randint(1, 6)
            self.assertGreaterEqual(result, 1)
            self.assertLessEqual(result, 6)

    def test_choice(self) -> None:
        rng = NanoRNG(self._get_seed())
        items = ['a', 'b', 'c', 'd']
        result = rng.choice(items)
        self.assertIn(result, items)

    def test_random(self) -> None:
        rng = NanoRNG(self._get_seed())
        for _ in range(20):
            result = rng.random()
            self.assertGreaterEqual(result, 0.0)
            self.assertLess(result, 1.0)

    def test_immutability(self) -> None:
        rng = NanoRNG(self._get_seed())
        with self.assertRaises(AttributeError):
            rng.foo = 'bar'  # type: ignore
