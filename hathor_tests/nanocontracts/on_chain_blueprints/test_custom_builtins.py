import unittest
from builtins import range as builtin_range

from hathor.nanocontracts.custom_builtins import custom_range


class TestCustomRange(unittest.TestCase):
    def compare_ranges(self, custom, builtin):
        self.assertEqual(list(custom), list(builtin))
        self.assertEqual(len(custom), len(builtin))
        self.assertEqual(custom.start, builtin.start)
        self.assertEqual(custom.stop, builtin.stop)
        self.assertEqual(custom.step, builtin.step)

    def test_single_argument(self):
        custom = custom_range(5)
        builtin = builtin_range(5)
        self.compare_ranges(custom, builtin)

    def test_two_arguments(self):
        custom = custom_range(1, 5)
        builtin = builtin_range(1, 5)
        self.compare_ranges(custom, builtin)

    def test_three_arguments(self):
        custom = custom_range(1, 10, 2)
        builtin = builtin_range(1, 10, 2)
        self.compare_ranges(custom, builtin)

    def test_negative_step(self):
        custom = custom_range(10, 1, -2)
        builtin = builtin_range(10, 1, -2)
        self.compare_ranges(custom, builtin)

    def test_empty_range(self):
        cases = [(5, 5), (5, 5, -1), (5, 10, -1)]
        for args in cases:
            custom = custom_range(*args)
            builtin = builtin_range(*args)
            self.compare_ranges(custom, builtin)

    def test_len(self):
        for args in [(5,), (1, 5), (1, 10, 2), (10, 1, -2)]:
            custom = custom_range(*args)
            builtin = builtin_range(*args)
            self.assertEqual(len(custom), len(builtin))

    def test_eq(self):
        self.assertEqual(custom_range(5), custom_range(0, 5, 1))
        self.assertNotEqual(custom_range(5), custom_range(1, 5))
        self.assertNotEqual(custom_range(1, 10, 2), custom_range(1, 10, 3))

    def test_contains(self):
        custom = custom_range(1, 10, 2)
        builtin = builtin_range(1, 10, 2)
        for val in [3, 4, 9, 10]:
            self.assertEqual(val in custom, val in builtin)

    def test_index(self):
        custom = custom_range(1, 10, 2)
        builtin = builtin_range(1, 10, 2)
        for val in [3, 9]:
            self.assertEqual(custom.index(val), builtin.index(val))
        with self.assertRaises(ValueError):
            custom.index(4)
        with self.assertRaises(ValueError):
            builtin.index(4)

    def test_count(self):
        custom = custom_range(1, 10, 2)
        builtin = builtin_range(1, 10, 2)
        for val in [3, 4, 9]:
            self.assertEqual(custom.count(val), builtin.count(val))

    def test_getitem(self):
        custom = custom_range(1, 10, 2)
        builtin = builtin_range(1, 10, 2)
        for idx in [0, 1, -1]:
            self.assertEqual(custom[idx], builtin[idx])
        with self.assertRaises(IndexError):
            _ = custom[10]
        with self.assertRaises(IndexError):
            _ = builtin[10]

    def test_slice_getitem(self):
        custom = custom_range(1, 10, 2)
        builtin = builtin_range(1, 10, 2)
        slices = [slice(1, 4), slice(None, None, 2), slice(None, None, -1)]
        for sl in slices:
            self.compare_ranges(custom[sl], builtin[sl])

    def test_iter(self):
        custom = custom_range(1, 5)
        builtin = builtin_range(1, 5)
        self.assertEqual(list(iter(custom)), list(iter(builtin)))

    def test_reversed(self):
        custom = custom_range(1, 10, 2)
        builtin = builtin_range(1, 10, 2)
        self.assertEqual(list(reversed(custom)), list(reversed(builtin)))

    def test_invalid_arguments(self):
        invalid_args = [(1.5,), (1, '10'), (1, 10, '2')]
        for args in invalid_args:
            with self.assertRaises(TypeError):
                custom_range(*args)
            with self.assertRaises(TypeError):
                builtin_range(*args)

    def test_large_range(self):
        # Very large range
        custom = custom_range(0, 10**6, 2)
        builtin = builtin_range(0, 10**6, 2)
        self.assertEqual(len(custom), len(builtin))
        self.assertEqual(custom[-1], builtin[-1])

    def test_large_negative_step(self):
        # Large negative step
        custom = custom_range(10**6, 0, -2)
        builtin = builtin_range(10**6, 0, -2)
        self.assertEqual(len(custom), len(builtin))
        self.assertEqual(custom[-1], builtin[-1])

    def test_single_element_range(self):
        # Single element ranges
        custom = custom_range(5, 6)
        builtin = builtin_range(5, 6)
        self.assertEqual(list(custom), list(builtin))
        self.assertEqual(len(custom), len(builtin))

    def test_single_element_negative_step(self):
        # Single element with negative step
        custom = custom_range(6, 5, -1)
        builtin = builtin_range(6, 5, -1)
        self.assertEqual(list(custom), list(builtin))
        self.assertEqual(len(custom), len(builtin))

    def test_start_stop_equal(self):
        # Start and stop are the same
        custom = custom_range(5, 5)
        builtin = builtin_range(5, 5)
        self.assertEqual(list(custom), list(builtin))
        self.assertEqual(len(custom), len(builtin))

    def test_step_larger_than_range(self):
        # Step size larger than the range
        custom = custom_range(1, 5, 10)
        builtin = builtin_range(1, 5, 10)
        self.assertEqual(list(custom), list(builtin))
        self.assertEqual(len(custom), len(builtin))

    def test_reverse_single_step(self):
        # Negative step with start and stop reversed by one step
        custom = custom_range(1, -1, -1)
        builtin = builtin_range(1, -1, -1)
        self.assertEqual(list(custom), list(builtin))
        self.assertEqual(len(custom), len(builtin))

    def test_index_out_of_bounds(self):
        # Check handling of out-of-bounds indices
        custom = custom_range(1, 10, 2)
        with self.assertRaises(IndexError):
            _ = custom[100]
        with self.assertRaises(IndexError):
            _ = custom[-100]

    def test_slice_with_large_step(self):
        # Slicing with a large step
        custom = custom_range(0, 100)
        builtin = builtin_range(0, 100)
        self.assertEqual(list(custom[::25]), list(builtin[::25]))

    def test_slice_out_of_bounds(self):
        # Slicing out of bounds
        custom = custom_range(0, 10)
        builtin = builtin_range(0, 10)
        self.assertEqual(list(custom[10:20]), list(builtin[10:20]))
        self.assertEqual(list(custom[-20:-10]), list(builtin[-20:-10]))

    def test_reverse_entire_range(self):
        # Reverse the entire range
        custom = custom_range(1, 10)
        builtin = builtin_range(1, 10)
        self.assertEqual(list(reversed(custom)), list(reversed(builtin)))

    def test_step_one(self):
        # Step of 1, which should produce a range identical to start-stop
        custom = custom_range(1, 10, 1)
        builtin = builtin_range(1, 10, 1)
        self.assertEqual(list(custom), list(builtin))
        self.assertEqual(len(custom), len(builtin))

    def test_zero_length_range(self):
        # A range with zero length due to the starting conditions
        custom = custom_range(10, 0)
        builtin = builtin_range(10, 0)
        self.assertEqual(list(custom), list(builtin))
        self.assertEqual(len(custom), len(builtin))
