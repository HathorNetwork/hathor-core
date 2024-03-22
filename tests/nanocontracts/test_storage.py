from hathor.nanocontracts.storage import NCChangesTracker
from tests import unittest


class BaseNCStorageTestCase(unittest.TestCase):
    __test__ = False

    def _run_test(self, value):
        self.storage.put('x', value)
        new_value = self.storage.get('x')
        self.assertEqual(new_value, value)
        self.storage.delete('x')

    def test_str(self):
        self._run_test('nano')

    def test_str_empty(self):
        self._run_test('')

    def test_bytes(self):
        self._run_test(b'nano')

    def test_bytes_empty(self):
        self._run_test(b'')

    def test_int_positive(self):
        self._run_test(123)

    def test_int_zero(self):
        self._run_test(0)

    def test_int_negative(self):
        self._run_test(-123)

    def test_bigint(self):
        self._run_test(2**40)

    def test_float(self):
        self._run_test(1.23)

    def test_none(self):
        self._run_test(None)

    def test_bool_true(self):
        self._run_test(True)

    def test_bool_false(self):
        self._run_test(False)

    def test_bool_tuple(self):
        self._run_test(('str', 1, 1.23, True))

    def test_int_as_float(self):
        value = 1
        self.storage.put('x', value)
        new_value = self.storage.get('x')
        self.assertEqual(new_value, value)
        self.storage.delete('x')

    def test_changes_tracker_delete(self):
        self.storage.put('x', 1)
        changes_tracker = NCChangesTracker(b'', self.storage)
        self.assertEqual(1, changes_tracker.get('x'))

        changes_tracker.delete('x')
        # Confirm the key has been deleted.
        with self.assertRaises(KeyError):
            changes_tracker.get('x')
        # Check that the key has not been deleted on the storage.
        self.assertEqual(1, self.storage.get('x'))

        # Commit changes and confirm the key was deleted on the storage.
        changes_tracker.commit()
        with self.assertRaises(KeyError):
            self.storage.get('x')


class NCMemoryStorageTestCase(BaseNCStorageTestCase):
    __test__ = True

    def setUp(self):
        from hathor.nanocontracts.storage import NCMemoryStorage
        self.storage = NCMemoryStorage()
        super().setUp()
