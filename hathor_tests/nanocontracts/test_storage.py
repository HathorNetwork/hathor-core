from typing import TypeVar

from hathor.nanocontracts import NCRocksDBStorageFactory
from hathor.nanocontracts.nc_types import NCType, NullNCType, make_nc_type_for_arg_type as make_nc_type
from hathor.nanocontracts.storage import NCChangesTracker
from hathor.nanocontracts.types import Amount, ContractId, Timestamp, VertexId
from hathor_tests import unittest

T = TypeVar('T')

STR_NC_TYPE = make_nc_type(str)
BYTES_NC_TYPE = make_nc_type(bytes)
INT_NC_TYPE = make_nc_type(int)
BOOL_NC_TYPE = make_nc_type(bool)


class NCRocksDBStorageTestCase(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        rocksdb_storage = self.create_rocksdb_storage()
        factory = NCRocksDBStorageFactory(rocksdb_storage)
        block_storage = factory.get_empty_block_storage()
        self.storage = block_storage.get_empty_contract_storage(ContractId(VertexId(b'')))
        super().setUp()

    def _run_test(self, data_in: T, value: NCType[T]) -> None:
        # XXX: maybe make the key random?
        key = b'x'
        # make sure the key is unused
        self.assertFalse(self.storage.has_obj(key))
        # value goes in
        self.storage.put_obj(key, value, data_in)
        # the key should be present
        self.assertTrue(self.storage.has_obj(key))
        # value comes out
        data_out = self.storage.get_obj(key, value)
        # should be the same
        self.assertEqual(data_in, data_out)
        # clean up
        self.storage.del_obj(key)
        # make sure the storage got rid of it
        self.assertFalse(self.storage.has_obj(key))

    def test_str(self) -> None:
        self._run_test('nano', STR_NC_TYPE)

    def test_str_empty(self) -> None:
        self._run_test('', STR_NC_TYPE)

    def test_bytes(self) -> None:
        self._run_test(b'nano', BYTES_NC_TYPE)

    def test_bytes_empty(self) -> None:
        self._run_test(b'', BYTES_NC_TYPE)

    def test_int_positive(self) -> None:
        self._run_test(123, INT_NC_TYPE)

    def test_int_zero(self) -> None:
        self._run_test(0, INT_NC_TYPE)

    def test_int_negative(self) -> None:
        self._run_test(-123, INT_NC_TYPE)

    def test_bigint(self) -> None:
        self._run_test(2**40, INT_NC_TYPE)

    def test_float(self) -> None:
        with self.assertRaises(TypeError):
            make_nc_type(float)
        with self.assertRaises(TypeError):
            # XXX: ignore misc, mypy catches this error but we want to test for it
            self._run_test(1.23, INT_NC_TYPE)  # type: ignore[misc]

    def test_none(self) -> None:
        value = NullNCType()
        self._run_test(None, value)

    def test_optional(self) -> None:
        value: NCType[int | None] = make_nc_type(int | None)  # type: ignore[arg-type]
        self._run_test(1, value)
        self._run_test(None, value)

    def test_bool_true(self) -> None:
        self._run_test(True, BOOL_NC_TYPE)

    def test_bool_false(self) -> None:
        self._run_test(False, BOOL_NC_TYPE)

    def test_tuple(self) -> None:
        value: NCType[tuple[str, int, set[int], bool]]
        value = make_nc_type(tuple[str, int, set[int], bool])
        self._run_test(('str', 1, {3}, True), value)

    def test_changes_tracker_delete(self) -> None:
        self.storage.put_obj(b'x', INT_NC_TYPE, 1)
        changes_tracker = NCChangesTracker(ContractId(VertexId(b'')), self.storage)
        self.assertEqual(1, changes_tracker.get_obj(b'x', INT_NC_TYPE))

        changes_tracker.del_obj(b'x')
        # Confirm the key has been deleted.
        with self.assertRaises(KeyError):
            changes_tracker.get_obj(b'x', INT_NC_TYPE)
        # Check that the key has not been deleted on the storage.
        self.assertEqual(1, self.storage.get_obj(b'x', INT_NC_TYPE))

        # Commit changes and confirm the key was deleted on the storage.
        changes_tracker.commit()
        with self.assertRaises(KeyError):
            self.storage.get_obj(b'x', INT_NC_TYPE)

    def test_changes_tracker_early_error(self) -> None:
        self.storage.put_obj(b'x', INT_NC_TYPE, 1)
        changes_tracker = NCChangesTracker(ContractId(VertexId(b'')), self.storage)

        # changes tracker should fail early when trying to use a value that would fail the serialzitation
        # (internally it effectively serializes that type early)
        with self.assertRaises(TypeError):
            # 3 is an invalid bool
            changes_tracker.put_obj(b'y', BOOL_NC_TYPE, 3)  # type: ignore[misc]

        # other examples of failures:

        amount_nc_type = make_nc_type(Amount)
        with self.assertRaises(ValueError):
            # Amount must be non-negative
            changes_tracker.put_obj(b'y', amount_nc_type, -1)  # type: ignore[misc]

        timestamp_nc_type = make_nc_type(Timestamp)
        with self.assertRaises(ValueError):
            # Timestamp uses Int32NCType
            changes_tracker.put_obj(b'y', timestamp_nc_type, 2**32)  # type: ignore[misc]

        nested_nc_type = make_nc_type(dict[int, set[int]])
        with self.assertRaises(TypeError):
            # inner string is not int
            changes_tracker.put_obj(b'y', nested_nc_type, {1: {'foo'}})  # type: ignore[misc]
