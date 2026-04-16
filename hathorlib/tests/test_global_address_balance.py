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

from hathorlib.headers.nano_header import ADDRESS_LEN_BYTES
from hathorlib.nanocontracts.nc_types.token_uid_nc_type import HATHOR_TOKEN_UID
from hathorlib.nanocontracts.storage.block_storage import NCBlockStorage
from hathorlib.nanocontracts.storage.changes_tracker import NCChangesTracker
from hathorlib.nanocontracts.storage.memory_backends import InMemoryNodeTrieStore
from hathorlib.nanocontracts.storage.patricia_trie import PatriciaTrie
from hathorlib.nanocontracts.types import Address, Amount, ContractId, TokenUid, VertexId


def _make_block_storage() -> NCBlockStorage:
    return NCBlockStorage(PatriciaTrie(InMemoryNodeTrieStore()))


def _addr(byte: int) -> Address:
    return Address(bytes([byte]) * ADDRESS_LEN_BYTES)


class NCBlockStorageAddressBalanceTestCase(unittest.TestCase):
    def test_get_address_balance_defaults_to_zero(self) -> None:
        block_storage = _make_block_storage()
        assert block_storage.get_address_balance(_addr(1), TokenUid(HATHOR_TOKEN_UID)) == 0

    def test_add_and_get_address_balance_roundtrip(self) -> None:
        block_storage = _make_block_storage()
        address = _addr(1)
        token = TokenUid(HATHOR_TOKEN_UID)

        block_storage.add_address_balance(address, Amount(5), token)
        block_storage.add_address_balance(address, Amount(3), token)

        assert block_storage.get_address_balance(address, token) == 8

    def test_add_address_balance_supports_negative_delta(self) -> None:
        block_storage = _make_block_storage()
        address = _addr(1)
        token = TokenUid(HATHOR_TOKEN_UID)
        block_storage.add_address_balance(address, Amount(5), token)

        block_storage.add_address_balance(address, Amount(-2), token)

        assert block_storage.get_address_balance(address, token) == 3

    def test_add_address_balance_rejects_wrong_address_length(self) -> None:
        block_storage = _make_block_storage()
        bad_address = Address(b'\x00' * (ADDRESS_LEN_BYTES - 1))

        with self.assertRaises(ValueError):
            block_storage.add_address_balance(bad_address, Amount(1), TokenUid(HATHOR_TOKEN_UID))

    def test_add_address_balance_rejects_non_address_bytes(self) -> None:
        block_storage = _make_block_storage()
        not_an_address = b'\x00' * ADDRESS_LEN_BYTES  # type: ignore[assignment]

        with self.assertRaises(ValueError):
            # Bypass the NewType: feed raw bytes that have the right length but wrong type.
            block_storage.add_address_balance(not_an_address, Amount(1), TokenUid(HATHOR_TOKEN_UID))  # type: ignore[arg-type]

    def test_add_address_balance_supports_multiple_tokens(self) -> None:
        block_storage = _make_block_storage()
        address = _addr(1)
        htr = TokenUid(HATHOR_TOKEN_UID)
        other = TokenUid(b'\x11' * 32)

        block_storage.add_address_balance(address, Amount(5), htr)
        block_storage.add_address_balance(address, Amount(9), other)

        assert block_storage.get_address_balance(address, htr) == 5
        assert block_storage.get_address_balance(address, other) == 9

    def test_iter_address_balances_yields_only_target_address(self) -> None:
        block_storage = _make_block_storage()
        target = _addr(1)
        other = _addr(2)
        htr = TokenUid(HATHOR_TOKEN_UID)
        custom = TokenUid(b'\x22' * 32)

        block_storage.add_address_balance(target, Amount(7), htr)
        block_storage.add_address_balance(target, Amount(4), custom)
        block_storage.add_address_balance(other, Amount(100), htr)

        entries = dict(block_storage.iter_address_balances(target))

        assert entries == {htr: Amount(7), custom: Amount(4)}

    def test_iter_address_balances_is_empty_when_no_entries(self) -> None:
        block_storage = _make_block_storage()
        # Populate some other address so the trie is non-empty.
        block_storage.add_address_balance(_addr(2), Amount(1), TokenUid(HATHOR_TOKEN_UID))

        assert list(block_storage.iter_address_balances(_addr(1))) == []

    def test_iter_address_balances_skips_zero_balance_entries(self) -> None:
        block_storage = _make_block_storage()
        address = _addr(1)
        htr = TokenUid(HATHOR_TOKEN_UID)
        custom = TokenUid(b'\x33' * 32)

        block_storage.add_address_balance(address, Amount(5), htr)
        block_storage.add_address_balance(address, Amount(2), custom)
        # Zero out the custom-token balance.
        block_storage.add_address_balance(address, Amount(-2), custom)

        entries = dict(block_storage.iter_address_balances(address))
        assert entries == {htr: Amount(5)}

    def test_iter_address_balances_rejects_wrong_address_length(self) -> None:
        block_storage = _make_block_storage()
        with self.assertRaises(ValueError):
            list(block_storage.iter_address_balances(Address(b'\x00' * 5)))


class NCChangesTrackerAddressBalanceTestCase(unittest.TestCase):
    def _make_tracker(self) -> tuple[NCBlockStorage, NCChangesTracker, ContractId]:
        block_storage = _make_block_storage()
        contract_id = ContractId(VertexId(b'\xaa' * 32))
        contract_storage = block_storage.get_empty_contract_storage(contract_id)
        tracker = NCChangesTracker(contract_id, contract_storage)
        return block_storage, tracker, contract_id

    def test_add_address_balance_accumulates_in_transfers_diff(self) -> None:
        _, tracker, _ = self._make_tracker()
        address = _addr(1)
        token = TokenUid(HATHOR_TOKEN_UID)

        tracker.add_address_balance(address, Amount(4), token)
        tracker.add_address_balance(address, Amount(3), token)

        assert tracker.get_address_balance_diff(address, token) == 7

    def test_address_balance_diff_defaults_to_zero(self) -> None:
        _, tracker, _ = self._make_tracker()
        assert tracker.get_address_balance_diff(_addr(1), TokenUid(HATHOR_TOKEN_UID)) == 0

    def test_all_address_balance_diffs_returns_live_view(self) -> None:
        _, tracker, _ = self._make_tracker()
        address = _addr(1)
        token = TokenUid(HATHOR_TOKEN_UID)

        diffs = tracker.get_all_address_balance_diffs()
        assert diffs == {}

        tracker.add_address_balance(address, Amount(5), token)
        assert dict(diffs) == {(address, token): 5}

    def test_commit_flushes_transfers_to_block_storage(self) -> None:
        block_storage, tracker, _ = self._make_tracker()
        address = _addr(1)
        token = TokenUid(HATHOR_TOKEN_UID)
        tracker.add_address_balance(address, Amount(6), token)

        assert block_storage.get_address_balance(address, token) == 0

        tracker.commit()

        assert block_storage.get_address_balance(address, token) == 6

    def test_add_address_balance_rejects_negative_amount(self) -> None:
        _, tracker, _ = self._make_tracker()
        with self.assertRaises(AssertionError):
            tracker.add_address_balance(_addr(1), Amount(-1), TokenUid(HATHOR_TOKEN_UID))


if __name__ == '__main__':
    unittest.main()
