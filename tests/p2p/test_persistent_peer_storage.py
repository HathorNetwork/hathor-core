import shutil
import tempfile

import pytest

from hathor.p2p.peer_discovery.storage import StoragePeerDiscovery, _Record
from hathor.storage.rocksdb_storage import RocksDBStorage
from hathor.util import not_none
from tests.unittest import PEER_ID_POOL, TestCase
from tests.utils import HAS_ROCKSDB


def _gen_entrypoints(k: int) -> list[str]:
    """A helper function to deterministically generate a fake entrypoint list that varies in size.

    The integer k is used to decide how many entrypoints will be generated and the ports. All entrypoints will the
    hostname `local.test` which can't resolve to anything, so it will never really connect in case any test ends up
    trying to, however tests using this should not try to test actuall connections.
    """
    entrypoints_len = (k % 3) + 1
    return [f'tcp://local.test:{(1 + k // 100) % 10:01}{k % 100:02}{i:02}' for i in range(entrypoints_len)]


def test_gen_entrypoints() -> None:
    assert _gen_entrypoints(0) == ['tcp://local.test:10000']
    assert _gen_entrypoints(1) == ['tcp://local.test:10100', 'tcp://local.test:10101']
    assert _gen_entrypoints(99) == ['tcp://local.test:19900']
    assert _gen_entrypoints(100) == ['tcp://local.test:20000', 'tcp://local.test:20001']


RECORDS = [
    _Record(
        peer_id=not_none(peer_id.id),
        entrypoints=_gen_entrypoints(i),
    )
    for i, peer_id in enumerate(PEER_ID_POOL)
]


def test_serialize_and_parse() -> None:
    from hathor.p2p.peer_discovery.storage import bytes_to_record, record_to_bytes
    for record in RECORDS:
        raw_record = record_to_bytes(record)
        record2 = bytes_to_record(raw_record)
        assert record2 == record


@pytest.mark.skipif(not HAS_ROCKSDB, reason='requires python-rocksdb')
class PeerStorageTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        self._directory = tempfile.mkdtemp()
        self.storage = StoragePeerDiscovery(RocksDBStorage(path=self._directory))

    def _load_records(self, records: list[_Record]) -> None:
        for record in records:
            self.storage._put(record)

    def tearDown(self) -> None:
        super().tearDown()
        shutil.rmtree(self._directory)

    def test_add_or_update(self) -> None:
        peer = PEER_ID_POOL[0]
        assert peer.id is not None
        connection_time = 10
        self.storage.add_connected(peer, connection_time)
        record = self.storage._get(peer.id)
        assert record is not None
        assert record.peer_id == peer.id
        assert record.entrypoints == peer.entrypoints
        assert record.last_connection == connection_time
        assert record.last_connection_attempt is None
        assert record.to_remove is False

    def test_mark_try_to_connect(self) -> None:
        peer = PEER_ID_POOL[0]
        assert peer.id is not None
        connection_time = 10
        self.storage.mark_try_to_connect(peer, connection_time)
        record = self.storage._get(peer.id)
        assert record is not None
        assert record.peer_id == peer.id
        assert record.entrypoints == []
        assert record.last_connection is None
        assert record.last_connection_attempt == connection_time
        assert record.to_remove is False

    async def test_discover_and_connect(self) -> None:
        self._load_records(RECORDS)

        entrypoints = set()

        def add_to_list(entrypoint: str) -> None:
            entrypoints.add(entrypoint)

        await self.storage.discover_and_connect(add_to_list)

        expected_entrypoints = set()
        for record in RECORDS:
            for entrypoint in record.entrypoints:
                expected_entrypoints.add(entrypoint)

        assert entrypoints == expected_entrypoints

    def test_run_cleanup_none(self) -> None:
        self._load_records(RECORDS)

        # sanity check, we don't have to do this in every cleanup test
        def key(r: _Record) -> str:
            return r.peer_id
        assert sorted(self.storage._iter_records(), key=key) == sorted(RECORDS, key=key)

        # they way the records were just loaded make it so the last_connection and last_connection_attempt are both
        # None, which mean that the first round of cleanup should mark them all as to_remove, and the second round
        # should remove them all, and the now_timestamp doesn't matter for this, so we use 0
        for record in self.storage._iter_records():
            assert not record.to_remove
        self.storage.run_cleanup(0)
        for record in self.storage._iter_records():
            assert record.to_remove
        self.storage.run_cleanup(0)
        assert list(self.storage._iter_records()) == []

    def test_run_cleanup_simple(self) -> None:
        self._load_records(RECORDS)

        # mark every record with progressively increasing last_connection
        for i, peer in enumerate(PEER_ID_POOL):
            assert peer.id is not None
            # XXX: a side effect is that the old entrypoints will be lost because the PeerId objects in PEER_ID_POOL
            # have no entrypoints, but that's not a problem because entrypoints do not affect cleanup
            self.storage.add_connected(peer, i)

        # let's make it so we forget peers that haven't connected in the last 15 seconds
        self.storage.peer_forget_timeout = 15

        # supposed the timestamp is len(RECORDS), which mean we would try to remove all but the last 15 peers
        now_timestamp = len(RECORDS)
        self.storage.run_cleanup(now_timestamp)
        assert len([r for r in self.storage._iter_records() if not r.to_remove]) == 15

        # let's now suppose that we do end up connecting to one of the peers that we marked for removal, it should not
        # be removed anymore
        peer = PEER_ID_POOL[1]
        assert peer.id is not None
        self.storage.add_connected(peer, now_timestamp)
        record = self.storage._get(peer.id)
        assert record is not None
        assert not record.to_remove

        # now, we push another cleanup, we should have 16 peers, but since we advanced the timestamp, one of those
        # should be marked for removal
        now_timestamp += 1
        self.storage.run_cleanup(now_timestamp)
        records = list(self.storage._iter_records())
        assert len(records) == 16
        assert len([r for r in records if r.to_remove]) == 1
