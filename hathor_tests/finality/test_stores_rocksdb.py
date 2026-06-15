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

import tempfile

from hathor.conf.get_settings import get_global_settings
from hathor.indexes.manager import RocksDBIndexesManager
from hathor.storage import RocksDBStorage
from hathor.types import VertexId
from hathorlib.conf.settings import FeatureSetting

TX_A = VertexId(b'\xa1' * 32)
SPENDER_1 = VertexId(b'\x01' * 32)
SPENDER_2 = VertexId(b'\x02' * 32)


def _finality_settings():
    return get_global_settings().model_copy(update={'ENABLE_TWO_TIER_FINALITY': FeatureSetting.ENABLED})


def test_finality_stores_created_only_when_enabled() -> None:
    settings = get_global_settings()
    assert not settings.ENABLE_TWO_TIER_FINALITY
    with tempfile.TemporaryDirectory() as directory:
        storage = RocksDBStorage(path=directory)
        indexes = RocksDBIndexesManager(rocksdb_storage=storage, settings=settings)
        assert indexes.finality_pin is None
        assert indexes.finality_certificate is None


def test_finality_pin_store_persists_across_reopen() -> None:
    settings = _finality_settings()
    with tempfile.TemporaryDirectory() as directory:
        # First "boot": create a pin.
        storage = RocksDBStorage(path=directory)
        indexes = RocksDBIndexesManager(rocksdb_storage=storage, settings=settings)
        assert indexes.finality_pin is not None
        assert indexes.finality_certificate is not None
        assert indexes.finality_pin.try_pin(TX_A, 0, SPENDER_1) is True
        indexes.finality_certificate.add_certificate(TX_A, b'cert-bytes')
        storage.close()

        # Second "boot" on the same directory: the pin and certificate must still be there, and a
        # conflicting pin must still be rejected (the validator cannot equivocate after a restart).
        storage = RocksDBStorage(path=directory)
        indexes = RocksDBIndexesManager(rocksdb_storage=storage, settings=settings)
        assert indexes.finality_pin is not None
        assert indexes.finality_certificate is not None
        assert indexes.finality_pin.get_pin(TX_A, 0) == bytes(SPENDER_1)
        assert indexes.finality_pin.try_pin(TX_A, 0, SPENDER_2) is False
        assert indexes.finality_certificate.get_certificate(TX_A) == b'cert-bytes'
        storage.close()
