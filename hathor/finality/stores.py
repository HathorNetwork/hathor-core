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

"""
Authoritative persistent stores for the finality fast path.

Unlike every other index in `hathor/indexes/`, these stores are NOT derived from the transaction DAG
and therefore cannot be rebuilt by scanning it:

- The **pin store** records, for each UTXO a validator has voted to spend, the unique transaction it
  pinned that UTXO to. This is the validator's authoritative anti-equivocation state; losing it would
  let the validator sign a second, conflicting spender after a restart, breaking soft-finality safety.
- The **certificate store** records, per transaction id, the Finality Certificate a node has verified
  and accepted. The block-validity (ratification) rule consults it with O(1) lookups.

Because they are authoritative rather than rebuildable, these stores are deliberately kept out of the
`IndexesManager.iter_all_indexes()` rebuild/clear loop: a reindex or `--reset-indexes` must never wipe
them. They are exposed as `indexes.finality_pin` / `indexes.finality_certificate`.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Iterable, Optional

from structlog import get_logger

from hathor.indexes.rocksdb_utils import RocksDBIndexUtils
from hathor.types import VertexId

if TYPE_CHECKING:  # pragma: no cover
    import rocksdb

logger = get_logger()

# Byte length used to encode an output index in a pin-store key.
_OUTPUT_INDEX_LEN = 4

_PIN_CF_NAME = b'finality-pin'
_CERTIFICATE_CF_NAME = b'finality-certificate'


def _outpoint_key(tx_id: VertexId, index: int) -> bytes:
    """Encode a UTXO outpoint (tx_id, index) as a pin-store key."""
    return bytes(tx_id) + index.to_bytes(_OUTPUT_INDEX_LEN, 'big')


class FinalityCertificateStore(ABC):
    """Stores verified Finality Certificates, keyed by transaction id."""

    @abstractmethod
    def add_certificate(self, tx_id: VertexId, certificate: bytes) -> None:
        """Persist a (verified) certificate for a transaction. Idempotent."""
        raise NotImplementedError

    @abstractmethod
    def get_certificate(self, tx_id: VertexId) -> Optional[bytes]:
        """Return the stored certificate bytes for a transaction, or None."""
        raise NotImplementedError

    def has_certificate(self, tx_id: VertexId) -> bool:
        """Return whether a certificate exists for a transaction."""
        return self.get_certificate(tx_id) is not None


class FinalityPinStore(ABC):
    """Stores a validator's immutable per-UTXO pins (outpoint -> pinned spender tx id)."""

    @abstractmethod
    def get_pin(self, tx_id: VertexId, index: int) -> Optional[VertexId]:
        """Return the transaction this UTXO is pinned to, or None if unpinned."""
        raise NotImplementedError

    @abstractmethod
    def _set_pin(self, tx_id: VertexId, index: int, spender: VertexId) -> None:
        raise NotImplementedError

    @abstractmethod
    def _delete_pin(self, tx_id: VertexId, index: int) -> None:
        raise NotImplementedError

    def try_pin(self, tx_id: VertexId, index: int, spender: VertexId) -> bool:
        """Pin a UTXO to ``spender`` iff it is unpinned or already pinned to ``spender``.

        Returns True if the UTXO is (now) pinned to ``spender``, and False if it was already pinned to
        a *different* transaction — i.e. the caller would be equivocating and must not sign. The pin is
        immutable: an existing pin to ``spender`` is left untouched and reported as success.
        """
        existing = self.get_pin(tx_id, index)
        if existing is not None:
            return existing == bytes(spender)
        self._set_pin(tx_id, index, spender)
        return True

    def unpin_resolved(self, outpoints: Iterable[tuple[VertexId, int]]) -> None:
        """Release the pins for UTXOs that have been resolved by settlement (housekeeping only)."""
        for tx_id, index in outpoints:
            self._delete_pin(tx_id, index)


class MemoryFinalityCertificateStore(FinalityCertificateStore):
    """In-memory certificate store (used in tests)."""

    def __init__(self) -> None:
        self._certificates: dict[bytes, bytes] = {}

    def add_certificate(self, tx_id: VertexId, certificate: bytes) -> None:
        self._certificates[bytes(tx_id)] = bytes(certificate)

    def get_certificate(self, tx_id: VertexId) -> Optional[bytes]:
        return self._certificates.get(bytes(tx_id))


class MemoryFinalityPinStore(FinalityPinStore):
    """In-memory pin store (used in tests)."""

    def __init__(self) -> None:
        self._pins: dict[bytes, bytes] = {}

    def get_pin(self, tx_id: VertexId, index: int) -> Optional[VertexId]:
        value = self._pins.get(_outpoint_key(tx_id, index))
        return VertexId(value) if value is not None else None

    def _set_pin(self, tx_id: VertexId, index: int, spender: VertexId) -> None:
        self._pins[_outpoint_key(tx_id, index)] = bytes(spender)

    def _delete_pin(self, tx_id: VertexId, index: int) -> None:
        self._pins.pop(_outpoint_key(tx_id, index), None)


class RocksDBFinalityCertificateStore(FinalityCertificateStore, RocksDBIndexUtils):
    """RocksDB-backed certificate store (its own column family)."""

    def __init__(self, db: 'rocksdb.DB') -> None:
        self.log = logger
        RocksDBIndexUtils.__init__(self, db, _CERTIFICATE_CF_NAME)

    def add_certificate(self, tx_id: VertexId, certificate: bytes) -> None:
        self.put(bytes(tx_id), bytes(certificate))

    def get_certificate(self, tx_id: VertexId) -> Optional[bytes]:
        return self.get_value(bytes(tx_id))


class RocksDBFinalityPinStore(FinalityPinStore, RocksDBIndexUtils):
    """RocksDB-backed pin store (its own column family)."""

    def __init__(self, db: 'rocksdb.DB') -> None:
        self.log = logger
        RocksDBIndexUtils.__init__(self, db, _PIN_CF_NAME)

    def get_pin(self, tx_id: VertexId, index: int) -> Optional[VertexId]:
        value = self.get_value(_outpoint_key(tx_id, index))
        return VertexId(value) if value is not None else None

    def _set_pin(self, tx_id: VertexId, index: int, spender: VertexId) -> None:
        self.put(_outpoint_key(tx_id, index), bytes(spender))

    def _delete_pin(self, tx_id: VertexId, index: int) -> None:
        self.delete(_outpoint_key(tx_id, index))
