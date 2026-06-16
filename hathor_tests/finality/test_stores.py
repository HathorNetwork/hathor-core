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

from hathor.finality.stores import MemoryFinalityCertificateStore, MemoryFinalityPinStore
from hathor.types import VertexId

TX_A = VertexId(b'\xa1' * 32)
TX_B = VertexId(b'\xb2' * 32)
SPENDER_1 = VertexId(b'\x01' * 32)
SPENDER_2 = VertexId(b'\x02' * 32)


def test_certificate_store_add_get_has() -> None:
    store = MemoryFinalityCertificateStore()
    assert not store.has_certificate(TX_A)
    assert store.get_certificate(TX_A) is None

    store.add_certificate(TX_A, b'cert-bytes')
    assert store.has_certificate(TX_A)
    assert store.get_certificate(TX_A) == b'cert-bytes'
    assert not store.has_certificate(TX_B)

    # Adding again is idempotent (last write wins).
    store.add_certificate(TX_A, b'cert-bytes-2')
    assert store.get_certificate(TX_A) == b'cert-bytes-2'


def test_pin_store_first_pin_succeeds() -> None:
    store = MemoryFinalityPinStore()
    assert store.get_pin(TX_A, 0) is None
    assert store.try_pin(TX_A, 0, SPENDER_1) is True
    assert store.get_pin(TX_A, 0) == bytes(SPENDER_1)


def test_pin_store_repin_same_spender_is_idempotent() -> None:
    store = MemoryFinalityPinStore()
    assert store.try_pin(TX_A, 0, SPENDER_1) is True
    # Re-pinning the same outpoint to the same spender must succeed (idempotent).
    assert store.try_pin(TX_A, 0, SPENDER_1) is True
    assert store.get_pin(TX_A, 0) == bytes(SPENDER_1)


def test_pin_store_conflicting_pin_is_rejected_and_immutable() -> None:
    store = MemoryFinalityPinStore()
    assert store.try_pin(TX_A, 0, SPENDER_1) is True
    # A different spender for the same outpoint must be rejected, and the pin must not change.
    assert store.try_pin(TX_A, 0, SPENDER_2) is False
    assert store.get_pin(TX_A, 0) == bytes(SPENDER_1)


def test_pin_store_distinguishes_outpoints() -> None:
    store = MemoryFinalityPinStore()
    assert store.try_pin(TX_A, 0, SPENDER_1) is True
    # Same tx, different output index is an independent outpoint.
    assert store.try_pin(TX_A, 1, SPENDER_2) is True
    assert store.get_pin(TX_A, 0) == bytes(SPENDER_1)
    assert store.get_pin(TX_A, 1) == bytes(SPENDER_2)


def test_pin_store_unpin_resolved() -> None:
    store = MemoryFinalityPinStore()
    store.try_pin(TX_A, 0, SPENDER_1)
    store.try_pin(TX_A, 1, SPENDER_1)
    store.unpin_resolved([(TX_A, 0), (TX_A, 1)])
    assert store.get_pin(TX_A, 0) is None
    assert store.get_pin(TX_A, 1) is None
    # After unpinning, the outpoint may be pinned again (e.g. to a different spender).
    assert store.try_pin(TX_A, 0, SPENDER_2) is True
