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

"""Round-trip tests for the canonical binary TransactionMetadata format (defined in Rust,
htr-rs/crates/htr-lib/src/metadata/mod.rs), replacing the JSON storage encoding."""

import pytest

from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.transaction.transaction_metadata import NCExecutionState, TransactionMetadata, ValidationState


def _roundtrip(meta: TransactionMetadata) -> TransactionMetadata:
    return TransactionMetadata.from_bytes(meta.to_bytes())


def test_minimal_roundtrip() -> None:
    meta = TransactionMetadata(hash=None)
    restored = _roundtrip(meta)
    assert restored.hash is None
    assert restored.validation is ValidationState.INITIAL
    assert restored.voided_by is None
    assert restored.conflict_with is None
    assert restored.twins == []
    assert restored.spent_outputs == {}
    assert restored.first_block is None
    assert restored.nc_execution is None
    assert restored.nc_calls is None
    assert restored.nc_events is None


def test_full_roundtrip() -> None:
    meta = TransactionMetadata(hash=b'\x11' * 32)
    meta.validation = ValidationState.FULL
    meta.accumulated_weight = 2 ** 80 + 12345  # beyond u64: the format must carry exact ints
    meta.score = 2 ** 75
    meta.first_block = b'\x22' * 32
    meta.voided_by = {b'\x33' * 32, b'tx-non-grata'}  # incl. a sentinel marker (soft-voided style)
    meta.conflict_with = [b'\x44' * 32]
    meta.twins = [b'\x55' * 32]
    meta.received_by = [7, 8]
    meta.spent_outputs[0] = [b'\x66' * 32, b'\x67' * 32]
    meta.spent_outputs[3] = [b'\x68' * 32]
    meta.feature_states = {Feature.NOP_FEATURE_1: FeatureState.ACTIVE}
    meta.nc_block_root_id = b'\x77' * 32
    meta.nc_execution = NCExecutionState.SUCCESS
    meta.nc_events = [(b'\x88' * 32, b'event-data')]

    restored = _roundtrip(meta)
    assert restored.hash == meta.hash
    assert restored.validation is ValidationState.FULL
    assert restored.accumulated_weight == meta.accumulated_weight
    assert restored.score == meta.score
    assert restored.first_block == meta.first_block
    assert restored.voided_by == meta.voided_by
    assert restored.conflict_with == meta.conflict_with
    assert restored.twins == meta.twins
    assert restored.received_by == meta.received_by
    assert dict(restored.spent_outputs) == dict(meta.spent_outputs)
    assert restored.feature_states == meta.feature_states
    assert restored.nc_block_root_id == meta.nc_block_root_id
    assert restored.nc_execution is NCExecutionState.SUCCESS
    assert restored.nc_events == meta.nc_events


def test_json_equivalence() -> None:
    # the binary round-trip must agree with the JSON round-trip (the consensus reference
    # for what survives storage) field by field. to_storage_json needs a tx ref (it embeds
    # legacy static fields that to_bytes strips), so use a real Transaction's metadata.
    from hathor.transaction import Transaction
    from hathor.transaction.static_metadata import TransactionStaticMetadata
    tx = Transaction(timestamp=1000, weight=1.0)
    tx.update_hash()
    tx.set_static_metadata(TransactionStaticMetadata(min_height=0, closest_ancestor_block=b'\x00' * 32))
    meta = tx.get_metadata(use_storage=False)
    meta.validation = ValidationState.FULL
    meta.accumulated_weight = 123456789
    meta.score = 42
    meta.first_block = b'\xbb' * 32
    meta.voided_by = {b'\xcc' * 32}
    meta.spent_outputs[1] = [b'\xdd' * 32]

    from hathor.util import json_dumpb, json_loadb
    json_dict = meta.to_storage_json()
    for legacy in ('height', 'min_height', 'feature_activation_bit_counts'):
        json_dict.pop(legacy, None)
    json_restored = TransactionMetadata.create_from_json(json_loadb(json_dumpb(json_dict)))
    binary_restored = _roundtrip(meta)
    for attr in ('hash', 'validation', 'accumulated_weight', 'score', 'first_block',
                 'voided_by', 'conflict_with', 'twins', 'received_by'):
        assert getattr(binary_restored, attr) == getattr(json_restored, attr), attr
    assert dict(binary_restored.spent_outputs) == dict(json_restored.spent_outputs)


def test_corrupt_record_raises() -> None:
    with pytest.raises(ValueError):
        TransactionMetadata.from_bytes(b'\xff\x00garbage')
