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

"""Round-trip tests for the canonical binary static-metadata format (defined in Rust,
htr-rs/crates/htr-lib/src/static_meta/mod.rs)."""

import pytest

from hathor.feature_activation.feature import Feature
from hathor.feature_activation.model.feature_state import FeatureState
from hathor.transaction import Block, Transaction
from hathor.transaction.static_metadata import BlockStaticMetadata, TransactionStaticMetadata, VertexStaticMetadata


def _roundtrip(meta: VertexStaticMetadata, target: Block | Transaction) -> VertexStaticMetadata:
    return VertexStaticMetadata.from_bytes(meta.to_bytes(), target=target)


def test_tx_static_metadata_roundtrip() -> None:
    meta = TransactionStaticMetadata(min_height=12345, closest_ancestor_block=b'\xab' * 32)
    assert _roundtrip(meta, Transaction()) == meta

    zero = TransactionStaticMetadata(min_height=0, closest_ancestor_block=b'\x00' * 32)
    assert _roundtrip(zero, Transaction()) == zero


def test_block_static_metadata_roundtrip() -> None:
    meta = BlockStaticMetadata(
        height=42,
        min_height=40,
        feature_activation_bit_counts=[0, 3, 7, 1],
        feature_states={Feature.NOP_FEATURE_1: FeatureState.ACTIVE, Feature.NOP_FEATURE_2: FeatureState.DEFINED},
    )
    assert _roundtrip(meta, Block()) == meta

    empty = BlockStaticMetadata(height=0, min_height=0, feature_activation_bit_counts=[], feature_states={})
    assert _roundtrip(empty, Block()) == empty


def test_kind_mismatch_is_rejected() -> None:
    tx_meta = TransactionStaticMetadata(min_height=1, closest_ancestor_block=b'\x01' * 32)
    with pytest.raises(AssertionError):
        VertexStaticMetadata.from_bytes(tx_meta.to_bytes(), target=Block())


def test_corrupt_record_raises() -> None:
    with pytest.raises(ValueError):
        VertexStaticMetadata.from_bytes(b'\xff\x00garbage', target=Transaction())
