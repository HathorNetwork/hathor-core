#  Copyright 2024 Hathor Labs
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

import pytest
from _pytest.fixtures import fixture

from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import HathorSettings
from hathor.transaction import Block, Transaction, TxInput, Vertex
from hathor.transaction.static_metadata import BlockStaticMetadata, TransactionStaticMetadata
from hathor.types import VertexId


@fixture
def settings() -> HathorSettings:
    return get_global_settings()


def create_block(*, vertex_id: VertexId, height: int) -> Block:
    block = Block(hash=vertex_id)
    block.set_static_metadata(BlockStaticMetadata(
        min_height=0,
        height=height,
        feature_activation_bit_counts=[],
        feature_states={},
    ))
    return block


def create_tx(*, vertex_id: VertexId, closest_ancestor_block: VertexId) -> Transaction:
    tx = Transaction(hash=vertex_id)
    tx.set_static_metadata(TransactionStaticMetadata(
        min_height=0,
        closest_ancestor_block=closest_ancestor_block,
    ))
    return tx


@fixture
def tx_storage() -> dict[VertexId, Vertex]:
    vertices = [
        create_block(vertex_id=b'b1', height=100),
        create_block(vertex_id=b'b2', height=101),
        create_block(vertex_id=b'b3', height=102),
        create_block(vertex_id=b'b4', height=103),
        create_tx(vertex_id=b'tx1', closest_ancestor_block=b'b1'),
        create_tx(vertex_id=b'tx2', closest_ancestor_block=b'b2'),
        create_tx(vertex_id=b'tx3', closest_ancestor_block=b'b4'),
    ]
    return {vertex.hash: vertex for vertex in vertices}


@pytest.mark.parametrize(
    ['inputs', 'expected'],
    [
        ([], b'b2'),
        ([b'b1'], b'b2'),
        ([b'b3'], b'b3'),
        ([b'tx3'], b'b4'),
        ([b'b1', b'b2', b'tx1', b'tx3'], b'b4'),
    ],
)
def test_closest_ancestor_block(
    settings: HathorSettings,
    tx_storage: dict[VertexId, Vertex],
    inputs: list[VertexId],
    expected: VertexId,
) -> None:
    tx = Transaction(
        parents=[b'tx1', b'tx2'],
        inputs=[TxInput(tx_id=vertex_id, index=0, data=b'') for vertex_id in inputs],
    )
    static_metadata = TransactionStaticMetadata.create(tx, settings, lambda vertex_id: tx_storage[vertex_id])

    assert static_metadata.closest_ancestor_block == expected
