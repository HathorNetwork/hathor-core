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

from unittest.mock import Mock

import pytest

from hathor.conf.get_settings import get_global_settings
from hathor.conf.settings import HathorSettings
from hathor.feature_activation.feature import Feature
from hathor.feature_activation.feature_service import FeatureService
from hathor.transaction import Block, Transaction
from hathor.transaction.exceptions import IncorrectParents
from hathor.transaction.storage import TransactionStorage
from hathor.verification.vertex_verifier import VertexVerifier


@pytest.fixture
def settings() -> HathorSettings:
    return get_global_settings()


@pytest.fixture
def storage() -> TransactionStorage:
    storage = Mock(spec_set=TransactionStorage)
    vertices = {
        b'block1': Block(hash=b'block1', timestamp=1),
        b'block2': Block(hash=b'block2', timestamp=1),
        b'tx1': Transaction(hash=b'tx1', timestamp=1),
        b'tx2': Transaction(hash=b'tx2', timestamp=1),
        b'tx3': Transaction(hash=b'tx3', timestamp=1),
    }

    storage.get_transaction = lambda vertex_id: vertices[vertex_id]
    return storage


def get_feature_service(*, is_feature_active: bool) -> FeatureService:
    feature_service = Mock(spec_set=FeatureService)

    def is_feature_active_for_block(*, block: Block, feature: Feature) -> bool:
        assert feature is Feature.PARENT_BLOCK_FOR_TRANSACTIONS
        return is_feature_active

    feature_service.is_feature_active_for_block = Mock(side_effect=is_feature_active_for_block)
    return feature_service


def test_block_correct(settings: HathorSettings, storage: TransactionStorage) -> None:
    verifier = VertexVerifier(settings=settings, daa=Mock(), feature_service=Mock())
    block = Block(storage=storage, parents=[b'block1', b'tx1', b'tx2'], timestamp=2)

    verifier.verify_parents(block)


@pytest.mark.parametrize(
    ['parents', 'error'],
    [
        ([b'tx1', b'tx2'], 'wrong number of parents (block type): 0, expecting 1'),
        ([b'block1', b'block2', b'tx1', b'tx2'], 'wrong number of parents (block type): 2, expecting 1'),
        ([b'block1', b'tx1'], 'wrong number of parents (tx type): 1, expecting 2'),
        ([b'block1', b'tx1', b'tx2', b'tx3'], 'wrong number of parents (tx type): 3, expecting 2'),
    ]
)
def test_block_incorrect(
    settings: HathorSettings,
    storage: TransactionStorage,
    parents: list[bytes],
    error: str,
) -> None:
    verifier = VertexVerifier(settings=settings, daa=Mock(), feature_service=Mock())
    block = Block(storage=storage, parents=parents, timestamp=2)

    with pytest.raises(IncorrectParents) as e:
        verifier.verify_parents(block)

    assert str(e.value) == error


def test_tx_correct_without_feature_active(settings: HathorSettings, storage: TransactionStorage) -> None:
    feature_service = get_feature_service(is_feature_active=False)
    verifier = VertexVerifier(settings=settings, daa=Mock(), feature_service=feature_service)
    tx = Transaction(storage=storage, parents=[b'tx1', b'tx2'], timestamp=2)

    verifier.verify_parents(tx)


@pytest.mark.parametrize(
    ['parents', 'error'],
    [
        ([b'block1', b'tx1', b'tx2'], 'wrong number of parents (block type): 1, expecting 0'),
        ([b'tx1'], 'wrong number of parents (tx type): 1, expecting 2'),
        ([b'tx1', b'tx2', b'tx3'], 'wrong number of parents (tx type): 3, expecting 2'),
    ]
)
def test_tx_incorrect_without_feature_active(
    settings: HathorSettings,
    storage: TransactionStorage,
    parents: list[bytes],
    error: str,
) -> None:
    feature_service = get_feature_service(is_feature_active=False)
    verifier = VertexVerifier(settings=settings, daa=Mock(), feature_service=feature_service)
    tx = Transaction(storage=storage, parents=parents, timestamp=2)

    with pytest.raises(IncorrectParents) as e:
        verifier.verify_parents(tx)

    assert str(e.value) == error


def test_tx_correct_with_feature_active(settings: HathorSettings, storage: TransactionStorage) -> None:
    feature_service = get_feature_service(is_feature_active=True)
    verifier = VertexVerifier(settings=settings, daa=Mock(), feature_service=feature_service)

    tx = Transaction(storage=storage, parents=[b'tx1', b'tx2'], timestamp=2)
    verifier.verify_parents(tx)

    tx = Transaction(storage=storage, parents=[b'block1', b'tx1', b'tx2'], timestamp=2)
    verifier.verify_parents(tx)


@pytest.mark.parametrize(
    ['parents', 'error'],
    [
        ([b'block1', b'block2', b'tx1', b'tx2'], 'wrong number of parents (block type): 2, expecting 0'),
        ([b'tx1'], 'wrong number of parents (tx type): 1, expecting 2'),
        ([b'tx1', b'tx2', b'tx3'], 'wrong number of parents (tx type): 3, expecting 2'),
    ]
)
def test_tx_incorrect_with_feature_active(
    settings: HathorSettings,
    storage: TransactionStorage,
    parents: list[bytes],
    error: str,
) -> None:
    feature_service = get_feature_service(is_feature_active=True)
    verifier = VertexVerifier(settings=settings, daa=Mock(), feature_service=feature_service)
    tx = Transaction(storage=storage, parents=parents, timestamp=2)

    with pytest.raises(IncorrectParents) as e:
        verifier.verify_parents(tx)

    assert str(e.value) == error
