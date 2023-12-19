#  Copyright 2023 Hathor Labs
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

from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.feature_activation.feature_service import FeatureService
from hathor.transaction import Block, Transaction, TransactionMetadata, TxInput
from hathor.transaction.exceptions import IncorrectParents, InexistentInput
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.verification.verification_model import BlockDependencies, TransactionDependencies


def test_create_block_dependencies_success() -> None:
    parent_meta = Mock(spec=TransactionMetadata)
    parent_meta.height = 123
    parent_block = Mock(spec_set=Block)
    parent_block.get_metadata = Mock(return_value=parent_meta)

    block = Mock(spec_set=Block)
    block.is_genesis = False
    block.get_parents = Mock(return_value=[parent_block, Transaction(), Transaction()])
    daa = Mock(spec_set=DifficultyAdjustmentAlgorithm)
    feature_service = Mock(spec_set=FeatureService)

    BlockDependencies.create(block, daa, feature_service)


def test_create_block_dependencies_success_genesis() -> None:
    block = Mock(spec_set=Block)
    block.is_genesis = True
    block.get_parents = Mock(return_value=[])
    daa = Mock(spec_set=DifficultyAdjustmentAlgorithm)
    feature_service = Mock(spec_set=FeatureService)

    BlockDependencies.create(block, daa, feature_service)


def test_create_block_dependencies_incorrect_block_parent() -> None:
    block = Mock(spec_set=Block)
    block.is_genesis = False
    block.get_parents = Mock(return_value=[Transaction(), Transaction(), Transaction()])
    daa = Mock(spec_set=DifficultyAdjustmentAlgorithm)
    feature_service = Mock(spec_set=FeatureService)

    with pytest.raises(IncorrectParents):
        BlockDependencies.create(block, daa, feature_service)


def test_create_transaction_dependencies_success() -> None:
    tx = Mock(spec=Transaction)
    tx.get_parents = Mock(return_value=[Transaction(), Transaction()])
    tx.inputs = [
        TxInput(tx_id=b'hash1', index=0, data=b''),
        TxInput(tx_id=b'hash2', index=1, data=b''),
    ]

    TransactionDependencies.create(tx)


def test_create_transaction_dependencies_inexistent_input() -> None:
    def get_spent_tx(_):
        raise TransactionDoesNotExist('hash')

    tx = Mock(spec=Transaction)
    tx.get_spent_tx = Mock(side_effect=get_spent_tx)
    tx.get_parents = Mock(return_value=[Transaction(), Transaction()])
    tx.inputs = [
        TxInput(tx_id=b'hash1', index=0, data=b''),
        TxInput(tx_id=b'hash2', index=1, data=b''),
    ]

    with pytest.raises(InexistentInput):
        TransactionDependencies.create(tx)
