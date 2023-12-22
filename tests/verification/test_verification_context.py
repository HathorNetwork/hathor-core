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

import pytest

from hathor.transaction import BaseTransaction, Block, Transaction
from hathor.transaction.storage import TransactionMemoryStorage
from hathor.verification.verification_context import verification_context


def test_verification_context_base_tx() -> None:
    storage = TransactionMemoryStorage()
    tx = Transaction(storage=storage)

    @verification_context
    def f(base_tx: BaseTransaction) -> None:
        assert base_tx.storage is None

    assert tx.storage == storage
    f(tx)
    assert tx.storage == storage


def test_verification_context_tx() -> None:
    storage = TransactionMemoryStorage()
    tx = Transaction(storage=storage)

    @verification_context
    def f(tx: Transaction) -> None:
        assert tx.storage is None

    assert tx.storage == storage
    f(tx)
    assert tx.storage == storage


def test_verification_context_block() -> None:
    storage = TransactionMemoryStorage()
    block = Block(storage=storage)

    @verification_context
    def f(blk: Block) -> None:
        assert blk.storage is None

    assert block.storage == storage
    f(block)
    assert block.storage == storage


def test_verification_context_no_base_tx() -> None:
    @verification_context
    def f(_x: int) -> None:
        pass

    with pytest.raises(AssertionError) as e:
        f(123)

    assert str(e.value) == 'The decorated function must have exactly 1 BaseTransaction parameter.'


def test_verification_context_multiple_base_tx() -> None:
    storage = TransactionMemoryStorage()
    tx = Transaction(storage=storage)
    block = Block(storage=storage)

    @verification_context
    def f(_blk: Block, _tx: Transaction) -> None:
        pass

    with pytest.raises(AssertionError) as e:
        f(block, tx)

    assert str(e.value) == 'The decorated function must have exactly 1 BaseTransaction parameter.'


def test_verification_context_nested() -> None:
    storage = TransactionMemoryStorage()
    tx = Transaction(storage=storage)

    @verification_context
    def f1(base_tx: BaseTransaction) -> None:
        assert base_tx.storage is None

    @verification_context
    def f2(base_tx: BaseTransaction) -> None:
        assert base_tx.storage is None
        f1(base_tx)
        assert base_tx.storage is None

    assert tx.storage == storage
    f2(tx)
    assert tx.storage == storage
