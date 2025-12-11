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

from hathor.conf.settings import HathorSettings
from hathor.consensus import poa
from hathor.consensus.consensus_settings import PoaSettings, PoaSignerSettings
from hathor.consensus.poa import PoaBlockProducer
from hathor.crypto.util import get_public_key_bytes_compressed
from hathor.manager import HathorManager
from hathor.transaction.poa import PoaBlock
from hathor_tests.poa.utils import get_settings, get_signer
from hathor_tests.test_memory_reactor_clock import TestMemoryReactorClock
from hathor_tests.unittest import TestBuilder


def _get_manager(settings: HathorSettings) -> HathorManager:
    reactor = TestMemoryReactorClock()
    reactor.advance(settings.GENESIS_BLOCK_TIMESTAMP)

    artifacts = TestBuilder() \
        .set_settings(settings) \
        .set_reactor(reactor) \
        .build()

    # tests will need the indexes to be initialized
    artifacts.manager._initialize_components()

    return artifacts.manager


def test_poa_block_producer_one_signer() -> None:
    signer = get_signer()
    settings = get_settings(signer, time_between_blocks=10)
    manager = _get_manager(settings)
    reactor = manager.reactor
    assert isinstance(reactor, TestMemoryReactorClock)
    manager = Mock(wraps=manager)
    producer = PoaBlockProducer(settings=settings, reactor=reactor, poa_signer=signer)
    producer.manager = manager
    producer.start()

    # at the beginning no blocks are produced
    reactor.advance(60)
    manager.on_new_tx.assert_not_called()

    # when we can start mining, we start producing blocks
    manager.can_start_mining = Mock(return_value=True)

    # we produce our first block
    reactor.advance(10)
    manager.on_new_tx.assert_called_once()
    block1 = manager.on_new_tx.call_args.args[0]
    assert isinstance(block1, PoaBlock)
    assert block1.timestamp == reactor.seconds()
    assert block1.weight == poa.BLOCK_WEIGHT_IN_TURN
    assert block1.outputs == []
    assert block1.get_block_parent_hash() == settings.GENESIS_BLOCK_HASH
    manager.on_new_tx.reset_mock()

    # haven't produced the second block yet
    reactor.advance(9)

    # we produce our second block
    reactor.advance(1)
    manager.on_new_tx.assert_called_once()
    block2 = manager.on_new_tx.call_args.args[0]
    assert isinstance(block2, PoaBlock)
    assert block2.timestamp == block1.timestamp + 10
    assert block2.weight == poa.BLOCK_WEIGHT_IN_TURN
    assert block2.outputs == []
    assert block2.get_block_parent_hash() == block1.hash
    manager.on_new_tx.reset_mock()

    # haven't produced the third block yet
    reactor.advance(9)

    # we produce our third block
    reactor.advance(1)
    manager.on_new_tx.assert_called_once()
    block3 = manager.on_new_tx.call_args.args[0]
    assert isinstance(block3, PoaBlock)
    assert block3.timestamp == block2.timestamp + 10
    assert block3.weight == poa.BLOCK_WEIGHT_IN_TURN
    assert block3.outputs == []
    assert block3.get_block_parent_hash() == block2.hash
    manager.on_new_tx.reset_mock()


def test_poa_block_producer_two_signers() -> None:
    signer1, signer2 = get_signer(), get_signer()
    settings = get_settings(signer1, signer2, time_between_blocks=10)
    manager = _get_manager(settings)
    reactor = manager.reactor
    assert isinstance(reactor, TestMemoryReactorClock)
    manager = Mock(wraps=manager)
    producer = PoaBlockProducer(settings=settings, reactor=reactor, poa_signer=signer1)
    producer.manager = manager
    producer.start()

    # at the beginning no blocks are produced
    reactor.advance(60)
    manager.on_new_tx.assert_not_called()

    # when we can start mining, we start producing blocks
    manager.can_start_mining = Mock(return_value=True)

    # we produce our first block
    reactor.advance(10)
    manager.on_new_tx.assert_called_once()
    block1 = manager.on_new_tx.call_args.args[0]
    assert isinstance(block1, PoaBlock)
    assert block1.timestamp == reactor.seconds()
    assert block1.weight == poa.BLOCK_WEIGHT_OUT_OF_TURN
    assert block1.outputs == []
    assert block1.get_block_parent_hash() == settings.GENESIS_BLOCK_HASH
    manager.on_new_tx.reset_mock()

    # haven't produced the second block yet
    reactor.advance(9)

    # we produce our second block
    reactor.advance(1)
    manager.on_new_tx.assert_called_once()
    block2 = manager.on_new_tx.call_args.args[0]
    assert isinstance(block2, PoaBlock)
    assert block2.timestamp == block1.timestamp + 10
    assert block2.weight == poa.BLOCK_WEIGHT_IN_TURN
    assert block2.outputs == []
    assert block2.get_block_parent_hash() == block1.hash
    manager.on_new_tx.reset_mock()

    # haven't produced the third block yet
    reactor.advance(29)

    # we produce our third block
    reactor.advance(1)
    manager.on_new_tx.assert_called_once()
    block3 = manager.on_new_tx.call_args.args[0]
    assert isinstance(block3, PoaBlock)
    assert block3.timestamp == block2.timestamp + 30
    assert block3.weight == poa.BLOCK_WEIGHT_OUT_OF_TURN
    assert block3.outputs == []
    assert block3.get_block_parent_hash() == block2.hash
    manager.on_new_tx.reset_mock()


@pytest.mark.parametrize(
    ['previous_height', 'signer_index', 'expected_delay'],
    [
        (0, 0, 90),
        (0, 1, 30),
        (0, 2, 70),
        (0, 3, 80),

        (1, 0, 80),
        (1, 1, 90),
        (1, 2, 30),
        (1, 3, 70),
    ]
)
def test_expected_block_timestamp(previous_height: int, signer_index: int, expected_delay: int) -> None:
    signers = [get_signer(), get_signer(), get_signer(), get_signer()]
    keys_and_signers = [
        (get_public_key_bytes_compressed(signer.get_public_key()), signer)
        for signer in signers
    ]
    signer = keys_and_signers[signer_index][1]
    settings = Mock()
    settings.CONSENSUS_ALGORITHM = PoaSettings(signers=tuple(
        [PoaSignerSettings(public_key=key_and_signer[0]) for key_and_signer in keys_and_signers]
    ))
    settings.AVG_TIME_BETWEEN_BLOCKS = 30
    producer = PoaBlockProducer(settings=settings, reactor=Mock(), poa_signer=signer)
    previous_block = Mock()
    previous_block.timestamp = 100
    previous_block.get_height = Mock(return_value=previous_height)

    result = producer._expected_block_timestamp(previous_block, signer_index)

    assert result == previous_block.timestamp + expected_delay
