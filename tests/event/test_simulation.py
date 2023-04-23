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

from typing import List
from unittest.mock import Mock

from hathor.event.model.base_event import BaseEvent
from hathor.event.model.event_data import EmptyData, TxData, TxMetadata, TxOutput
from hathor.event.model.event_type import EventType
from hathor.p2p.peer_id import PeerId
from hathor.simulator import Simulator
from hathor.simulator.miner.dummy_miner import DummyMiner
from tests.utils import zip_chunkify

SIMULATOR_SEED = 9922163193306864793


def test_fresh_start():
    simulator = Simulator(seed=SIMULATOR_SEED)
    simulator.start()

    main_peer_id = PeerId()
    main_manager = simulator.create_peer(
        peer_id=main_peer_id,
        full_verification=False,
        event_ws_factory=Mock()
    )
    main_manager.allow_mining_without_peers()

    simulator.run(2 * 60)

    actual_event_iterator = main_manager._event_manager.event_storage.iter_from_event(0)
    actual_events = list(actual_event_iterator)

    expected_events = [
        BaseEvent(
            peer_id=main_peer_id.id,
            id=0,
            timestamp=1572653259,
            type=EventType.LOAD_STARTED,
            data=EmptyData()
        ),
        BaseEvent(
            peer_id=main_peer_id.id,
            id=1,
            timestamp=1572653259,
            type=EventType.NEW_VERTEX_ACCEPTED,
            data=TxData(hash='339f47da87435842b0b1b528ecd9eac2495ce983b3e9c923a37e1befbe12c792', nonce=0, timestamp=1572636343, version=0, weight=2, inputs=[], outputs=[TxOutput(value=100000000000, script='dqkU/QUFm2AGJJVDuC82h2oXxz/SJnuIrA==', token_data=0)], parents=[], tokens=[], metadata=TxMetadata(hash='339f47da87435842b0b1b528ecd9eac2495ce983b3e9c923a37e1befbe12c792', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=2.0, first_block=None, height=0, validation='full'))  # noqa: E501
        ),
        BaseEvent(
            peer_id=main_peer_id.id,
            id=2,
            timestamp=1572653259.0,
            type=EventType.NEW_VERTEX_ACCEPTED,
            data=TxData(hash='16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', nonce=6, timestamp=1572636344, version=1, weight=2.0, inputs=[], outputs=[], parents=[], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=2.0, first_block=None, height=0, validation='full'))  # noqa: E501
        ),
        BaseEvent(
            peer_id=main_peer_id.id,
            id=3,
            timestamp=1572653259.0,
            type=EventType.NEW_VERTEX_ACCEPTED,
            data=TxData(hash='33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869', nonce=2, timestamp=1572636345, version=1, weight=2.0, inputs=[], outputs=[], parents=[], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=2.0, first_block=None, height=0, validation='full'))  # noqa: E501
        ),
        BaseEvent(
            peer_id=main_peer_id.id,
            id=4,
            timestamp=1572653259,
            type=EventType.LOAD_FINISHED,
            data=EmptyData()
        ),
    ]

    assert expected_events == actual_events


def test_single_chain():
    simulator = Simulator(seed=SIMULATOR_SEED)
    simulator.start()

    main_peer_id = PeerId()
    main_manager = simulator.create_peer(
        peer_id=main_peer_id,
        full_verification=False,
        event_ws_factory=Mock()
    )
    main_manager.allow_mining_without_peers()

    miner = simulator.create_miner(main_manager, DummyMiner, block_times=[120])
    miner.start()

    # tx_gen1 = simulator.create_tx_generator(main_manager, rate=0.01, hashpower=1e9, ignore_no_funds=True)
    # tx_gen1.start()

    simulator.run(2 * 60)

    # print()
    # print('Number of blocks:', main_manager.wallet.get_total_tx())
    # print()
    # print('Balance:', main_manager.wallet.balance[settings.HATHOR_TOKEN_UID])
    # print()
    # print()
    # txs = main_manager.tx_storage.transactions.values()
    # print('Txs:', len(txs))
    # for tx in txs:
    #     print(tx)
    #
    # print()
    # print()

    actual_event_iterator = main_manager._event_manager.event_storage.iter_from_event(0)
    actual_events = list(actual_event_iterator)

    expected_events = [
        [
            BaseEvent(
                peer_id=main_peer_id.id,
                id=0,
                timestamp=1572653259,
                type=EventType.LOAD_STARTED,
                data=EmptyData()
            ),
            BaseEvent(
                peer_id=main_peer_id.id,
                id=1,
                timestamp=1572653259,
                type=EventType.NEW_VERTEX_ACCEPTED,
                data=TxData(hash='339f47da87435842b0b1b528ecd9eac2495ce983b3e9c923a37e1befbe12c792', nonce=0, timestamp=1572636343, version=0, weight=2, inputs=[], outputs=[TxOutput(value=100000000000, script='dqkU/QUFm2AGJJVDuC82h2oXxz/SJnuIrA==', token_data=0)], parents=[], tokens=[], metadata=TxMetadata(hash='339f47da87435842b0b1b528ecd9eac2495ce983b3e9c923a37e1befbe12c792', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=2.0, first_block=None, height=0, validation='full'))  # noqa: E501
            ),
            BaseEvent(
                peer_id=main_peer_id.id,
                id=2,
                timestamp=1572653259.0,
                type=EventType.NEW_VERTEX_ACCEPTED,
                data=TxData(hash='16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', nonce=6, timestamp=1572636344, version=1, weight=2.0, inputs=[], outputs=[], parents=[], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=2.0, first_block=None, height=0, validation='full'))  # noqa: E501
            ),
            BaseEvent(
                peer_id=main_peer_id.id,
                id=3,
                timestamp=1572653259.0,
                type=EventType.NEW_VERTEX_ACCEPTED,
                data=TxData(hash='33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869', nonce=2, timestamp=1572636345, version=1, weight=2.0, inputs=[], outputs=[], parents=[], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=2.0, first_block=None, height=0, validation='full'))  # noqa: E501
            ),
            BaseEvent(
                peer_id=main_peer_id.id,
                id=4,
                timestamp=1572653259,
                type=EventType.LOAD_FINISHED,
                data=EmptyData()
            )
        ],
        UnorderedEventList([
            BaseEvent(
                peer_id=main_peer_id.id,
                id=5,
                timestamp=1572653409.0,
                type=EventType.VERTEX_METADATA_CHANGED,
                data=TxData(hash='16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', nonce=6, timestamp=1572636344, version=1, weight=2.0, inputs=[], outputs=[], parents=[], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=['c7316accecf14910349ee06dbc265d7daa87cfb65c36b317f0985cb75ec71de8'], twins=[], accumulated_weight=2.0, score=2.0, first_block='c7316accecf14910349ee06dbc265d7daa87cfb65c36b317f0985cb75ec71de8', height=0, validation='full')),  # noqa: E501
                group_id=None
            ),
            BaseEvent(
                peer_id=main_peer_id.id,
                id=6,
                timestamp=1572653409.0,
                type=EventType.VERTEX_METADATA_CHANGED,
                data=TxData(hash='c7316accecf14910349ee06dbc265d7daa87cfb65c36b317f0985cb75ec71de8', nonce=3849224008, timestamp=1572653409, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUCVEmDq3zPs6KV42QQDe7R/jVSsCIrA==', token_data=0)], parents=['339f47da87435842b0b1b528ecd9eac2495ce983b3e9c923a37e1befbe12c792', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='c7316accecf14910349ee06dbc265d7daa87cfb65c36b317f0985cb75ec71de8', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=4.0, first_block=None, height=1, validation='full')),  # noqa: E501
                group_id=None
            ),
            BaseEvent(
                peer_id=main_peer_id.id,
                id=7,
                timestamp=1572653409.0,
                type=EventType.VERTEX_METADATA_CHANGED,
                data=TxData(hash='33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869', nonce=2, timestamp=1572636345, version=1, weight=2.0, inputs=[], outputs=[], parents=[], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=['c7316accecf14910349ee06dbc265d7daa87cfb65c36b317f0985cb75ec71de8'], twins=[], accumulated_weight=2.0, score=2.0, first_block='c7316accecf14910349ee06dbc265d7daa87cfb65c36b317f0985cb75ec71de8', height=0, validation='full')),  # noqa: E501
                group_id=None
            )
        ]),
        [
            BaseEvent(
                peer_id=main_peer_id.id,
                id=8,
                timestamp=1572653409.0,
                type=EventType.NEW_VERTEX_ACCEPTED,
                data=TxData(hash='c7316accecf14910349ee06dbc265d7daa87cfb65c36b317f0985cb75ec71de8', nonce=3849224008, timestamp=1572653409, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUCVEmDq3zPs6KV42QQDe7R/jVSsCIrA==', token_data=0)], parents=['339f47da87435842b0b1b528ecd9eac2495ce983b3e9c923a37e1befbe12c792', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='c7316accecf14910349ee06dbc265d7daa87cfb65c36b317f0985cb75ec71de8', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=4.0, first_block=None, height=1, validation='full')),  # noqa: E501
                group_id=None
            )
        ]
    ]

    # print([actual_events[5:]])

    # print('-------------------')
    # print([item for sublist in expected_events for item in sublist])
    # print(actual_events)
    # print('-------------------')

    _assert_equal_events(actual_events, expected_events)


class UnorderedEventList(list):
    def __eq__(self, other):
        return _sorted_by_hash_without_id(self) == _sorted_by_hash_without_id(other)


def _assert_equal_events(actual_events, expected_events):
    for actual_events_chunk, expected_events_chunk in zip_chunkify(actual_events, expected_events):
        assert expected_events_chunk == actual_events_chunk


def _sorted_by_hash_without_id(events: List[BaseEvent]) -> List[BaseEvent]:
    events_without_id = [event.copy(exclude={'id'}) for event in events]

    def key(event: BaseEvent) -> str:
        assert isinstance(event.data, TxData), 'only tx events can be sorted'
        return event.data.hash

    return sorted(events_without_id, key=key)
