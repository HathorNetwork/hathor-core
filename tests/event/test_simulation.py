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
from hathor.event.model.event_data import EmptyData, SpentOutput, TxData, TxInput, TxMetadata, TxOutput
from hathor.event.model.event_type import EventType
from hathor.p2p.peer_id import PeerId
from hathor.simulator import Simulator
from hathor.simulator.miner.dummy_miner import DummyMiner
from tests.utils import zip_chunkify

SIMULATOR_SEED = 9922163193306864793


def test_only_load():
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


def test_single_chain_one_block():
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

    simulator.run(2 * 60)

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
            ),
            BaseEvent(
                peer_id=main_peer_id.id,
                id=6,
                timestamp=1572653409.0,
                type=EventType.VERTEX_METADATA_CHANGED,
                data=TxData(hash='c7316accecf14910349ee06dbc265d7daa87cfb65c36b317f0985cb75ec71de8', nonce=3849224008, timestamp=1572653409, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUCVEmDq3zPs6KV42QQDe7R/jVSsCIrA==', token_data=0)], parents=['339f47da87435842b0b1b528ecd9eac2495ce983b3e9c923a37e1befbe12c792', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='c7316accecf14910349ee06dbc265d7daa87cfb65c36b317f0985cb75ec71de8', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=4.0, first_block=None, height=1, validation='full')),  # noqa: E501
            ),
            BaseEvent(
                peer_id=main_peer_id.id,
                id=7,
                timestamp=1572653409.0,
                type=EventType.VERTEX_METADATA_CHANGED,
                data=TxData(hash='33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869', nonce=2, timestamp=1572636345, version=1, weight=2.0, inputs=[], outputs=[], parents=[], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=['c7316accecf14910349ee06dbc265d7daa87cfb65c36b317f0985cb75ec71de8'], twins=[], accumulated_weight=2.0, score=2.0, first_block='c7316accecf14910349ee06dbc265d7daa87cfb65c36b317f0985cb75ec71de8', height=0, validation='full')),  # noqa: E501
            )
        ]),
        [
            BaseEvent(
                peer_id=main_peer_id.id,
                id=8,
                timestamp=1572653409.0,
                type=EventType.NEW_VERTEX_ACCEPTED,
                data=TxData(hash='c7316accecf14910349ee06dbc265d7daa87cfb65c36b317f0985cb75ec71de8', nonce=3849224008, timestamp=1572653409, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUCVEmDq3zPs6KV42QQDe7R/jVSsCIrA==', token_data=0)], parents=['339f47da87435842b0b1b528ecd9eac2495ce983b3e9c923a37e1befbe12c792', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='c7316accecf14910349ee06dbc265d7daa87cfb65c36b317f0985cb75ec71de8', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=4.0, first_block=None, height=1, validation='full')),  # noqa: E501
            )
        ]
    ]

    _assert_equal_events(actual_events, expected_events)


def test_single_chain_blocks_and_transactions():
    simulator = Simulator(seed=SIMULATOR_SEED)
    simulator.start()

    main_peer_id = PeerId()
    main_manager = simulator.create_peer(
        peer_id=main_peer_id,
        full_verification=False,
        event_ws_factory=Mock()
    )
    main_manager.allow_mining_without_peers()

    miner = simulator.create_miner(main_manager, DummyMiner, block_times=[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 120])
    miner.start()

    tx_gen = simulator.create_tx_generator(main_manager, rate=0.2, hashpower=1e12, ignore_no_funds=True)
    tx_gen.start()

    simulator.run(2 * 60)

    actual_event_iterator = main_manager._event_manager.event_storage.iter_from_event(0)
    actual_events = list(actual_event_iterator)

    expected_events = [
        [
            BaseEvent(peer_id=main_peer_id.id, id=0, timestamp=1572653259.0, type='LOAD_STARTED', data=EmptyData(), group_id=None),  # noqa E501
            BaseEvent(peer_id=main_peer_id.id, id=1, timestamp=1572653259.0, type='NEW_VERTEX_ACCEPTED', data=TxData(hash='339f47da87435842b0b1b528ecd9eac2495ce983b3e9c923a37e1befbe12c792', nonce=0, timestamp=1572636343, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=100000000000, script='dqkU/QUFm2AGJJVDuC82h2oXxz/SJnuIrA==', token_data=0)], parents=[], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='339f47da87435842b0b1b528ecd9eac2495ce983b3e9c923a37e1befbe12c792', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=2.0, first_block=None, height=0, validation='full')), group_id=None),  # noqa E501
            BaseEvent(peer_id=main_peer_id.id, id=2, timestamp=1572653259.0, type='NEW_VERTEX_ACCEPTED', data=TxData(hash='16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', nonce=6, timestamp=1572636344, version=1, weight=2.0, inputs=[], outputs=[], parents=[], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=2.0, first_block=None, height=0, validation='full')), group_id=None),  # noqa E501
            BaseEvent(peer_id=main_peer_id.id, id=3, timestamp=1572653259.0, type='NEW_VERTEX_ACCEPTED', data=TxData(hash='33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869', nonce=2, timestamp=1572636345, version=1, weight=2.0, inputs=[], outputs=[], parents=[], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=2.0, first_block=None, height=0, validation='full')), group_id=None),  # noqa E501
            BaseEvent(peer_id=main_peer_id.id, id=4, timestamp=1572653259.0, type='LOAD_FINISHED', data=EmptyData(), group_id=None),  # noqa E501
        ],
        UnorderedEventList([
            BaseEvent(peer_id=main_peer_id.id, id=5, timestamp=1572653289.25, type='VERTEX_METADATA_CHANGED', data=TxData(hash='16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', nonce=6, timestamp=1572636344, version=1, weight=2.0, inputs=[], outputs=[], parents=[], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=['d8d221392cda50bdb2c4bef1f11f826ddcad85ddab395d062d05fc4a592195c2'], twins=[], accumulated_weight=2.0, score=2.0, first_block='d8d221392cda50bdb2c4bef1f11f826ddcad85ddab395d062d05fc4a592195c2', height=0, validation='full')), group_id=None),  # noqa E501
            BaseEvent(peer_id=main_peer_id.id, id=7, timestamp=1572653289.25, type='VERTEX_METADATA_CHANGED', data=TxData(hash='33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869', nonce=2, timestamp=1572636345, version=1, weight=2.0, inputs=[], outputs=[], parents=[], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=['d8d221392cda50bdb2c4bef1f11f826ddcad85ddab395d062d05fc4a592195c2'], twins=[], accumulated_weight=2.0, score=2.0, first_block='d8d221392cda50bdb2c4bef1f11f826ddcad85ddab395d062d05fc4a592195c2', height=0, validation='full')), group_id=None),  # noqa E501
            BaseEvent(peer_id=main_peer_id.id, id=6, timestamp=1572653289.25, type='VERTEX_METADATA_CHANGED', data=TxData(hash='d8d221392cda50bdb2c4bef1f11f826ddcad85ddab395d062d05fc4a592195c2', nonce=3849224008, timestamp=1572653289, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUCVEmDq3zPs6KV42QQDe7R/jVSsCIrA==', token_data=0)], parents=['339f47da87435842b0b1b528ecd9eac2495ce983b3e9c923a37e1befbe12c792', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='d8d221392cda50bdb2c4bef1f11f826ddcad85ddab395d062d05fc4a592195c2', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=4.0, first_block=None, height=1, validation='full')), group_id=None),  # noqa E501
        ]),
        [
            BaseEvent(peer_id=main_peer_id.id, id=8, timestamp=1572653289.25, type='NEW_VERTEX_ACCEPTED', data=TxData(hash='d8d221392cda50bdb2c4bef1f11f826ddcad85ddab395d062d05fc4a592195c2', nonce=3849224008, timestamp=1572653289, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUCVEmDq3zPs6KV42QQDe7R/jVSsCIrA==', token_data=0)], parents=['339f47da87435842b0b1b528ecd9eac2495ce983b3e9c923a37e1befbe12c792', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='d8d221392cda50bdb2c4bef1f11f826ddcad85ddab395d062d05fc4a592195c2', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=4.0, first_block=None, height=1, validation='full')), group_id=None),  # noqa E501

            BaseEvent(peer_id=main_peer_id.id, id=9, timestamp=1572653290.0, type='VERTEX_METADATA_CHANGED', data=TxData(hash='6c4babf9e8fcda5c2eb9628cdef0216e9ac5ae6c118c671deb29ad705e0751b1', nonce=2571046484, timestamp=1572653290, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkU7TohZ0qkDwOGVvk902Ee5ocSLjiIrA==', token_data=0)], parents=['d8d221392cda50bdb2c4bef1f11f826ddcad85ddab395d062d05fc4a592195c2', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='6c4babf9e8fcda5c2eb9628cdef0216e9ac5ae6c118c671deb29ad705e0751b1', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=4.321928094887363, first_block=None, height=2, validation='full')), group_id=None),  # noqa E501
            BaseEvent(peer_id=main_peer_id.id, id=10, timestamp=1572653290.0, type='NEW_VERTEX_ACCEPTED', data=TxData(hash='6c4babf9e8fcda5c2eb9628cdef0216e9ac5ae6c118c671deb29ad705e0751b1', nonce=2571046484, timestamp=1572653290, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkU7TohZ0qkDwOGVvk902Ee5ocSLjiIrA==', token_data=0)], parents=['d8d221392cda50bdb2c4bef1f11f826ddcad85ddab395d062d05fc4a592195c2', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='6c4babf9e8fcda5c2eb9628cdef0216e9ac5ae6c118c671deb29ad705e0751b1', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=4.321928094887363, first_block=None, height=2, validation='full')), group_id=None),  # noqa E501

            BaseEvent(peer_id=main_peer_id.id, id=11, timestamp=1572653291.0, type='VERTEX_METADATA_CHANGED', data=TxData(hash='34eb2302c10686be9755f4abc309ae6414dbd38a9a1b02c067f3b46f04def16c', nonce=2810868913, timestamp=1572653291, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUJ1IwZftpI4amogcnKJWgc6/eJWuIrA==', token_data=0)], parents=['6c4babf9e8fcda5c2eb9628cdef0216e9ac5ae6c118c671deb29ad705e0751b1', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='34eb2302c10686be9755f4abc309ae6414dbd38a9a1b02c067f3b46f04def16c', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=4.584962500721156, first_block=None, height=3, validation='full')), group_id=None),  # noqa E501
            BaseEvent(peer_id=main_peer_id.id, id=12, timestamp=1572653291.0, type='NEW_VERTEX_ACCEPTED', data=TxData(hash='34eb2302c10686be9755f4abc309ae6414dbd38a9a1b02c067f3b46f04def16c', nonce=2810868913, timestamp=1572653291, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUJ1IwZftpI4amogcnKJWgc6/eJWuIrA==', token_data=0)], parents=['6c4babf9e8fcda5c2eb9628cdef0216e9ac5ae6c118c671deb29ad705e0751b1', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='34eb2302c10686be9755f4abc309ae6414dbd38a9a1b02c067f3b46f04def16c', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=4.584962500721156, first_block=None, height=3, validation='full')), group_id=None),  # noqa E501

            BaseEvent(peer_id=main_peer_id.id, id=13, timestamp=1572653292.0, type='VERTEX_METADATA_CHANGED', data=TxData(hash='4f358aa26c3aec3ba29d67f7610d1efa01a71d82217c7f8cbfaf586ecaf46b4d', nonce=2900453906, timestamp=1572653292, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUA6/mkfdCoE0/VMGDn4pFDLOkJF6IrA==', token_data=0)], parents=['34eb2302c10686be9755f4abc309ae6414dbd38a9a1b02c067f3b46f04def16c', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='4f358aa26c3aec3ba29d67f7610d1efa01a71d82217c7f8cbfaf586ecaf46b4d', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=4.807354922057604, first_block=None, height=4, validation='full')), group_id=None),  # noqa E501
            BaseEvent(peer_id=main_peer_id.id, id=14, timestamp=1572653292.0, type='NEW_VERTEX_ACCEPTED', data=TxData(hash='4f358aa26c3aec3ba29d67f7610d1efa01a71d82217c7f8cbfaf586ecaf46b4d', nonce=2900453906, timestamp=1572653292, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUA6/mkfdCoE0/VMGDn4pFDLOkJF6IrA==', token_data=0)], parents=['34eb2302c10686be9755f4abc309ae6414dbd38a9a1b02c067f3b46f04def16c', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='4f358aa26c3aec3ba29d67f7610d1efa01a71d82217c7f8cbfaf586ecaf46b4d', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=4.807354922057604, first_block=None, height=4, validation='full')), group_id=None),  # noqa E501

            BaseEvent(peer_id=main_peer_id.id, id=15, timestamp=1572653293.0, type='VERTEX_METADATA_CHANGED', data=TxData(hash='b9d8a77417f01e03ac13805c7d23f84367c72efb087aabaa8a6ce9669f407850', nonce=71421764, timestamp=1572653293, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkU+Rx7PbRe12ascscuo5C+ebnqXESIrA==', token_data=0)], parents=['4f358aa26c3aec3ba29d67f7610d1efa01a71d82217c7f8cbfaf586ecaf46b4d', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='b9d8a77417f01e03ac13805c7d23f84367c72efb087aabaa8a6ce9669f407850', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=5.0, first_block=None, height=5, validation='full')), group_id=None),  # noqa E501
            BaseEvent(peer_id=main_peer_id.id, id=16, timestamp=1572653293.0, type='NEW_VERTEX_ACCEPTED', data=TxData(hash='b9d8a77417f01e03ac13805c7d23f84367c72efb087aabaa8a6ce9669f407850', nonce=71421764, timestamp=1572653293, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkU+Rx7PbRe12ascscuo5C+ebnqXESIrA==', token_data=0)], parents=['4f358aa26c3aec3ba29d67f7610d1efa01a71d82217c7f8cbfaf586ecaf46b4d', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='b9d8a77417f01e03ac13805c7d23f84367c72efb087aabaa8a6ce9669f407850', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=5.0, first_block=None, height=5, validation='full')), group_id=None),  # noqa E501

            BaseEvent(peer_id=main_peer_id.id, id=17, timestamp=1572653294.0, type='VERTEX_METADATA_CHANGED', data=TxData(hash='c9066a952b25ff994461c39f16665602ee8b9d13da143307d264612d7e408d1e', nonce=2877639466, timestamp=1572653294, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUR/OZE3YnG5JNA94GMjCapu+YyqiIrA==', token_data=0)], parents=['b9d8a77417f01e03ac13805c7d23f84367c72efb087aabaa8a6ce9669f407850', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='c9066a952b25ff994461c39f16665602ee8b9d13da143307d264612d7e408d1e', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=5.169925001442312, first_block=None, height=6, validation='full')), group_id=None),  # noqa E501
            BaseEvent(peer_id=main_peer_id.id, id=18, timestamp=1572653294.0, type='NEW_VERTEX_ACCEPTED', data=TxData(hash='c9066a952b25ff994461c39f16665602ee8b9d13da143307d264612d7e408d1e', nonce=2877639466, timestamp=1572653294, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUR/OZE3YnG5JNA94GMjCapu+YyqiIrA==', token_data=0)], parents=['b9d8a77417f01e03ac13805c7d23f84367c72efb087aabaa8a6ce9669f407850', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='c9066a952b25ff994461c39f16665602ee8b9d13da143307d264612d7e408d1e', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=5.169925001442312, first_block=None, height=6, validation='full')), group_id=None),  # noqa E501

            BaseEvent(peer_id=main_peer_id.id, id=19, timestamp=1572653295.0, type='VERTEX_METADATA_CHANGED', data=TxData(hash='429543a84d186b6d3e6e20c41bfc6b26c812a18e04cc03deebf2d8ba05780aac', nonce=1254860223, timestamp=1572653295, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkU2G9W3JjDgfDf92m10Y1SliEnJWSIrA==', token_data=0)], parents=['c9066a952b25ff994461c39f16665602ee8b9d13da143307d264612d7e408d1e', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='429543a84d186b6d3e6e20c41bfc6b26c812a18e04cc03deebf2d8ba05780aac', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=5.321928094887363, first_block=None, height=7, validation='full')), group_id=None),  # noqa E501
            BaseEvent(peer_id=main_peer_id.id, id=20, timestamp=1572653295.0, type='NEW_VERTEX_ACCEPTED', data=TxData(hash='429543a84d186b6d3e6e20c41bfc6b26c812a18e04cc03deebf2d8ba05780aac', nonce=1254860223, timestamp=1572653295, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkU2G9W3JjDgfDf92m10Y1SliEnJWSIrA==', token_data=0)], parents=['c9066a952b25ff994461c39f16665602ee8b9d13da143307d264612d7e408d1e', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='429543a84d186b6d3e6e20c41bfc6b26c812a18e04cc03deebf2d8ba05780aac', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=5.321928094887363, first_block=None, height=7, validation='full')), group_id=None),  # noqa E501

            BaseEvent(peer_id=main_peer_id.id, id=21, timestamp=1572653296.0, type='VERTEX_METADATA_CHANGED', data=TxData(hash='81e7e7d0b7fb462a2d56d3df26327d9668679b447db9bbc7dd76d2ec9e5970db', nonce=681687539, timestamp=1572653296, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUzWAOeu+SS7iMOMU3PLGJWw0pzeCIrA==', token_data=0)], parents=['429543a84d186b6d3e6e20c41bfc6b26c812a18e04cc03deebf2d8ba05780aac', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='81e7e7d0b7fb462a2d56d3df26327d9668679b447db9bbc7dd76d2ec9e5970db', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=5.459431618637297, first_block=None, height=8, validation='full')), group_id=None),  # noqa E501
            BaseEvent(peer_id=main_peer_id.id, id=22, timestamp=1572653296.0, type='NEW_VERTEX_ACCEPTED', data=TxData(hash='81e7e7d0b7fb462a2d56d3df26327d9668679b447db9bbc7dd76d2ec9e5970db', nonce=681687539, timestamp=1572653296, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUzWAOeu+SS7iMOMU3PLGJWw0pzeCIrA==', token_data=0)], parents=['429543a84d186b6d3e6e20c41bfc6b26c812a18e04cc03deebf2d8ba05780aac', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='81e7e7d0b7fb462a2d56d3df26327d9668679b447db9bbc7dd76d2ec9e5970db', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=5.459431618637297, first_block=None, height=8, validation='full')), group_id=None),  # noqa E501

            BaseEvent(peer_id=main_peer_id.id, id=23, timestamp=1572653297.0, type='VERTEX_METADATA_CHANGED', data=TxData(hash='6a04d02f03caecd8d9a5c5388fc15afd1022b2db13f68e79f7a4568ac30329d0', nonce=1629369717, timestamp=1572653297, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUSQT96vTRhrFDCpyd3UYpXzzizO2IrA==', token_data=0)], parents=['81e7e7d0b7fb462a2d56d3df26327d9668679b447db9bbc7dd76d2ec9e5970db', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='6a04d02f03caecd8d9a5c5388fc15afd1022b2db13f68e79f7a4568ac30329d0', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=5.584962500721156, first_block=None, height=9, validation='full')), group_id=None),  # noqa E501
            BaseEvent(peer_id=main_peer_id.id, id=24, timestamp=1572653297.0, type='NEW_VERTEX_ACCEPTED', data=TxData(hash='6a04d02f03caecd8d9a5c5388fc15afd1022b2db13f68e79f7a4568ac30329d0', nonce=1629369717, timestamp=1572653297, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUSQT96vTRhrFDCpyd3UYpXzzizO2IrA==', token_data=0)], parents=['81e7e7d0b7fb462a2d56d3df26327d9668679b447db9bbc7dd76d2ec9e5970db', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='6a04d02f03caecd8d9a5c5388fc15afd1022b2db13f68e79f7a4568ac30329d0', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=5.584962500721156, first_block=None, height=9, validation='full')), group_id=None),  # noqa E501

            BaseEvent(peer_id=main_peer_id.id, id=25, timestamp=1572653298.0, type='VERTEX_METADATA_CHANGED', data=TxData(hash='556f8669c2c5beb864e2f0b34090bd86dcd4922dc6ccef8108bc4ba69b785e9e', nonce=1825990282, timestamp=1572653298, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkU3ME2MVjVXosrj6JwB1CUW5YpRpyIrA==', token_data=0)], parents=['6a04d02f03caecd8d9a5c5388fc15afd1022b2db13f68e79f7a4568ac30329d0', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='556f8669c2c5beb864e2f0b34090bd86dcd4922dc6ccef8108bc4ba69b785e9e', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=5.700439718141092, first_block=None, height=10, validation='full')), group_id=None),  # noqa E501
            BaseEvent(peer_id=main_peer_id.id, id=26, timestamp=1572653298.0, type='NEW_VERTEX_ACCEPTED', data=TxData(hash='556f8669c2c5beb864e2f0b34090bd86dcd4922dc6ccef8108bc4ba69b785e9e', nonce=1825990282, timestamp=1572653298, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkU3ME2MVjVXosrj6JwB1CUW5YpRpyIrA==', token_data=0)], parents=['6a04d02f03caecd8d9a5c5388fc15afd1022b2db13f68e79f7a4568ac30329d0', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='556f8669c2c5beb864e2f0b34090bd86dcd4922dc6ccef8108bc4ba69b785e9e', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=5.700439718141092, first_block=None, height=10, validation='full')), group_id=None),  # noqa E501

            BaseEvent(peer_id=main_peer_id.id, id=27, timestamp=1572653299.0, type='VERTEX_METADATA_CHANGED', data=TxData(hash='ddf62cc80ce6aa1a64fe89b5d15af59555e94126f88618eb28fae6a5b51fcae6', nonce=738245143, timestamp=1572653299, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUuSgyjGBpztv2JOEZEuBZ8hMWj0yIrA==', token_data=0)], parents=['556f8669c2c5beb864e2f0b34090bd86dcd4922dc6ccef8108bc4ba69b785e9e', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='ddf62cc80ce6aa1a64fe89b5d15af59555e94126f88618eb28fae6a5b51fcae6', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=5.807354922057604, first_block=None, height=11, validation='full')), group_id=None),  # noqa E501
            BaseEvent(peer_id=main_peer_id.id, id=28, timestamp=1572653299.0, type='NEW_VERTEX_ACCEPTED', data=TxData(hash='ddf62cc80ce6aa1a64fe89b5d15af59555e94126f88618eb28fae6a5b51fcae6', nonce=738245143, timestamp=1572653299, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUuSgyjGBpztv2JOEZEuBZ8hMWj0yIrA==', token_data=0)], parents=['556f8669c2c5beb864e2f0b34090bd86dcd4922dc6ccef8108bc4ba69b785e9e', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='ddf62cc80ce6aa1a64fe89b5d15af59555e94126f88618eb28fae6a5b51fcae6', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=2.0, score=5.807354922057604, first_block=None, height=11, validation='full')), group_id=None),  # noqa E501
        ],
        UnorderedEventList([
            BaseEvent(peer_id=main_peer_id.id, id=29, timestamp=1572653370.0, type='VERTEX_METADATA_CHANGED', data=TxData(hash='d8d221392cda50bdb2c4bef1f11f826ddcad85ddab395d062d05fc4a592195c2', nonce=3849224008, timestamp=1572653289, version=0, weight=2.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUCVEmDq3zPs6KV42QQDe7R/jVSsCIrA==', token_data=0)], parents=['339f47da87435842b0b1b528ecd9eac2495ce983b3e9c923a37e1befbe12c792', '16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='d8d221392cda50bdb2c4bef1f11f826ddcad85ddab395d062d05fc4a592195c2', spent_outputs=[SpentOutput(index=0, tx_ids=['f42fbcd1549389632236f85a80ad2dd8cac2f150501fb40b11210bad03718f79'])], conflict_with=[], voided_by=[], received_by=[], children=['6c4babf9e8fcda5c2eb9628cdef0216e9ac5ae6c118c671deb29ad705e0751b1'], twins=[], accumulated_weight=2.0, score=4.0, first_block=None, height=1, validation='full')), group_id=None),  # noqa E501
            BaseEvent(peer_id=main_peer_id.id, id=30, timestamp=1572653370.0, type='VERTEX_METADATA_CHANGED', data=TxData(hash='f42fbcd1549389632236f85a80ad2dd8cac2f150501fb40b11210bad03718f79', nonce=2, timestamp=1572653369, version=1, weight=18.664694903964126, inputs=[TxInput(tx_id='d8d221392cda50bdb2c4bef1f11f826ddcad85ddab395d062d05fc4a592195c2', index=0, data='SDBGAiEAwRECSYXApimxuQ9cD88w9U0N+SdAtJZfi0x1e3VgGmYCIQDsIsEC2nZzWgIa1U+eh/pIzhMg0rKvH3u8BaRLCpz4ICEC6Y5mbQB/qe5dH40iULOaEGoGq9CKeQMumnT8+yyMIHM=')], outputs=[TxOutput(value=1431, script='dqkU91U6sMdzgT3zxOtdIVGbqobP0FmIrA==', token_data=0), TxOutput(value=4969, script='dqkUm3CeNv0dX1HsZAvl2H0Cr6NZ40CIrA==', token_data=0)], parents=['16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='f42fbcd1549389632236f85a80ad2dd8cac2f150501fb40b11210bad03718f79', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=18.664694903964126, score=0.0, first_block=None, height=0, validation='full')), group_id=None),  # noqa E501
        ]),
        [
            BaseEvent(peer_id=main_peer_id.id, id=31, timestamp=1572653370.0, type='NEW_VERTEX_ACCEPTED', data=TxData(hash='f42fbcd1549389632236f85a80ad2dd8cac2f150501fb40b11210bad03718f79', nonce=2, timestamp=1572653369, version=1, weight=18.664694903964126, inputs=[TxInput(tx_id='d8d221392cda50bdb2c4bef1f11f826ddcad85ddab395d062d05fc4a592195c2', index=0, data='SDBGAiEAwRECSYXApimxuQ9cD88w9U0N+SdAtJZfi0x1e3VgGmYCIQDsIsEC2nZzWgIa1U+eh/pIzhMg0rKvH3u8BaRLCpz4ICEC6Y5mbQB/qe5dH40iULOaEGoGq9CKeQMumnT8+yyMIHM=')], outputs=[TxOutput(value=1431, script='dqkU91U6sMdzgT3zxOtdIVGbqobP0FmIrA==', token_data=0), TxOutput(value=4969, script='dqkUm3CeNv0dX1HsZAvl2H0Cr6NZ40CIrA==', token_data=0)], parents=['16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='f42fbcd1549389632236f85a80ad2dd8cac2f150501fb40b11210bad03718f79', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=18.664694903964126, score=0.0, first_block=None, height=0, validation='full')), group_id=None),  # noqa E501
        ],
        UnorderedEventList([
            BaseEvent(peer_id=main_peer_id.id, id=32, timestamp=1572653384.75, type='VERTEX_METADATA_CHANGED', data=TxData(hash='58fba3126e91f546fc11792637d0c4112e2de12920628f98ca1abe4fa97cc74f', nonce=4, timestamp=1572653384, version=1, weight=19.568795613217652, inputs=[TxInput(tx_id='f42fbcd1549389632236f85a80ad2dd8cac2f150501fb40b11210bad03718f79', index=0, data='RzBFAiBYhxr1IwcaECRZ+1aBbbribFNlBwaHj6xYloRvM5GgNgIhAJEZFLLmhQu50PkbVN+ShY0Wu3nC8ovnH/0A4HPT+oM3IQJ5e3XMPtNc1G7jFBLtvi0UahT3TdEIE7Oy5aV8FTNzng=='), TxInput(tx_id='f42fbcd1549389632236f85a80ad2dd8cac2f150501fb40b11210bad03718f79', index=1, data='RzBFAiBpIjqEJTn35NZ6f5K1yjKhs+JI52VaeoVYeh/KKXVCaQIhAPFpz7OuVHxAjY47dUqf30WAK/K65ESfwFcc3cq8Vx5QIQNuTU0Ido94RX5qWDgmtAgJIgBn2levBgXDiFai9kRQpg==')], outputs=[TxOutput(value=1199, script='dqkULLHzgtmv69PpRwlTBTzNGRcIE9yIrA==', token_data=0), TxOutput(value=5201, script='dqkUhLDX6YydV5HBbevVaHD+YWuBHRyIrA==', token_data=0)], parents=['f42fbcd1549389632236f85a80ad2dd8cac2f150501fb40b11210bad03718f79', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='58fba3126e91f546fc11792637d0c4112e2de12920628f98ca1abe4fa97cc74f', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=19.568795613217652, score=0.0, first_block=None, height=0, validation='full')), group_id=None),  # noqa E501
            BaseEvent(peer_id=main_peer_id.id, id=33, timestamp=1572653384.75, type='VERTEX_METADATA_CHANGED', data=TxData(hash='f42fbcd1549389632236f85a80ad2dd8cac2f150501fb40b11210bad03718f79', nonce=2, timestamp=1572653369, version=1, weight=18.664694903964126, inputs=[TxInput(tx_id='d8d221392cda50bdb2c4bef1f11f826ddcad85ddab395d062d05fc4a592195c2', index=0, data='SDBGAiEAwRECSYXApimxuQ9cD88w9U0N+SdAtJZfi0x1e3VgGmYCIQDsIsEC2nZzWgIa1U+eh/pIzhMg0rKvH3u8BaRLCpz4ICEC6Y5mbQB/qe5dH40iULOaEGoGq9CKeQMumnT8+yyMIHM=')], outputs=[TxOutput(value=1431, script='dqkU91U6sMdzgT3zxOtdIVGbqobP0FmIrA==', token_data=0), TxOutput(value=4969, script='dqkUm3CeNv0dX1HsZAvl2H0Cr6NZ40CIrA==', token_data=0)], parents=['16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='f42fbcd1549389632236f85a80ad2dd8cac2f150501fb40b11210bad03718f79', spent_outputs=[SpentOutput(index=0, tx_ids=['58fba3126e91f546fc11792637d0c4112e2de12920628f98ca1abe4fa97cc74f']), SpentOutput(index=1, tx_ids=['58fba3126e91f546fc11792637d0c4112e2de12920628f98ca1abe4fa97cc74f'])], conflict_with=[], voided_by=[], received_by=[], children=['58fba3126e91f546fc11792637d0c4112e2de12920628f98ca1abe4fa97cc74f'], twins=[], accumulated_weight=18.664694903964126, score=0.0, first_block=None, height=0, validation='full')), group_id=None),  # noqa E501
        ]),
        [
            BaseEvent(peer_id=main_peer_id.id, id=34, timestamp=1572653384.75, type='NEW_VERTEX_ACCEPTED', data=TxData(hash='58fba3126e91f546fc11792637d0c4112e2de12920628f98ca1abe4fa97cc74f', nonce=4, timestamp=1572653384, version=1, weight=19.568795613217652, inputs=[TxInput(tx_id='f42fbcd1549389632236f85a80ad2dd8cac2f150501fb40b11210bad03718f79', index=0, data='RzBFAiBYhxr1IwcaECRZ+1aBbbribFNlBwaHj6xYloRvM5GgNgIhAJEZFLLmhQu50PkbVN+ShY0Wu3nC8ovnH/0A4HPT+oM3IQJ5e3XMPtNc1G7jFBLtvi0UahT3TdEIE7Oy5aV8FTNzng=='), TxInput(tx_id='f42fbcd1549389632236f85a80ad2dd8cac2f150501fb40b11210bad03718f79', index=1, data='RzBFAiBpIjqEJTn35NZ6f5K1yjKhs+JI52VaeoVYeh/KKXVCaQIhAPFpz7OuVHxAjY47dUqf30WAK/K65ESfwFcc3cq8Vx5QIQNuTU0Ido94RX5qWDgmtAgJIgBn2levBgXDiFai9kRQpg==')], outputs=[TxOutput(value=1199, script='dqkULLHzgtmv69PpRwlTBTzNGRcIE9yIrA==', token_data=0), TxOutput(value=5201, script='dqkUhLDX6YydV5HBbevVaHD+YWuBHRyIrA==', token_data=0)], parents=['f42fbcd1549389632236f85a80ad2dd8cac2f150501fb40b11210bad03718f79', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='58fba3126e91f546fc11792637d0c4112e2de12920628f98ca1abe4fa97cc74f', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=19.568795613217652, score=0.0, first_block=None, height=0, validation='full')), group_id=None),  # noqa E501
        ],
        UnorderedEventList([
            BaseEvent(peer_id=main_peer_id.id, id=35, timestamp=1572653409.0, type='VERTEX_METADATA_CHANGED', data=TxData(hash='58fba3126e91f546fc11792637d0c4112e2de12920628f98ca1abe4fa97cc74f', nonce=4, timestamp=1572653384, version=1, weight=19.568795613217652, inputs=[TxInput(tx_id='f42fbcd1549389632236f85a80ad2dd8cac2f150501fb40b11210bad03718f79', index=0, data='RzBFAiBYhxr1IwcaECRZ+1aBbbribFNlBwaHj6xYloRvM5GgNgIhAJEZFLLmhQu50PkbVN+ShY0Wu3nC8ovnH/0A4HPT+oM3IQJ5e3XMPtNc1G7jFBLtvi0UahT3TdEIE7Oy5aV8FTNzng=='), TxInput(tx_id='f42fbcd1549389632236f85a80ad2dd8cac2f150501fb40b11210bad03718f79', index=1, data='RzBFAiBpIjqEJTn35NZ6f5K1yjKhs+JI52VaeoVYeh/KKXVCaQIhAPFpz7OuVHxAjY47dUqf30WAK/K65ESfwFcc3cq8Vx5QIQNuTU0Ido94RX5qWDgmtAgJIgBn2levBgXDiFai9kRQpg==')], outputs=[TxOutput(value=1199, script='dqkULLHzgtmv69PpRwlTBTzNGRcIE9yIrA==', token_data=0), TxOutput(value=5201, script='dqkUhLDX6YydV5HBbevVaHD+YWuBHRyIrA==', token_data=0)], parents=['f42fbcd1549389632236f85a80ad2dd8cac2f150501fb40b11210bad03718f79', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='58fba3126e91f546fc11792637d0c4112e2de12920628f98ca1abe4fa97cc74f', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=['01375179ce0f6a6d6501fec0ee14dba8e134372a8fe6519aa952ced7b0577aaa'], twins=[], accumulated_weight=19.568795613217652, score=0.0, first_block='01375179ce0f6a6d6501fec0ee14dba8e134372a8fe6519aa952ced7b0577aaa', height=0, validation='full')), group_id=None),  # noqa E501
            BaseEvent(peer_id=main_peer_id.id, id=36, timestamp=1572653409.0, type='VERTEX_METADATA_CHANGED', data=TxData(hash='f42fbcd1549389632236f85a80ad2dd8cac2f150501fb40b11210bad03718f79', nonce=2, timestamp=1572653369, version=1, weight=18.664694903964126, inputs=[TxInput(tx_id='d8d221392cda50bdb2c4bef1f11f826ddcad85ddab395d062d05fc4a592195c2', index=0, data='SDBGAiEAwRECSYXApimxuQ9cD88w9U0N+SdAtJZfi0x1e3VgGmYCIQDsIsEC2nZzWgIa1U+eh/pIzhMg0rKvH3u8BaRLCpz4ICEC6Y5mbQB/qe5dH40iULOaEGoGq9CKeQMumnT8+yyMIHM=')], outputs=[TxOutput(value=1431, script='dqkU91U6sMdzgT3zxOtdIVGbqobP0FmIrA==', token_data=0), TxOutput(value=4969, script='dqkUm3CeNv0dX1HsZAvl2H0Cr6NZ40CIrA==', token_data=0)], parents=['16ba3dbe424c443e571b00840ca54b9ff4cff467e10b6a15536e718e2008f952', '33e14cb555a96967841dcbe0f95e9eab5810481d01de8f4f73afb8cce365e869'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='f42fbcd1549389632236f85a80ad2dd8cac2f150501fb40b11210bad03718f79', spent_outputs=[SpentOutput(index=0, tx_ids=['58fba3126e91f546fc11792637d0c4112e2de12920628f98ca1abe4fa97cc74f']), SpentOutput(index=1, tx_ids=['58fba3126e91f546fc11792637d0c4112e2de12920628f98ca1abe4fa97cc74f'])], conflict_with=[], voided_by=[], received_by=[], children=['58fba3126e91f546fc11792637d0c4112e2de12920628f98ca1abe4fa97cc74f', '01375179ce0f6a6d6501fec0ee14dba8e134372a8fe6519aa952ced7b0577aaa'], twins=[], accumulated_weight=18.664694903964126, score=0.0, first_block='01375179ce0f6a6d6501fec0ee14dba8e134372a8fe6519aa952ced7b0577aaa', height=0, validation='full')), group_id=None),  # noqa E501
            BaseEvent(peer_id=main_peer_id.id, id=37, timestamp=1572653409.0, type='VERTEX_METADATA_CHANGED', data=TxData(hash='01375179ce0f6a6d6501fec0ee14dba8e134372a8fe6519aa952ced7b0577aaa', nonce=4226205465, timestamp=1572653409, version=0, weight=8.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUlAsOm11At4ng3JBW477DOP0eQtGIrA==', token_data=0)], parents=['ddf62cc80ce6aa1a64fe89b5d15af59555e94126f88618eb28fae6a5b51fcae6', '58fba3126e91f546fc11792637d0c4112e2de12920628f98ca1abe4fa97cc74f', 'f42fbcd1549389632236f85a80ad2dd8cac2f150501fb40b11210bad03718f79'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='01375179ce0f6a6d6501fec0ee14dba8e134372a8fe6519aa952ced7b0577aaa', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=8.0, score=20.18681516127742, first_block=None, height=12, validation='full')), group_id=None),  # noqa E501
        ]),
        [
            BaseEvent(peer_id=main_peer_id.id, id=38, timestamp=1572653409.0, type='NEW_VERTEX_ACCEPTED', data=TxData(hash='01375179ce0f6a6d6501fec0ee14dba8e134372a8fe6519aa952ced7b0577aaa', nonce=4226205465, timestamp=1572653409, version=0, weight=8.0, inputs=[], outputs=[TxOutput(value=6400, script='dqkUlAsOm11At4ng3JBW477DOP0eQtGIrA==', token_data=0)], parents=['ddf62cc80ce6aa1a64fe89b5d15af59555e94126f88618eb28fae6a5b51fcae6', '58fba3126e91f546fc11792637d0c4112e2de12920628f98ca1abe4fa97cc74f', 'f42fbcd1549389632236f85a80ad2dd8cac2f150501fb40b11210bad03718f79'], tokens=[], token_name=None, token_symbol=None, metadata=TxMetadata(hash='01375179ce0f6a6d6501fec0ee14dba8e134372a8fe6519aa952ced7b0577aaa', spent_outputs=[], conflict_with=[], voided_by=[], received_by=[], children=[], twins=[], accumulated_weight=8.0, score=20.18681516127742, first_block=None, height=12, validation='full')), group_id=None)  # noqa E501
        ]
    ]

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
