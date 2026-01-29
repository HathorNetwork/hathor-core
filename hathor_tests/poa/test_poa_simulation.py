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

import hashlib
from collections import defaultdict
from typing import Iterator

import base58
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from twisted.python.failure import Failure

from hathor.conf.settings import HathorSettings
from hathor.consensus import poa
from hathor.consensus.consensus_settings import PoaSettings, PoaSignerSettings
from hathor.consensus.poa import PoaSigner
from hathor.consensus.poa.poa_signer import PoaSignerId
from hathor.crypto.util import get_address_b58_from_public_key_bytes, get_public_key_bytes_compressed
from hathor.manager import HathorManager
from hathor.simulator import FakeConnection
from hathor.simulator.trigger import StopWhenTrue
from hathor.transaction import BaseTransaction, Block, TxInput, TxOutput
from hathor.transaction.genesis import generate_new_genesis
from hathor.transaction.poa import PoaBlock
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.util import not_none
from hathor_tests.poa.utils import get_settings, get_signer
from hathor_tests.simulation.base import SimulatorTestCase
from hathorlib.scripts import P2PKH


def _get_blocks_by_height(manager: HathorManager) -> defaultdict[int, list[PoaBlock]]:
    blocks_by_height: defaultdict[int, list[PoaBlock]] = defaultdict(list)

    for vertex in manager.tx_storage.get_all_transactions():
        if vertex.is_genesis or not isinstance(vertex, Block):
            continue
        assert isinstance(vertex, PoaBlock)
        blocks_by_height[vertex.get_height()].append(vertex)

    return blocks_by_height


def _assert_block_in_turn(block: PoaBlock, signer: PoaSigner) -> None:
    assert not block.get_metadata().voided_by
    assert block.weight == poa.BLOCK_WEIGHT_IN_TURN
    assert block.signer_id == signer._signer_id


def _assert_height_weight_signer_id(
    vertices: Iterator[BaseTransaction],
    expected: list[tuple[int, float, PoaSignerId]]
) -> None:
    non_voided_blocks: list[tuple[int, float, bytes]] = []

    for vertex in vertices:
        meta = vertex.get_metadata()
        if not isinstance(vertex, PoaBlock) or meta.voided_by:
            continue
        non_voided_blocks.append((vertex.get_height(), vertex.weight, vertex.signer_id))

    assert sorted(non_voided_blocks) == expected


class PoaSimulationTest(SimulatorTestCase):
    def _get_manager(self, signer: PoaSigner | None = None) -> HathorManager:
        builder = self.simulator.get_default_builder()
        if signer:
            builder.set_poa_signer(signer)
        artifacts = self.simulator.create_artifacts(builder)
        return artifacts.manager

    def test_no_producers(self) -> None:
        signer = get_signer()
        self.simulator.settings = get_settings(signer, time_between_blocks=10)
        manager1 = self._get_manager()
        manager2 = self._get_manager()

        connection = FakeConnection(manager1, manager2)
        self.simulator.add_connection(connection)

        # no producers, so no blocks
        self.simulator.run(120)
        assert manager1.tx_storage.get_block_count() == 1
        assert manager2.tx_storage.get_block_count() == 1

    def test_different_signer_settings(self) -> None:
        signer1, signer2 = get_signer(), get_signer()
        self.simulator.settings = get_settings(signer1)
        manager1 = self._get_manager()
        self.simulator.settings = get_settings(signer2)
        manager2 = self._get_manager()

        connection = FakeConnection(manager1, manager2)
        self.simulator.add_connection(connection)

        connection.run_one_step()
        assert b'ERROR Settings values are different' in connection.peek_tr1_value()
        assert connection.tr1.disconnecting

    def test_one_producer_allowed(self) -> None:
        signer = get_signer()
        signer_id = signer._signer_id
        self.simulator.settings = get_settings(signer, time_between_blocks=10)
        manager = self._get_manager(signer)

        # manager is allowed to produce blocks, so it does
        manager.allow_mining_without_peers()
        self.simulator.run(90)
        assert manager.tx_storage.get_block_count() == 10

        _assert_height_weight_signer_id(
            manager.tx_storage.get_all_transactions(),
            [
                (1, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (2, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (3, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (4, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (5, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (6, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (7, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (8, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (9, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
            ]
        )

    def test_one_producer_not_allowed(self) -> None:
        signer = get_signer()
        self.simulator.settings = get_settings(signer, time_between_blocks=10)
        manager = self._get_manager(signer)

        # manager is not allowed to produce blocks, so it does not
        self.simulator.run(120)
        assert manager.tx_storage.get_block_count() == 1

    def test_two_producers(self) -> None:
        signer1, signer2 = get_signer(), get_signer()
        signer_id1, signer_id2 = signer1._signer_id, signer2._signer_id
        self.simulator.settings = get_settings(signer1, signer2, time_between_blocks=10)
        manager1 = self._get_manager(signer1)
        manager2 = self._get_manager(signer2)

        connection = FakeConnection(manager1, manager2)
        self.simulator.add_connection(connection)

        trigger = StopWhenTrue(lambda: manager2.tx_storage.get_block_count() == 12)
        assert self.simulator.run(200, trigger=trigger)
        assert manager1.tx_storage.get_block_count() == 12
        assert manager2.tx_storage.get_block_count() == 12
        assert manager1.tx_storage.get_best_block_hash() == manager2.tx_storage.get_best_block_hash()

        _assert_height_weight_signer_id(
            manager1.tx_storage.get_all_transactions(),
            [
                (1, poa.BLOCK_WEIGHT_IN_TURN, signer_id2),
                (2, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (3, poa.BLOCK_WEIGHT_IN_TURN, signer_id2),
                (4, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (5, poa.BLOCK_WEIGHT_IN_TURN, signer_id2),
                (6, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (7, poa.BLOCK_WEIGHT_IN_TURN, signer_id2),
                (8, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (9, poa.BLOCK_WEIGHT_IN_TURN, signer_id2),
                (10, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
            ]
        )

        manager1_blocks_by_height = _get_blocks_by_height(manager1)
        manager2_blocks_by_height = _get_blocks_by_height(manager2)

        # both managers produce and propagate block #1 instantly
        assert len(manager1_blocks_by_height[1]) == 2
        assert set(manager1_blocks_by_height[1]) == set(manager2_blocks_by_height[1])

        # but only the block from signer2 becomes non-voided, as it is in turn
        non_voided_block1 = manager1.tx_storage.get_block_by_height(1)
        assert isinstance(non_voided_block1, PoaBlock)
        _assert_block_in_turn(non_voided_block1, signer2)

        # from blocks #2 to #10, the last one, the behavior alternates
        for height in range(2, 11):
            blocks_manager1 = manager1_blocks_by_height[height]
            blocks_manager2 = manager2_blocks_by_height[height]

            if height % 2 == 0:
                # if the height is even, it's manager1's turn.
                assert len(blocks_manager1) == 1
                _assert_block_in_turn(blocks_manager1[0], signer1)
            else:
                # if the height is odd, the opposite happens
                assert len(blocks_manager2) == 1
                _assert_block_in_turn(blocks_manager2[0], signer2)

    def test_four_signers(self) -> None:
        signer1, signer2, signer3, signer4 = get_signer(), get_signer(), get_signer(), get_signer()
        signer_id1, signer_id2, signer_id3 = signer1._signer_id, signer2._signer_id, signer3._signer_id
        self.simulator.settings = get_settings(signer1, signer2, signer3, signer4, time_between_blocks=10)
        manager1 = self._get_manager(signer1)
        manager2 = self._get_manager(signer2)
        manager3 = self._get_manager(signer3)

        connection12 = FakeConnection(manager1, manager2)
        connection13 = FakeConnection(manager1, manager3)
        self.simulator.add_connection(connection12)
        self.simulator.add_connection(connection13)

        # all managers are producing blocks
        self.simulator.run(110)

        # manager2 and manager3 leave
        manager2.stop()
        manager3.stop()
        self.simulator.run(160)

        # manager1 produces out of turn blocks with decreasing weights
        _assert_height_weight_signer_id(
            manager1.tx_storage.get_all_transactions(),
            [
                (1, poa.BLOCK_WEIGHT_IN_TURN, signer_id2),
                (2, poa.BLOCK_WEIGHT_IN_TURN, signer_id3),
                (3, poa.BLOCK_WEIGHT_OUT_OF_TURN / 1, signer_id1),
                (4, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (5, poa.BLOCK_WEIGHT_IN_TURN, signer_id2),
                (6, poa.BLOCK_WEIGHT_IN_TURN, signer_id3),
                (7, poa.BLOCK_WEIGHT_OUT_OF_TURN / 1, signer_id1),
                (8, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (9, poa.BLOCK_WEIGHT_OUT_OF_TURN / 3, signer_id1),
                (10, poa.BLOCK_WEIGHT_OUT_OF_TURN / 2, signer_id1),
                (11, poa.BLOCK_WEIGHT_OUT_OF_TURN / 1, signer_id1),
                (12, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
            ]
        )

    def test_producer_leave_and_comeback(self) -> None:
        signer1, signer2 = get_signer(), get_signer()
        signer_id1, signer_id2 = signer1._signer_id, signer2._signer_id
        self.simulator.settings = get_settings(signer1, signer2, time_between_blocks=10)

        expected = [
            # Before manager2 joins, only manager1 produces blocks
            (1, poa.BLOCK_WEIGHT_OUT_OF_TURN, signer_id1),
            (2, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
            (3, poa.BLOCK_WEIGHT_OUT_OF_TURN, signer_id1),
            # When manager2 joins, both of them start taking turns
            # But manager2 must sync first.
            (4, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
            # Here manager2 has already synced.
            (5, poa.BLOCK_WEIGHT_IN_TURN, signer_id2),
            (6, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
            (7, poa.BLOCK_WEIGHT_IN_TURN, signer_id2),
            (8, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
            (9, poa.BLOCK_WEIGHT_IN_TURN, signer_id2),
            (10, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
            (11, poa.BLOCK_WEIGHT_IN_TURN, signer_id2),
            (12, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
            # manager2 leaves so manager1 produces all the next blocks
            (13, poa.BLOCK_WEIGHT_OUT_OF_TURN, signer_id1),
            (14, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
            (15, poa.BLOCK_WEIGHT_OUT_OF_TURN, signer_id1),
            # manager2 comes back again, so both of them take turns again
            (16, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
            (17, poa.BLOCK_WEIGHT_IN_TURN, signer_id2),
            (18, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
        ]

        # here we create a situation with an intermittent producer, testing that the other producer produces blocks
        # out of turn
        manager1 = self._get_manager(signer1)
        manager1.allow_mining_without_peers()
        self.simulator.run(50)

        assert manager1.tx_storage.get_block_count() == 4
        _assert_height_weight_signer_id(
            manager1.tx_storage.get_all_transactions(),
            expected[:3],
        )

        manager2 = self._get_manager(signer2)
        connection = FakeConnection(manager1, manager2)
        self.simulator.add_connection(connection)
        self.simulator.run(80)

        assert manager1.tx_storage.get_block_count() == 14
        _assert_height_weight_signer_id(
            manager1.tx_storage.get_all_transactions(),
            expected[:12],
        )

        manager2.stop()
        connection.disconnect(Failure(Exception('testing')))
        self.simulator.remove_connection(connection)
        self.simulator.run(70)

        assert manager1.tx_storage.get_block_count() == 17
        _assert_height_weight_signer_id(
            manager1.tx_storage.get_all_transactions(),
            expected[:15],
        )

        assert not manager2.can_start_mining()
        self.simulator.add_connection(connection)
        connection.reconnect()
        manager2.start()
        self.simulator.run(30)

        assert manager1.tx_storage.get_block_count() == 20
        assert manager2.tx_storage.get_block_count() == 20
        assert manager1.tx_storage.get_best_block_hash() == manager2.tx_storage.get_best_block_hash()

        _assert_height_weight_signer_id(
            manager1.tx_storage.get_all_transactions(),
            expected,
        )

    def test_existing_storage(self) -> None:
        signer = get_signer()
        signer_id = signer._signer_id

        self.simulator.settings = get_settings(signer, time_between_blocks=10)
        builder = self.simulator.get_default_builder() \
            .set_poa_signer(signer) \

        artifacts1 = self.simulator.create_artifacts(builder)
        manager1 = artifacts1.manager
        rocksdb_dir = not_none(artifacts1.rocksdb_storage.temp_dir)
        manager1.allow_mining_without_peers()

        self.simulator.run(50)
        assert manager1.tx_storage.get_block_count() == 6

        _assert_height_weight_signer_id(
            manager1.tx_storage.get_all_transactions(),
            [
                (1, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (2, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (3, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (4, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (5, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
            ]
        )
        manager1.stop()
        not_none(artifacts1.rocksdb_storage).close()

        builder = self.simulator.get_default_builder() \
            .set_poa_signer(signer) \
            .set_rocksdb_path(path=rocksdb_dir)

        artifacts = self.simulator.create_artifacts(builder)
        manager2 = artifacts.manager
        manager2.allow_mining_without_peers()

        self.simulator.run(60)
        assert manager2.tx_storage.get_block_count() == 12

        _assert_height_weight_signer_id(
            manager2.tx_storage.get_all_transactions(),
            [
                (1, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (2, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (3, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (4, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (5, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (6, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (7, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (8, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (9, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (10, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (11, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
            ]
        )

    def test_new_signer_added(self) -> None:
        signer1, signer2 = get_signer(), get_signer()
        key1 = get_public_key_bytes_compressed(signer1.get_public_key())
        key2 = get_public_key_bytes_compressed(signer2.get_public_key())
        signer_settings1 = PoaSignerSettings(public_key=key1)
        signer_settings2 = PoaSignerSettings(public_key=key2, start_height=6, end_height=13)
        signer_id1 = signer1._signer_id
        self.simulator.settings = get_settings(signer_settings1, time_between_blocks=10)

        builder_1a = self.simulator.get_default_builder() \
            .set_poa_signer(signer1)
        artifacts_1a = self.simulator.create_artifacts(builder_1a)
        storage_1a = artifacts_1a.tx_storage
        manager_1a = artifacts_1a.manager
        manager_1a.allow_mining_without_peers()

        self.simulator.run(50)
        assert manager_1a.tx_storage.get_block_count() == 6

        _assert_height_weight_signer_id(
            manager_1a.tx_storage.get_all_transactions(),
            [
                (1, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (2, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (3, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (4, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (5, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
            ]
        )

        # we stop the network and add a new signer to the settings
        manager_1a.stop()
        self.simulator.settings = get_settings(signer_settings1, signer_settings2, time_between_blocks=10)

        builder_1b = self.simulator.get_default_builder() \
            .set_tx_storage(storage_1a) \
            .set_poa_signer(signer1)
        artifacts_1b = self.simulator.create_artifacts(builder_1b)
        manager_1b = artifacts_1b.manager
        manager_1b.allow_mining_without_peers()

        self.simulator.run(90)
        assert manager_1b.tx_storage.get_block_count() == 11

        # after we restart it, new blocks are alternating
        _assert_height_weight_signer_id(
            manager_1b.tx_storage.get_all_transactions(),
            [
                (1, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (2, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (3, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (4, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (5, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (6, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (7, poa.BLOCK_WEIGHT_OUT_OF_TURN, signer_id1),
                (8, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (9, poa.BLOCK_WEIGHT_OUT_OF_TURN, signer_id1),
                (10, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
            ]
        )

        # we add a non-producer
        manager_2 = self._get_manager()

        connection = FakeConnection(manager_1b, manager_2)
        self.simulator.add_connection(connection)
        self.simulator.run(60)

        # it should sync to the same blockchain
        _assert_height_weight_signer_id(
            manager_2.tx_storage.get_all_transactions(),
            [
                (1, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (2, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (3, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (4, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (5, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (6, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (7, poa.BLOCK_WEIGHT_OUT_OF_TURN, signer_id1),
                (8, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (9, poa.BLOCK_WEIGHT_OUT_OF_TURN, signer_id1),
                (10, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (11, poa.BLOCK_WEIGHT_OUT_OF_TURN, signer_id1),
                (12, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (13, poa.BLOCK_WEIGHT_OUT_OF_TURN, signer_id1),
                (14, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
                (15, poa.BLOCK_WEIGHT_IN_TURN, signer_id1),
            ]
        )

    def test_use_case(self) -> None:
        """Simulate a use case that uses a PoA network to mint all native tokens into custom tokens."""
        self.simulator.stop()
        private_key = ec.generate_private_key(ec.SECP256K1())
        signer = PoaSigner(private_key)
        public_key = signer.get_public_key()
        public_key_bytes = get_public_key_bytes_compressed(public_key)
        address = get_address_b58_from_public_key_bytes(public_key_bytes)
        script = P2PKH.create_output_script(base58.b58decode(address))
        signer_id = signer._signer_id

        tokens = 100_000
        block_timestamp = 1718894758
        min_block_weight = 0
        min_tx_weight = 0
        genesis_block, genesis_tx1, genesis_tx2 = generate_new_genesis(
            tokens=tokens,
            address=address,
            block_timestamp=block_timestamp,
            min_block_weight=min_block_weight,
            min_tx_weight=min_tx_weight,
        )

        self.simulator.settings = HathorSettings(
            P2PKH_VERSION_BYTE=b'\x49',
            MULTISIG_VERSION_BYTE=b'\x87',
            NETWORK_NAME='use-case-testnet',
            GENESIS_BLOCK_HASH=genesis_block.hash,
            GENESIS_TX1_HASH=genesis_tx1.hash,
            GENESIS_TX2_HASH=genesis_tx2.hash,
            GENESIS_OUTPUT_SCRIPT=script,
            GENESIS_BLOCK_TIMESTAMP=block_timestamp,
            GENESIS_BLOCK_NONCE=0,
            GENESIS_TX1_NONCE=0,
            GENESIS_TX2_NONCE=0,
            DECIMAL_PLACES=0,
            GENESIS_TOKENS=tokens,
            GENESIS_TOKEN_UNITS=tokens,
            TOKEN_DEPOSIT_PERCENTAGE=0.0000001,
            BLOCKS_PER_HALVING=None,
            INITIAL_TOKEN_UNITS_PER_BLOCK=0,
            MINIMUM_TOKEN_UNITS_PER_BLOCK=0,
            MIN_BLOCK_WEIGHT=min_block_weight,
            MIN_TX_WEIGHT_K=0,
            MIN_TX_WEIGHT_COEFFICIENT=0,
            MIN_TX_WEIGHT=min_tx_weight,
            REWARD_SPEND_MIN_BLOCKS=1,
            AVG_TIME_BETWEEN_BLOCKS=10,
            CONSENSUS_ALGORITHM=PoaSettings(
                signers=(PoaSignerSettings(public_key=public_key_bytes),),
            ),
        )
        self.simulator.start()

        manager = self._get_manager(signer)
        manager.allow_mining_without_peers()
        self.simulator.run(100)
        assert manager.tx_storage.get_block_count() == 11

        _assert_height_weight_signer_id(
            manager.tx_storage.get_all_transactions(),
            [
                (1, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (2, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (3, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (4, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (5, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (6, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (7, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (8, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (9, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
                (10, poa.BLOCK_WEIGHT_IN_TURN, signer_id),
            ]
        )

        token_tx = TokenCreationTransaction(
            timestamp=self.simulator.settings.GENESIS_BLOCK_TIMESTAMP + 3,
            weight=0,
            parents=[self.simulator.settings.GENESIS_TX1_HASH, self.simulator.settings.GENESIS_TX2_HASH],
            inputs=[TxInput(self.simulator.settings.GENESIS_BLOCK_HASH, 0, b'')],
            outputs=[
                TxOutput(1_000_000_000_000, script, 0b00000001),
                TxOutput(TxOutput.TOKEN_MINT_MASK, script, 0b10000001),
                TxOutput(TxOutput.TOKEN_MELT_MASK, script, 0b10000001),
            ],
            token_name='custom-token',
            token_symbol='CTK',
        )

        data_to_sign = token_tx.get_sighash_all()
        hashed_data = hashlib.sha256(data_to_sign).digest()
        signature = private_key.sign(hashed_data, ec.ECDSA(hashes.SHA256()))
        token_tx.inputs[0].data = P2PKH.create_input_data(public_key_bytes, signature)
        token_tx.update_hash()

        assert manager.on_new_tx(token_tx)
