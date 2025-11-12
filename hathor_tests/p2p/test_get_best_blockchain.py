from twisted.internet.protocol import Protocol

from hathor.indexes.height_index import HeightInfo
from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.resources import StatusResource
from hathor.p2p.states import ReadyState
from hathor.p2p.utils import to_height_info
from hathor.simulator import FakeConnection
from hathor.simulator.trigger import StopAfterNMinedBlocks
from hathor.util import json_dumps
from hathor_tests.resources.base_resource import StubSite
from hathor_tests.simulation.base import SimulatorTestCase


def check_decreasing_monotonicity(sequence: list[int]) -> bool:
    """Check if a sequence is monotonic and is decreasing. Raise an exception otherwise.
    """
    n = len(sequence)
    for i in range(1, n):
        if sequence[i] >= sequence[i-1]:
            raise ValueError(f'Sequence not monotonic. Value {sequence[i]} >= {sequence[i-1]}. Index: {i}.')
    return True


class GetBestBlockchainTestCase(SimulatorTestCase):
    seed_config = 6

    def _send_cmd(self, proto: Protocol, cmd: str, payload: str | None = None) -> None:
        if not payload:
            line = '{}\r\n'.format(cmd)
        else:
            line = '{} {}\r\n'.format(cmd, payload)

        proto.dataReceived(line.encode('utf-8'))

    def test_get_best_blockchain(self) -> None:
        manager1 = self.create_peer()
        manager2 = self.create_peer()
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)
        self.simulator.run(3600)

        connected_peers1 = list(manager1.connections.connected_peers.values())
        connected_peers2 = list(manager2.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers1))
        self.assertEqual(1, len(connected_peers2))

        # assert the protocol has capabilities
        # HelloState is responsible to transmite to protocol the capabilities
        protocol1 = connected_peers2[0]
        protocol2 = connected_peers1[0]
        self.assertIsNotNone(protocol1.capabilities)
        self.assertIsNotNone(protocol2.capabilities)

        # assert the protocol has the GET_BEST_BLOCKCHAIN capability
        self.assertIn(self._settings.CAPABILITY_GET_BEST_BLOCKCHAIN, protocol1.capabilities)
        self.assertIn(self._settings.CAPABILITY_GET_BEST_BLOCKCHAIN, protocol2.capabilities)

        # assert the protocol is in ReadyState
        state1 = protocol1.state
        state2 = protocol2.state
        assert isinstance(state1, ReadyState)
        assert isinstance(state2, ReadyState)

        # assert ReadyState commands
        self.assertIn(ProtocolMessages.GET_BEST_BLOCKCHAIN, state1.cmd_map)
        self.assertIn(ProtocolMessages.BEST_BLOCKCHAIN, state1.cmd_map)
        self.assertIn(ProtocolMessages.GET_BEST_BLOCKCHAIN, state2.cmd_map)
        self.assertIn(ProtocolMessages.BEST_BLOCKCHAIN, state2.cmd_map)

        # assert best blockchain contains the genesis block
        self.assertIsNotNone(state1.peer_best_blockchain)
        self.assertIsNotNone(state2.peer_best_blockchain)

        # mine 20 blocks
        miner = self.simulator.create_miner(manager1, hashpower=1e6)
        miner.start()
        trigger = StopAfterNMinedBlocks(miner, quantity=20)
        self.assertTrue(self.simulator.run(7200, trigger=trigger))
        miner.stop()

        # assert best blockchain exchange
        state1.send_get_best_blockchain()
        state2.send_get_best_blockchain()
        self.simulator.run(60)
        self.assertEqual(self._settings.DEFAULT_BEST_BLOCKCHAIN_BLOCKS, len(state1.peer_best_blockchain))
        self.assertEqual(self._settings.DEFAULT_BEST_BLOCKCHAIN_BLOCKS, len(state2.peer_best_blockchain))

        assert isinstance(state1.peer_best_blockchain[0], HeightInfo)
        assert isinstance(state2.peer_best_blockchain[0], HeightInfo)

    def test_handle_get_best_blockchain(self) -> None:
        manager1 = self.create_peer()
        manager2 = self.create_peer()
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)

        # mine 20 blocks
        miner = self.simulator.create_miner(manager1, hashpower=1e6)
        miner.start()
        trigger = StopAfterNMinedBlocks(miner, quantity=20)
        self.assertTrue(self.simulator.run(7200, trigger=trigger))
        miner.stop()

        connected_peers1 = list(manager1.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers1))
        protocol2 = connected_peers1[0]
        state2 = protocol2.state
        assert isinstance(state2, ReadyState)

        connected_peers2 = list(manager2.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers2))
        protocol1 = connected_peers2[0]
        state1 = protocol1.state
        assert isinstance(state1, ReadyState)

        # assert compliance with N blocks inside the boundaries
        state1.send_get_best_blockchain(n_blocks=1)
        self.simulator.run(60)
        self.assertFalse(conn12.tr1.disconnecting)

        state2.send_get_best_blockchain(n_blocks=20)
        self.simulator.run(60)
        self.assertFalse(conn12.tr2.disconnecting)

        # assert compliance with N blocks under lower boundary
        state1.send_get_best_blockchain(n_blocks=0)
        self.simulator.run(60)
        self.assertTrue(conn12.tr1.disconnecting)

        # assert compliance with N blocks beyond upper boundary
        state2.send_get_best_blockchain(n_blocks=21)
        self.simulator.run(60)
        self.assertTrue(conn12.tr2.disconnecting)

        # prepare to assert param validation exception
        manager1 = self.create_peer()
        manager2 = self.create_peer()
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)
        self.simulator.run(60)
        self.assertFalse(conn12.tr1.disconnecting)
        self.assertFalse(conn12.tr2.disconnecting)

        connected_peers2 = list(manager2.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers2))
        protocol1 = connected_peers2[0]
        state1 = protocol1.state
        assert isinstance(state1, ReadyState)

        # assert param validation exception closes connection
        state1.handle_get_best_blockchain('invalid single value')
        self.simulator.run(60)
        # state1 is managed by manager2
        self.assertTrue(conn12.tr2.disconnecting)

    def test_handle_best_blockchain(self) -> None:
        manager1 = self.create_peer()
        manager2 = self.create_peer()
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)
        self.simulator.run(60)

        connected_peers1 = list(manager1.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers1))
        protocol2 = connected_peers1[0]
        state2 = protocol2.state
        assert isinstance(state2, ReadyState)

        connected_peers2 = list(manager2.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers2))
        protocol1 = connected_peers2[0]
        state1 = protocol1.state
        assert isinstance(state1, ReadyState)

        self.assertFalse(conn12.tr1.disconnecting)
        self.simulator.run(60)

        # assert a valid blockchain keeps connections open
        fake_blockchain: list[tuple[float, str]] = [
            (1, '0000000000000002eccfbca9bc06c449c01f37afb3cb49c04ee62921d9bcf9dc'),
            (2, '00000000000000006c846e182462a2cc437070288a486dfa21aa64bb373b8507'),
        ]
        state1.handle_best_blockchain(json_dumps(fake_blockchain))
        state2.handle_best_blockchain(json_dumps(fake_blockchain))
        self.simulator.run(60)
        self.assertFalse(conn12.tr1.disconnecting)
        self.assertFalse(conn12.tr2.disconnecting)

        # assert an invalid HeightInfo closes connection
        fake_blockchain = [
            # valid
            (1, '0000000000000002eccfbca9bc06c449c01f37afb3cb49c04ee62921d9bcf9dc'),
            # invalid because height is of float type
            (3.1, '00000000000000006c846e182462a2cc437070288a486dfa21aa64bb373b8507'),
        ]
        state2.handle_best_blockchain(json_dumps(fake_blockchain))
        self.simulator.run(60)
        self.assertTrue(conn12.tr1.disconnecting)

        fake_blockchain = [
            # valid
            (1, '0000000000000002eccfbca9bc06c449c01f37afb3cb49c04ee62921d9bcf9dc'),
            # invalid hash
            (2, 'invalid hash'),
        ]
        state1.handle_best_blockchain(json_dumps(fake_blockchain))
        self.simulator.run(60)
        self.assertTrue(conn12.tr2.disconnecting)

    def test_node_without_get_best_blockchain_capability(self) -> None:
        manager1 = self.create_peer()
        manager2 = self.create_peer()

        cababilities_without_get_best_blockchain = [
            self._settings.CAPABILITY_WHITELIST,
            self._settings.CAPABILITY_SYNC_VERSION,
        ]
        manager2.capabilities = cababilities_without_get_best_blockchain

        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)
        self.simulator.run(60)

        # assert the nodes are connected
        connected_peers1 = list(manager1.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers1))
        connected_peers2 = list(manager2.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers2))

        # assert the peers have the proper capabilities
        protocol2 = connected_peers1[0]
        self.assertTrue(protocol2.capabilities.issuperset(set(cababilities_without_get_best_blockchain)))
        protocol1 = connected_peers2[0]
        default_capabilities = manager2.get_default_capabilities()
        self.assertTrue(protocol1.capabilities.issuperset(set(default_capabilities)))

        # assert the peers don't engage in get_best_blockchain messages
        state2 = protocol2.state
        assert isinstance(state2, ReadyState)
        self.assertIsNone(state2.lc_get_best_blockchain)
        state1 = protocol1.state
        assert isinstance(state1, ReadyState)
        self.assertIsNone(state1.lc_get_best_blockchain)

        # assert the connections remains open
        self.assertFalse(conn12.tr2.disconnecting)
        self.assertFalse(conn12.tr1.disconnecting)

        # mine 10 blocks
        miner = self.simulator.create_miner(manager1, hashpower=1e6)
        miner.start()
        trigger = StopAfterNMinedBlocks(miner, quantity=10)
        self.assertTrue(self.simulator.run(720, trigger=trigger))
        miner.stop()

        # assert the best_blockchain remains empty even after mine
        self.assertEqual([], state2.peer_best_blockchain)
        self.assertEqual([], state1.peer_best_blockchain)

        # assert connections will close if force get_best_blockchain
        state1.send_get_best_blockchain()
        self.simulator.run(60)
        self.assertTrue(conn12.tr1.disconnecting)
        state2.send_get_best_blockchain()
        self.simulator.run(60)
        self.assertTrue(conn12.tr2.disconnecting)

    def test_best_blockchain_from_storage(self) -> None:
        manager1 = self.create_peer()
        manager2 = self.create_peer()
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)
        blocks = 10

        # cache miss because the cache is empty
        self.assertEqual(len(manager1.tx_storage._latest_n_height_tips), 0)
        best_blockchain = manager1.tx_storage.get_n_height_tips(1)  # there is only the genesis block
        self.assertIsNotNone(manager1.tx_storage._latest_n_height_tips)

        # cache hit
        block = best_blockchain[0]
        best_blockchain = manager1.tx_storage.get_n_height_tips(1)  # there is only the genesis block
        memo_block = best_blockchain[0]
        # can only produce the same object if use the memoized best_blockchain
        self.assertTrue(block is memo_block)

        # cache miss if best block doesn't match
        fake_block = HeightInfo(1, b'fake hash')
        # manager1._latest_n_height_tips = [fake_block]  # FIXME: This property is not defined. Fix this test.
        best_blockchain = manager1.tx_storage.get_n_height_tips(1)  # there is only the genesis block
        block = best_blockchain[0]
        # the memoized best_blockchain is skiped
        # and a new best_blockchain object is generated
        self.assertFalse(block is fake_block)

        # mine 10 blocks
        miner = self.simulator.create_miner(manager1, hashpower=1e6)
        miner.start()
        trigger = StopAfterNMinedBlocks(miner, quantity=10)
        self.assertTrue(self.simulator.run(720, trigger=trigger))
        miner.stop()

        # cache miss if n_blocks > cache length
        manager1.tx_storage.get_n_height_tips(blocks)  # update cache
        memo_block = best_blockchain[0]
        best_blockchain = manager1.tx_storage.get_n_height_tips(blocks+1)
        block = best_blockchain[0]
        self.assertFalse(block is memo_block)

        # cache hit if n_blocks <= cache length
        memo_block = block
        best_blockchain = manager1.tx_storage.get_n_height_tips(blocks-1)
        block = best_blockchain[0]
        self.assertTrue(block is memo_block)

    def test_stop_looping_on_exit(self) -> None:
        manager1 = self.create_peer()
        manager2 = self.create_peer()
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)
        self.simulator.run(60)

        connected_peers1 = list(manager1.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers1))
        protocol2 = connected_peers1[0]
        state2 = protocol2.state
        assert isinstance(state2, ReadyState)

        connected_peers2 = list(manager2.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers2))
        protocol1 = connected_peers2[0]
        state1 = protocol1.state
        assert isinstance(state1, ReadyState)

        assert state1.lc_get_best_blockchain is not None
        self.assertTrue(state1.lc_get_best_blockchain.running)

        assert state2.lc_get_best_blockchain is not None
        self.assertTrue(state2.lc_get_best_blockchain.running)

        state1.on_exit()
        state2.on_exit()

        self.assertIsNotNone(state1.lc_get_best_blockchain)
        self.assertFalse(state1.lc_get_best_blockchain.running)

        self.assertIsNotNone(state2.lc_get_best_blockchain)
        self.assertFalse(state2.lc_get_best_blockchain.running)

    async def test_best_blockchain_from_status_resource(self) -> None:
        manager1 = self.create_peer()
        manager2 = self.create_peer()
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)
        self.simulator.run(60)

        # check /status before generate blocks
        self.web = StubSite(StatusResource(manager1))
        response = await self.web.get("status")
        data = response.json_value()
        connections = data.get('connections')
        self.assertEqual(len(connections['connected_peers']), 1)
        dag = data.get('dag')

        # connected_peers
        # assert there is the genesis block
        peer_best_blockchain = connections['connected_peers'][0]['peer_best_blockchain']
        self.assertEqual(len(peer_best_blockchain), 1)
        # assert the height_info height is from genesis
        raw_height_info_height = peer_best_blockchain[0][0]
        self.assertEqual(raw_height_info_height, 0)

        # dag
        # assert there is the genesis block
        peer_best_blockchain = dag['best_blockchain']
        self.assertEqual(len(peer_best_blockchain), 1)
        # assert the height_info height is from genesis
        raw_height_info_height = peer_best_blockchain[0][0]
        self.assertEqual(raw_height_info_height, 0)

        # mine 20 blocks
        miner = self.simulator.create_miner(manager1, hashpower=1e6)
        miner.start()
        trigger = StopAfterNMinedBlocks(miner, quantity=20)
        self.assertTrue(self.simulator.run(1440, trigger=trigger))
        miner.stop()
        # let the blocks to propagate
        self.simulator.run(60)

        # check /status after mine blocks
        response = await self.web.get("status")
        data = response.json_value()
        connections = data.get('connections')
        self.assertEqual(len(connections['connected_peers']), 1)
        dag = data.get('dag')

        # connected_peers
        # assert default peer_best_blockchain length
        peer_best_blockchain = connections['connected_peers'][0]['peer_best_blockchain']
        self.assertEqual(len(peer_best_blockchain), self._settings.DEFAULT_BEST_BLOCKCHAIN_BLOCKS)

        # assert a raw_height_info can be converted to HeightInfo
        try:
            raw_height_info = peer_best_blockchain[0]
            height_info = to_height_info(raw_height_info)
            # assert the first element height is from the lastest block mined
            self.assertEqual(height_info.height, 20)
        except ValueError:
            self.fail('Block info not valid')

        # assert decreasing order for a sequence of heights
        height_sequence = [hi[0] for hi in peer_best_blockchain]
        try:
            self.assertTrue(check_decreasing_monotonicity(height_sequence))
        except ValueError as e:
            self.fail(str(e))

        # dag
        # assert default peer_best_blockchain length
        peer_best_blockchain = dag['best_blockchain']
        self.assertEqual(len(peer_best_blockchain), self._settings.DEFAULT_BEST_BLOCKCHAIN_BLOCKS)

        # assert a raw_height_info can be converted to HeightInfo
        try:
            raw_height_info = peer_best_blockchain[0]
            height_info = to_height_info(raw_height_info)
            # assert the first element height is from the lastest block mined
            self.assertEqual(height_info.height, 20)
        except ValueError:
            self.fail('Block info not valid')

        # assert decreasing order for a sequence of heights
        height_sequence = [hi[0] for hi in peer_best_blockchain]
        try:
            self.assertTrue(check_decreasing_monotonicity(height_sequence))
        except ValueError as e:
            self.fail(str(e))
