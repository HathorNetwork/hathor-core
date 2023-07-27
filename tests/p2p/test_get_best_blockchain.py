from hathor.conf import HathorSettings
from hathor.manager import DEFAULT_CAPABILITIES
from hathor.p2p.messages import ProtocolMessages
from hathor.p2p.states import ReadyState
from hathor.p2p.states.ready import BlockInfo
from hathor.simulator import FakeConnection
from hathor.simulator.trigger import StopAfterNMinedBlocks
from hathor.util import json_dumps
from tests import unittest
from tests.simulation.base import SimulatorTestCase

settings = HathorSettings()


class BaseGetBestBlockchainTestCase(SimulatorTestCase):

    def _send_cmd(self, proto, cmd, payload=None):
        if not payload:
            line = '{}\r\n'.format(cmd)
        else:
            line = '{} {}\r\n'.format(cmd, payload)

        if isinstance(line, str):
            line = line.encode('utf-8')

        return proto.dataReceived(line)

    def test_get_best_blockchain(self):
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
        self.assertIn(settings.CAPABILITY_GET_BEST_BLOCKCHAIN, protocol1.capabilities)
        self.assertIn(settings.CAPABILITY_GET_BEST_BLOCKCHAIN, protocol2.capabilities)

        # assert the protocol is in ReadyState
        state1 = protocol1.state
        state2 = protocol2.state
        self.assertIsInstance(state1, ReadyState)
        self.assertIsInstance(state2, ReadyState)

        # assert ReadyState commands
        self.assertIn(ProtocolMessages.GET_BEST_BLOCKCHAIN, state1.cmd_map)
        self.assertIn(ProtocolMessages.BEST_BLOCKCHAIN, state1.cmd_map)
        self.assertIn(ProtocolMessages.GET_BEST_BLOCKCHAIN, state2.cmd_map)
        self.assertIn(ProtocolMessages.BEST_BLOCKCHAIN, state2.cmd_map)

        # assert best blockchain contains the genesis block
        self.assertIsNotNone(state1.best_blockchain)
        self.assertIsNotNone(state2.best_blockchain)

        # mine 100 blocks
        miner = self.simulator.create_miner(manager1, hashpower=1e6)
        miner.start()
        trigger = StopAfterNMinedBlocks(miner, quantity=100)
        self.assertTrue(self.simulator.run(7200, trigger=trigger))
        miner.stop()

        # assert best blockchain exchange
        state1.send_get_best_blockchain()
        state2.send_get_best_blockchain()
        self.simulator.run(60)
        self.assertEqual(settings.DEFAULT_BEST_BLOCKCHAIN_BLOCKS, len(state1.best_blockchain))
        self.assertEqual(settings.DEFAULT_BEST_BLOCKCHAIN_BLOCKS, len(state2.best_blockchain))

        self.assertIsInstance(state1.best_blockchain[0], BlockInfo)
        self.assertIsInstance(state2.best_blockchain[0], BlockInfo)

    def test_handle_get_best_blockchain(self):
        manager1 = self.create_peer()
        manager2 = self.create_peer()
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)

        # mine 100 blocks
        miner = self.simulator.create_miner(manager1, hashpower=1e6)
        miner.start()
        trigger = StopAfterNMinedBlocks(miner, quantity=100)
        self.assertTrue(self.simulator.run(7200, trigger=trigger))
        miner.stop()

        connected_peers1 = list(manager1.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers1))
        protocol2 = connected_peers1[0]
        state2 = protocol2.state
        self.assertIsInstance(state2, ReadyState)

        connected_peers2 = list(manager2.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers2))
        protocol1 = connected_peers2[0]
        state1 = protocol1.state
        self.assertIsInstance(state1, ReadyState)

        # assert compliance with N blocks inside the boundaries
        state1.send_get_best_blockchain(n_blocks=1)
        self.simulator.run(60)
        self.assertFalse(conn12.tr1.disconnecting)

        state2.send_get_best_blockchain(n_blocks=100)
        self.simulator.run(60)
        self.assertFalse(conn12.tr2.disconnecting)

        # assert compliance with N blocks under lower boundary
        state1.send_get_best_blockchain(n_blocks=0)
        self.simulator.run(60)
        self.assertTrue(conn12.tr1.disconnecting)

        # assert compliance with N blocks beyond upper boundary
        state2.send_get_best_blockchain(n_blocks=101)
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
        self.assertIsInstance(state1, ReadyState)

        # assert param validation exception closes connection
        state1.handle_get_best_blockchain('invalid single value')
        self.simulator.run(60)
        # state1 is managed by manager2
        self.assertTrue(conn12.tr2.disconnecting)

    def test_handle_best_blockchain(self):
        manager1 = self.create_peer()
        manager2 = self.create_peer()
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)
        self.simulator.run(60)

        connected_peers1 = list(manager1.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers1))
        protocol2 = connected_peers1[0]
        state2 = protocol2.state
        self.assertIsInstance(state2, ReadyState)

        connected_peers2 = list(manager2.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers2))
        protocol1 = connected_peers2[0]
        state1 = protocol1.state
        self.assertIsInstance(state1, ReadyState)

        self.assertFalse(conn12.tr1.disconnecting)
        self.simulator.run(60)

        # assert a valid blockchain keeps connections open
        fake_blockchain = [
            (BlockInfo('0000000000000002eccfbca9bc06c449c01f37afb3cb49c04ee62921d9bcf9dc', 1, 1.1)),
            (BlockInfo('00000000000000006c846e182462a2cc437070288a486dfa21aa64bb373b8507', 2, 1.3)),
        ]
        state1.handle_best_blockchain(json_dumps(fake_blockchain))
        state2.handle_best_blockchain(json_dumps(fake_blockchain))
        self.simulator.run(60)
        self.assertFalse(conn12.tr1.disconnecting)
        self.assertFalse(conn12.tr2.disconnecting)

        # assert an invalid BlockInfo closes connection
        fake_blockchain = [
            # valid
            (BlockInfo('0000000000000002eccfbca9bc06c449c01f37afb3cb49c04ee62921d9bcf9dc', 1, 1.1)),
            # invalid because height is of float type
            (BlockInfo('00000000000000006c846e182462a2cc437070288a486dfa21aa64bb373b8507', 3.1, 1.3)),
        ]
        state2.handle_best_blockchain(json_dumps(fake_blockchain))
        self.simulator.run(60)
        self.assertTrue(conn12.tr1.disconnecting)

        fake_blockchain = [
            # valid
            (BlockInfo('0000000000000002eccfbca9bc06c449c01f37afb3cb49c04ee62921d9bcf9dc', 1, 1.1)),
            # invalid hash
            (BlockInfo('invalid hash', 3, 1.3)),
        ]
        state1.handle_best_blockchain(json_dumps(fake_blockchain))
        self.simulator.run(60)
        self.assertTrue(conn12.tr2.disconnecting)

    def test_node_without_get_best_blockchain_capability(self):
        manager1 = self.create_peer()
        manager2 = self.create_peer()

        cababilities_without_get_best_blockchain = [
            settings.CAPABILITY_WHITELIST,
            settings.CAPABILITY_SYNC_VERSION,
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
        self.assertTrue(protocol1.capabilities.issuperset(set(DEFAULT_CAPABILITIES)))

        # assert the peers don't engage in get_best_blockchain messages
        state2 = protocol2.state
        self.assertIsInstance(state2, ReadyState)
        self.assertIsNone(state2.lc_get_best_blockchain)
        state1 = protocol1.state
        self.assertIsInstance(state1, ReadyState)
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
        self.assertEqual([], state2.best_blockchain)
        self.assertEqual([], state1.best_blockchain)

        # assert connections will close if force get_best_blockchain
        state1.send_get_best_blockchain()
        self.simulator.run(60)
        self.assertTrue(conn12.tr1.disconnecting)
        state2.send_get_best_blockchain()
        self.simulator.run(60)
        self.assertTrue(conn12.tr2.disconnecting)

    def test_best_blockchain_from_hathor_manager(self):
        manager1 = self.create_peer()
        manager2 = self.create_peer()
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)
        blocks = 10

        error_msg = 'Invalid N. N must be greater than 0.'
        with self.assertRaises(ValueError, msg=error_msg):
            manager1.get_best_blockchain(0)

        # cache miss because the cache is empty
        self.assertEqual(len(manager1._latest_best_blockchain), 0)
        best_blockchain = manager1.get_best_blockchain(1)  # there is only the genesis block
        self.assertIsNotNone(manager1._latest_best_blockchain)

        # cache hit
        block = best_blockchain[0]
        best_blockchain = manager1.get_best_blockchain(1)  # there is only the genesis block
        memo_block = best_blockchain[0]
        # can only produce the same object if use the memoized best_blockchain
        self.assertTrue(block is memo_block)

        # cache miss if best block doesn't match
        fake_block = BlockInfo('fake hash', 1, 1.1)
        manager1._latest_best_blockchain = [fake_block]
        best_blockchain = manager1.get_best_blockchain(1)  # there is only the genesis block
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
        manager1.get_best_blockchain(blocks)  # update cache
        memo_block = best_blockchain[0]
        best_blockchain = manager1.get_best_blockchain(blocks+1)
        block = best_blockchain[0]
        self.assertFalse(block is memo_block)

        # cache hit if n_blocks <= cache length
        memo_block = block
        best_blockchain = manager1.get_best_blockchain(blocks-1)
        block = best_blockchain[0]
        self.assertTrue(block is memo_block)

    def test_stop_looping_on_exit(self):
        manager1 = self.create_peer()
        manager2 = self.create_peer()
        conn12 = FakeConnection(manager1, manager2, latency=0.05)
        self.simulator.add_connection(conn12)
        self.simulator.run(60)

        connected_peers1 = list(manager1.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers1))
        protocol2 = connected_peers1[0]
        state2 = protocol2.state
        self.assertIsInstance(state2, ReadyState)

        connected_peers2 = list(manager2.connections.connected_peers.values())
        self.assertEqual(1, len(connected_peers2))
        protocol1 = connected_peers2[0]
        state1 = protocol1.state
        self.assertIsInstance(state1, ReadyState)

        self.assertIsNotNone(state1.lc_get_best_blockchain)
        self.assertTrue(state1.lc_get_best_blockchain.running)

        self.assertIsNotNone(state2.lc_get_best_blockchain)
        self.assertTrue(state2.lc_get_best_blockchain.running)

        state1.on_exit()
        state2.on_exit()

        self.assertIsNotNone(state1.lc_get_best_blockchain)
        self.assertFalse(state1.lc_get_best_blockchain.running)

        self.assertIsNotNone(state2.lc_get_best_blockchain)
        self.assertFalse(state2.lc_get_best_blockchain.running)


class SyncV1GetBestBlockchainTestCase(unittest.SyncV1Params, BaseGetBestBlockchainTestCase):
    __test__ = True


class SyncV2GetBestBlockchainTestCase(unittest.SyncV2Params, BaseGetBestBlockchainTestCase):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeGetBestBlockchainTestCase(unittest.SyncBridgeParams, BaseGetBestBlockchainTestCase):
    __test__ = True
