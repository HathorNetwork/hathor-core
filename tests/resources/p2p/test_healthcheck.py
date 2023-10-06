from twisted.internet.defer import inlineCallbacks

from hathor.conf.get_settings import get_settings
from hathor.manager import HathorManager
from hathor.p2p.resources.healthcheck import HealthcheckReadinessResource
from hathor.simulator import FakeConnection
from tests import unittest
from tests.resources.base_resource import StubSite, _BaseResourceTest
from tests.utils import add_new_blocks


class BaseHealthcheckReadinessTest(_BaseResourceTest._ResourceTest):
    __test__ = False

    def setUp(self):
        super().setUp()
        self.web = StubSite(HealthcheckReadinessResource(self.manager))

    @inlineCallbacks
    def test_get_no_recent_activity(self):
        """Scenario where the node doesn't have a recent block
        """
        response = yield self.web.get("p2p/readiness")
        data = response.json_value()

        self.assertEqual(data['success'], False)
        self.assertEqual(data['reason'], HathorManager.UnhealthinessReason.NO_RECENT_ACTIVITY)

    @inlineCallbacks
    def test_get_no_connected_peer(self):
        """Scenario where the node doesn't have any connected peer
        """
        # This will make sure the node has recent activity
        add_new_blocks(self.manager, 5)

        self.assertEqual(self.manager.has_recent_activity(), True)

        response = yield self.web.get("p2p/readiness")
        data = response.json_value()

        self.assertEqual(data['success'], False)
        self.assertEqual(data['reason'], HathorManager.UnhealthinessReason.NO_SYNCED_PEER)

    @inlineCallbacks
    def test_get_peer_out_of_sync(self):
        """Scenario where the node is connected with a peer but not synced
        """
        # This will make sure the node has recent activity
        add_new_blocks(self.manager, 5)

        self.manager2 = self.create_peer('testnet')
        self.conn1 = FakeConnection(self.manager, self.manager2)
        self.conn1.run_one_step()  # HELLO
        self.conn1.run_one_step()  # PEER-ID
        self.conn1.run_one_step()  # READY

        self.assertEqual(self.manager2.state, self.manager2.NodeState.READY)

        response = yield self.web.get("p2p/readiness")
        data = response.json_value()

        self.assertEqual(data['success'], False)
        self.assertEqual(data['reason'], HathorManager.UnhealthinessReason.NO_SYNCED_PEER)

    @inlineCallbacks
    def test_get_ready(self):
        """Scenario where the node is ready
        """
        self.manager2 = self.create_peer('testnet')
        self.conn1 = FakeConnection(self.manager, self.manager2)

        # This will make sure the node has recent activity
        add_new_blocks(self.manager, 5)

        # This will make sure the peers are synced
        for _ in range(600):
            self.conn1.run_one_step(debug=True)
            self.clock.advance(0.1)

        response = yield self.web.get("p2p/readiness")
        data = response.json_value()

        self.assertEqual(data['success'], True)

    @inlineCallbacks
    def test_peer_best_blockchain_too_far_ahead(self):
        """Scenarion where there is a connected peer which is too far ahead
        """
        self.manager2 = self.create_peer('testnet')
        self.manager3 = self.create_peer('testnet')
        self.conn1 = FakeConnection(self.manager, self.manager2)
        self.conn2 = FakeConnection(self.manager, self.manager3)

        # This will make sure the node has recent activity
        add_new_blocks(self.manager, 5)

        # This will make sure the peers are synced with us
        for _ in range(600):
            self.conn1.run_one_step(debug=True)
            self.conn2.run_one_step(debug=True)
            self.clock.advance(0.1)

        # Disable sync between us and manager3, because we want to guarantee that manager3
        # will have more blocks than us, while still being connected to us and reporting its
        # best-blockchain to us
        self.conn2.disable_sync()

        # This will make sure manager 3 has more blocks than us, enough to trigger the
        # BEST_PEER_HEIGHT_TOO_FAR unhealthiness
        additional_blocks_count = get_settings().HEALTHCHECK_MAX_HEIGHT_DIFF + 1
        add_new_blocks(self.manager3, additional_blocks_count)

        # This will let the peers exchange their best-blockchain. We won't sync with manager3
        # because we disabled it above. We let them run for 3 times the interval to be sure.
        for _ in range(3 * 10 * get_settings().BEST_BLOCKCHAIN_INTERVAL):
            self.conn1.run_one_step(debug=True)
            self.conn2.run_one_step(debug=True)
            self.clock.advance(0.1)

        response = yield self.web.get("p2p/readiness")
        data = response.json_value()

        self.assertEqual(data['success'], False)
        self.assertEqual(
            data['reason'],
            HathorManager.UnhealthinessReason.BEST_PEER_HEIGHT_TOO_FAR
            + f" Theirs is {additional_blocks_count + 5}, ours is 5"
        )


class SyncV1StatusTest(unittest.SyncV1Params, BaseHealthcheckReadinessTest):
    __test__ = True


class SyncV2StatusTest(unittest.SyncV2Params, BaseHealthcheckReadinessTest):
    __test__ = True


# sync-bridge should behave like sync-v2
class SyncBridgeStatusTest(unittest.SyncBridgeParams, SyncV2StatusTest):
    pass
