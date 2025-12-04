import asyncio
from unittest.mock import ANY

from twisted.internet.defer import Deferred, inlineCallbacks

from hathor.healthcheck.resources.healthcheck import HealthcheckResource
from hathor.manager import HathorManager
from hathor.simulator import FakeConnection
from hathor.simulator.utils import add_new_blocks
from hathor_tests.resources.base_resource import StubSite, _BaseResourceTest


class HealthcheckReadinessTest(_BaseResourceTest._ResourceTest):
    def setUp(self):
        super().setUp()
        self.web = StubSite(HealthcheckResource(self.manager))

    @inlineCallbacks
    def test_get_no_recent_activity(self):
        """Scenario where the node doesn't have a recent block
        """
        response = yield self.web.get('/health')
        data = response.json_value()

        self.assertEqual(response.responseCode, 503)
        self.assertEqual(data, {
            'status': 'fail',
            'description': ANY,
            'checks': {
                'sync': [{
                    'componentType': 'internal',
                    'componentName': 'sync',
                    'status': 'fail',
                    'output': HathorManager.UnhealthinessReason.NO_RECENT_ACTIVITY,
                    'time': ANY
                }]
            }
        })

    def test_with_running_asyncio_loop(self):
        """Test with a running asyncio loop.

           This is a simulation of how this endpoint should behave in production when the
           --x-asyncio-reactor is provided to hathor-core, because this causes the reactor to run
           an asyncio loop.
        """
        # This deferred will be used solely to make sure the test doesn't finish before the async code
        done = Deferred()

        def set_done(_):
            done.callback(None)

        def set_done_fail(failure):
            done.errback(failure)

        # This will be called from inside the async method to perform the web request
        # while a running asyncio loop is present
        @inlineCallbacks
        def get_health():
            response = yield self.web.get('/health')
            return response.json_value()

        async def run():
            data = get_health()
            # When the request is done, we make sure the response is as expected
            data.addCallback(self.assertEqual, {
                'status': 'fail',
                'description': ANY,
                'checks': {
                    'sync': [{
                        'componentType': 'internal',
                        'componentName': 'sync',
                        'status': 'fail',
                        'output': HathorManager.UnhealthinessReason.NO_RECENT_ACTIVITY,
                        'time': ANY
                    }]
                }
            })
            # We succeed the "done" deferred if everything is ok
            data.addCallback(set_done)
            # We fail the "done" deferred if something goes wrong. This includes the assertion above failing.
            data.addErrback(set_done_fail)

        # This will make sure we have a running asyncio loop
        asyncio.get_event_loop().run_until_complete(run())

        # Return the deferred so the test doesn't finish before the async code
        return done

    @inlineCallbacks
    def test_strict_status_code(self):
        """Make sure the 'strict_status_code' parameter is working.
        The node should return 200 even if it's not ready.
        """
        response = yield self.web.get('/health', {b'strict_status_code': b'1'})
        data = response.json_value()

        self.assertEqual(response.responseCode, 200)
        self.assertEqual(data, {
            'status': 'fail',
            'description': ANY,
            'checks': {
                'sync': [{
                    'componentType': 'internal',
                    'componentName': 'sync',
                    'status': 'fail',
                    'output': HathorManager.UnhealthinessReason.NO_RECENT_ACTIVITY,
                    'time': ANY
                }]
            }
        })

    @inlineCallbacks
    def test_get_no_connected_peer(self):
        """Scenario where the node doesn't have any connected peer
        """
        # This will make sure the node has recent activity
        add_new_blocks(self.manager, 5)

        self.assertEqual(self.manager.has_recent_activity(), True)

        response = yield self.web.get('/health')
        data = response.json_value()

        self.assertEqual(response.responseCode, 503)
        self.assertEqual(data, {
            'status': 'fail',
            'description': ANY,
            'checks': {
                'sync': [{
                    'componentType': 'internal',
                    'componentName': 'sync',
                    'status': 'fail',
                    'output': HathorManager.UnhealthinessReason.NO_SYNCED_PEER,
                    'time': ANY
                }]
            }
        })

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

        response = yield self.web.get('/health')
        data = response.json_value()

        self.assertEqual(response.responseCode, 503)
        self.assertEqual(data, {
            'status': 'fail',
            'description': ANY,
            'checks': {
                'sync': [{
                    'componentType': 'internal',
                    'componentName': 'sync',
                    'status': 'fail',
                    'output': HathorManager.UnhealthinessReason.NO_SYNCED_PEER,
                    'time': ANY
                }]
            }
        })

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

        response = yield self.web.get('/health')
        data = response.json_value()

        self.assertTrue('application/json; charset=utf-8' in response.responseHeaders.getRawHeaders('content-type'))
        self.assertEqual(response.responseCode, 200)
        self.assertEqual(data, {
            'status': 'pass',
            'description': ANY,
            'checks': {
                'sync': [{
                    'componentType': 'internal',
                    'componentName': 'sync',
                    'status': 'pass',
                    'output': 'Healthy',
                    'time': ANY
                }]
            }
        })
