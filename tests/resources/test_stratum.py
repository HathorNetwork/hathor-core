from twisted.internet.address import IPv4Address
from twisted.internet.defer import inlineCallbacks
from twisted.test.proto_helpers import StringTransportWithDisconnection

from hathor.stratum import JSONRPC
from hathor.stratum.resources import MiningStatsResource
from tests.resources.base_resource import StubSite, _BaseResourceTest


class StratumResourceTest(_BaseResourceTest._ResourceTest):
    def _manager_kwargs(self):
        kwargs = super()._manager_kwargs()
        kwargs['stratum_port'] = 8123
        return kwargs

    def setUp(self):
        super().setUp()
        self.web = StubSite(MiningStatsResource(self.manager))

    @inlineCallbacks
    def test_get(self):
        response = yield self.web.get('miners')
        data = response.json_value()
        self.assertEqual(data, [])

    @inlineCallbacks
    def test_subscribe_and_mine(self):
        import json
        from hashlib import sha256

        # boilerplate needed to exchange bytes

        transport = StringTransportWithDisconnection()
        protocol = self.manager.stratum_factory.buildProtocol(IPv4Address('TCP', '127.0.0.1', 8123))
        transport.protocol = protocol
        protocol.makeConnection(transport)

        # subscribe

        req = {
            'jsonrpc': '2.0',
            'id': '1',
            'method': 'subscribe'
        }
        protocol.lineReceived(json.dumps(req).encode())
        res = transport.value().split(JSONRPC.delimiter)
        self.assertEqual(len(res), 3)

        # check if we have subscribed

        response = yield self.web.get('miners')
        data = response.json_value()
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        r = data[0]
        del r['connection_start_time']
        del r['miner_id']
        self.assertEqual(
            r,
            {'address': '127.0.0.1:8123', 'blocks_found': 0, 'completed_jobs': 0, 'estimated_hash_rate': 0.0}
        )

        # mine a block

        # TODO: use predictable work instead of always repeating this work
        print(res)
        job = json.loads(res[1])['params']
        job_id = job['job_id']
        job_hash1 = sha256(bytes.fromhex(job['data']))
        job_nonce_size = job['nonce_size']
        job_max_nonce = 1 << (8 * job_nonce_size)
        job_target = 2**(256 - job['weight']) - 1
        nonce = 0
        while nonce < job_max_nonce:
            job_hash2 = job_hash1.copy()
            job_hash2.update(nonce.to_bytes(job_nonce_size, 'big'))
            if int(sha256(job_hash2.digest()).digest()[::-1].hex(), 16) < job_target:
                break
            nonce += 1
        # FIXME: assuming nonce was found: exited loop through break

        # submit our work

        req = {'job_id': job_id, 'nonce': nonce}
        protocol.lineReceived(json.dumps(req).encode())
        res = transport.value().split(JSONRPC.delimiter)
        self.assertEqual(len(res), 4)

        # check if our work has updated the stats

        response = yield self.web.get('miners')
        data = response.json_value()
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)
        res = data[0]
        del res['connection_start_time']
        del res['miner_id']
        self.assertEqual(
            res,
            # TODO: what is the actual estimated hash rate? should we test it?
            {'address': '127.0.0.1:8123', 'blocks_found': 1, 'completed_jobs': 1, 'estimated_hash_rate': 0.0}
        )
