from hashlib import sha256
from json import dumps as json_dumps, loads as json_loads
from time import sleep
from typing import Optional
from uuid import uuid4

import pytest
from twisted.internet.testing import StringTransportWithDisconnection

from hathor.simulator.clock import MemoryReactorHeapClock
from hathor.stratum import (
    INVALID_PARAMS,
    INVALID_REQUEST,
    INVALID_SOLUTION,
    JOB_NOT_FOUND,
    JSONRPC,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    STALE_JOB,
    StratumClient,
    StratumFactory,
)
from hathor.transaction.block import Block
from hathor_tests import unittest


def _send_subscribe(protocol, id=None):
    """Sends subcribe request."""
    if id is None:
        id = uuid4()
    protocol.lineReceived('{{"jsonrpc": "2.0", "id": "{}", "method": "subscribe"}}'.format(id).encode())


class _BaseStratumTest(unittest.TestCase):
    __test__ = False

    def setUp(self):
        super().setUp()
        self.manager = self.create_peer('testnet')
        self.manager.allow_mining_without_peers()
        self.factory = StratumFactory(self.manager, reactor=MemoryReactorHeapClock())
        self.factory.start()
        self.protocol = self.factory.buildProtocol('127.0.0.1')
        self.transport = StringTransportWithDisconnection()
        self.transport.protocol = self.protocol
        self.protocol.makeConnection(self.transport)
        # subscribe and ignore response
        _send_subscribe(self.protocol)
        self.job = self._get_latest_message()['params']
        self.transport.clear()

    def tearDown(self):
        super().tearDown()
        self.factory.stop()

    def _get_latest_message(self):
        value = self.transport.value()
        data = value.split(JSONRPC.delimiter)[-2]
        self.log.debug('get_latest_message', value=value, data=data)
        return json_loads(data)


class StratumServerTest(_BaseStratumTest):
    __test__ = True

    def test_parse_error(self):
        self.protocol.lineReceived(b'{]')
        response = json_loads(self.transport.value())
        self.assertEqual(response['error'], PARSE_ERROR)

    def test_invalid_json_rpc(self):
        self.protocol.lineReceived(b'{"jsonrpc": "x.y"}')
        response = json_loads(self.transport.value())
        self.assertEqual(response['error'], INVALID_REQUEST)

    def test_invalid_id_error(self):
        self.protocol.lineReceived(b'{"id": 123}')
        response = json_loads(self.transport.value())
        self.assertEqual(response['error'], INVALID_REQUEST)

    def test_send_rpc_error(self):
        miner_id = self.protocol.miner_id
        self.assertIsNotNone(miner_id)
        self.assertIn(miner_id, self.factory.miner_protocols)

        self.protocol.send_error(INVALID_REQUEST)
        self.assertNotIn(miner_id, self.factory.miner_protocols)

    def test_result_and_error(self):
        self.protocol.lineReceived(b'{"jsonrpc": "2.0", "result": "OK", "error": {"code": 0, "message": "Fake"}}')
        response = json_loads(self.transport.value())
        self.assertEqual(response['error'], INVALID_REQUEST)

    def test_json_rpc(self):
        # Test sending request
        uuid = uuid4()
        self.protocol.send_request('foo', ['bar', 'foobar'], uuid)
        # Test receiving response
        self.protocol.lineReceived(b'{"jsonrpc": "2.0", "result": "foo"}')
        # Test receiving error
        self.protocol.lineReceived(b'{"jsonrpc": "2.0", "error": {"code": 0, "message": "Fake"}}')
        # Test sending unserializable request
        self.protocol.send_json({'id': uuid})

    def test_stratum_connection(self):
        transport = StringTransportWithDisconnection()
        protocol = self.factory.buildProtocol('127.0.0.1')
        protocol.makeConnection(transport)
        self.assertEqual(len(self.factory.miner_protocols), 1)
        _send_subscribe(protocol)
        self.assertEqual(len(self.factory.miner_protocols), 2)
        protocol.connectionLost()
        self.assertEqual(len(self.factory.miner_protocols), 1)

    def test_not_request_or_response(self):
        self.protocol.lineReceived(b'{"jsonrpc": "2.0", "foo": "bar"}')
        response = json_loads(self.transport.value())
        self.assertEqual(response['error'], INVALID_REQUEST)

    def test_invalid_method(self):
        self.protocol.lineReceived(b'{"id": "123", "jsonrpc": "2.0", "method": "test.invalid_method_x"}')
        data = self.transport.value().split(JSONRPC.delimiter)[-2]

        response = json_loads(data)
        self.assertEqual(response['error'], METHOD_NOT_FOUND)

    def test_subscribe(self):
        transport = StringTransportWithDisconnection()
        protocol = self.factory.buildProtocol('127.0.0.1')
        protocol.makeConnection(transport)
        id = uuid4()
        _send_subscribe(protocol, id)

        self.assertEqual(len(self.factory.miner_protocols), 2)
        data = transport.value().split(JSONRPC.delimiter)
        self.assertEqual(len(data), 3)

        response = json_loads(data[0])
        self.assertEqual(response['id'], str(id))
        self.assertEqual(response['result'], "ok")

        job = json_loads(data[1])
        self.assertEqual(job['method'], 'job')


class StratumJobTest(_BaseStratumTest):
    __test__ = True

    def _get_nonce(self, valid=True):
        target = 2**(256 - self.job['weight']) - 1
        base = sha256(bytes.fromhex(self.job['data']))
        nonce = 0
        while True:
            hash = base.copy()
            hash.update(nonce.to_bytes(Block.SERIALIZATION_NONCE_SIZE, 'big'))
            if (int(sha256(hash.digest()).digest()[::-1].hex(), 16) < target) == valid:
                return hex(nonce)
            nonce += 1

    def _submit(self, job_id: Optional[str], nonce: Optional[int]) -> None:
        self.protocol.lineReceived(
            json_dumps({
                "jsonrpc": "2.0",
                "id": "2a5438c5f64a4b5c992758d900a8b6b5",
                "method": "submit",
                "params": {
                    **({"job_id": job_id} if job_id is not None else {}),
                    **({"nonce": nonce} if nonce is not None else {}),
                }
            }))

    def test_job_not_found(self):
        # Certainly different from received job_id
        self._submit("41c49d8c977f4d65b8a3f568db7b4017", 0)
        self.assertEqual(self._get_latest_message()['error'], JOB_NOT_FOUND)

    def test_invalid_job(self):
        nonce = self._get_nonce(valid=False)
        self._submit(self.job['job_id'], nonce)
        self.assertEqual(self._get_latest_message()['error'], INVALID_SOLUTION)

        self._submit(None, nonce)
        self.assertEqual(self._get_latest_message()['error'], INVALID_PARAMS)

        self._submit(self.job['job_id'], None)
        self.assertEqual(self._get_latest_message()['error'], INVALID_PARAMS)

        self._submit('23123nidsdni2', nonce)
        self.assertEqual(self._get_latest_message()['error'], INVALID_PARAMS)

    def test_valid_solution(self):
        nonce = self._get_nonce()
        self._submit(self.job['job_id'], nonce)
        self.assertIn('result', self._get_latest_message())

    def test_force_propagation_failure(self):
        nonce = self._get_nonce()
        current_job = self.protocol.current_job
        self._submit(self.job['job_id'], nonce)
        self.protocol.current_job = current_job
        self._submit(self.job['job_id'], nonce)
        self.assertEqual(self._get_latest_message()['error'], STALE_JOB)

    def test_stale_solution(self):
        nonce = self._get_nonce()
        self._submit(self.job['job_id'], nonce)
        self.run_to_completion()
        self._submit(self.job['job_id'], nonce)
        self.assertEqual(self._get_latest_message()['error'], STALE_JOB)

    def test_min_share_weight(self):
        # submit a job
        nonce = self._get_nonce()
        self._submit(self.job['job_id'], nonce)
        msg = self._get_latest_message()
        self.assertIn('result', msg)

        # force server to have a very long time between jobs
        self.protocol.jobs[self.protocol.job_ids[0]].tx.timestamp = 0

        # get new job and check the weight
        job = self.protocol.create_job()
        self.assertTrue(job.weight >= 1, f'job weight of {job.weight} is too small')


class StratumClientTest(unittest.TestCase):
    def setUp(self):
        super().setUp()
        storage = self.create_tx_storage()
        self.block = storage.get_transaction(self._settings.GENESIS_BLOCK_HASH)
        self.transport = StringTransportWithDisconnection()
        self.protocol = StratumClient(reactor=self.clock)
        self.protocol.makeConnection(self.transport)
        self.job_request_params = {
            'data': self.block.get_mining_header_without_nonce().hex(),
            'job_id': 'a734d03fe4b64739be2894742f3de20f',
            'nonce_size': Block.SERIALIZATION_NONCE_SIZE,
            'weight': self.block.weight,
        }

    def tearDown(self):
        super().tearDown()
        self.protocol.stop()

    @pytest.mark.skip(reason='hangs on some systems')
    def test_n_core_mining(self):
        self.protocol.start(self.clock)
        self.protocol.handle_request('job', self.job_request_params, None)

        # Ignore subscribe request and empty line after line break
        requests = self.transport.value().split(JSONRPC.delimiter)[1:-1]
        while len(requests) < 1:
            sleep(1)
            self.clock.advance(1)
            requests = self.transport.value().split(JSONRPC.delimiter)[1:-1]

        submits = [json_loads(request) for request in requests]
        submits_params = [submit['params'] for submit in submits]

        methods = [submit['method'] for submit in submits]
        jobs_id = [params['job_id'] for params in submits_params]
        nonces = [params['nonce'] for params in submits_params]

        self.assertTrue(all(method == 'submit' for method in methods))
        self.assertTrue(all(job_id == self.job_request_params['job_id'] for job_id in jobs_id))
        for nonce in nonces:
            self.block.nonce = int(nonce, 16)
            self.block.update_hash()
            self.block.verify_pow()
