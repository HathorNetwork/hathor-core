from hashlib import sha256
from json import dumps as json_dumps, loads as json_loads
from time import sleep
from typing import Optional
from uuid import UUID

from twisted.test.proto_helpers import MemoryReactor, StringTransportWithDisconnection

from hathor.stratum import (
    INVALID_PARAMS,
    INVALID_REQUEST,
    INVALID_SOLUTION,
    JOB_NOT_FOUND,
    JSONRPC,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    PROPAGATION_FAILED,
    STALE_JOB,
    StratumClient,
    StratumFactory,
)
from hathor.transaction.block import Block
from hathor.transaction.genesis import genesis_transactions
from tests import unittest


class StratumTestBase(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.manager = self.create_peer('testnet')
        self.factory = StratumFactory(self.manager, port=8123, reactor=MemoryReactor())
        self.factory.start()
        self.protocol = self.factory.buildProtocol('127.0.0.1')
        self.transport = StringTransportWithDisconnection()
        self.transport.protocol = self.protocol
        self.protocol.makeConnection(self.transport)


class TestStratum(StratumTestBase):
    def test_parse_error(self):
        self.protocol.lineReceived(b'{]')
        response = json_loads(self.transport.value())
        assert response['error'] == PARSE_ERROR

    def test_invalid_json_rpc(self):
        self.protocol.lineReceived(b'{"jsonrpc": "x.y"}')
        response = json_loads(self.transport.value())
        assert response['error'] == INVALID_REQUEST

    def test_invalid_id_error(self):
        self.protocol.lineReceived(b'{"id": 123}')
        response = json_loads(self.transport.value())
        assert response['error'] == INVALID_REQUEST

    def test_send_rpc_error(self):
        miner_id = self.protocol.miner_id
        assert miner_id is not None and miner_id in self.factory.miner_protocols
        self.protocol.send_error(INVALID_REQUEST)
        assert miner_id not in self.factory.miner_protocols

    def test_result_and_error(self):
        self.protocol.lineReceived(b'{"jsonrpc": "2.0", "result": "OK", "error": {"code": 0, "message": "Fake"}}')
        response = json_loads(self.transport.value())
        assert response['error'] == INVALID_REQUEST

    def test_json_rpc(self):
        # Test sending request
        uuid = UUID('eadee1bd-5581-4f04-98c9-fbee30456ec4')
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
        assert len(self.factory.miner_protocols) == 2
        protocol.connectionLost()
        assert len(self.factory.miner_protocols) == 1

    def test_not_request_or_response(self):
        self.protocol.lineReceived(b'{"jsonrpc": "2.0", "foo": "bar"}')
        response = json_loads(self.transport.value())
        assert response['error'] == INVALID_REQUEST

    def test_invalid_method(self):
        self.protocol.lineReceived(b'{"jsonrpc": "2.0", "method": "test.invalid_method_x"}')
        data = self.transport.value().split(JSONRPC.delimiter)[-2]

        response = json_loads(data)
        assert response['error'] == METHOD_NOT_FOUND

    def test_subscribe(self):
        id = "52dce7e1c7b34143bdd80ead4814ef07"
        self.protocol.lineReceived('{{"jsonrpc": "2.0", "id": "{}", "method": "subscribe"}}'.format(id).encode())
        data = self.transport.value().split(JSONRPC.delimiter)
        assert len(data) == 3

        response = json_loads(data[0])
        assert response['id'] == id
        assert response['result'] == "ok"

        job = json_loads(data[1])
        assert job['method'] == 'job'


class TestStratumJob(StratumTestBase):
    def _get_latest_message(self):
        data = self.transport.value().split(JSONRPC.delimiter)[-2]
        return json_loads(data)

    def _get_nonce(self, valid=True):
        target = 2**(256 - self.job['weight']) - 1
        base = sha256(bytes.fromhex(self.job['data']))
        nonce = 0
        while True:
            hash = base.copy()
            hash.update(nonce.to_bytes(Block.NONCE_SIZE, 'big'))
            if (int(sha256(hash.digest()).digest()[::-1].hex(), 16) < target) == valid:
                return hex(nonce)
            nonce += 1

    def _submit(self, job_id: Optional[str], nonce: Optional[int]):
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

    def setUp(self):
        super().setUp()
        subscribe = b'{"jsonrpc": "2.0", "id": "52dce7e1c7b34143bdd80ead4814ef07", "method": "subscribe"}'
        self.protocol.lineReceived(subscribe)
        self.job = self._get_latest_message()['params']

    def test_job_not_found(self):
        # Certainly different from received job_id
        self._submit("41c49d8c977f4d65b8a3f568db7b4017", 0)
        assert self._get_latest_message()['error'] == JOB_NOT_FOUND

    def test_invalid_job(self):
        nonce = self._get_nonce(valid=False)
        self._submit(self.job['job_id'], nonce)
        assert self._get_latest_message()['error'] == INVALID_SOLUTION

        self._submit(None, nonce)
        assert self._get_latest_message()['error'] == INVALID_PARAMS

        self._submit(self.job['job_id'], None)
        assert self._get_latest_message()['error'] == INVALID_PARAMS

        self._submit('23123nidsdni2', nonce)
        assert self._get_latest_message()['error'] == INVALID_PARAMS

    def test_valid_solution(self):
        nonce = self._get_nonce()
        self._submit(self.job['job_id'], nonce)
        assert 'result' in self._get_latest_message()

    def test_force_propagation_failure(self):
        nonce = self._get_nonce()
        current_job = self.protocol.current_job
        self._submit(self.job['job_id'], nonce)
        self.protocol.current_job = current_job
        self._submit(self.job['job_id'], nonce)
        assert self._get_latest_message()['error'] == PROPAGATION_FAILED

    def test_stale_solution(self):
        nonce = self._get_nonce()
        self._submit(self.job['job_id'], nonce)
        self._submit(self.job['job_id'], nonce)
        assert self._get_latest_message()['error'] == STALE_JOB


class StratumClientTest(unittest.TestCase):

    def setUp(self):
        super().setUp()
        self.block = genesis_transactions(None)[0]
        self.transport = StringTransportWithDisconnection()
        self.protocol = StratumClient()
        self.protocol.makeConnection(self.transport)
        self.job_request_params = {
            'data': self.block.get_header_without_nonce().hex(),
            'job_id': 'a734d03fe4b64739be2894742f3de20f',
            'nonce_size': Block.NONCE_SIZE,
            'weight': self.block.weight,
        }

    def tearDown(self):
        super().tearDown()
        self.protocol.stop()

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

        assert all(method == 'submit' for method in methods)
        assert all(job_id == self.job_request_params['job_id'] for job_id in jobs_id)
        for nonce in nonces:
            self.block.nonce = int(nonce, 16)
            self.block.update_hash()
            self.block.verify_pow()
