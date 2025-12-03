from twisted.internet.defer import succeed
from twisted.web import server
from twisted.web.test.requesthelper import DummyRequest

from hathor.daa import TestMode
from hathor.util import json_dumpb, json_loadb
from hathor_tests import unittest


class _BaseResourceTest:
    class _ResourceTest(unittest.TestCase):
        def setUp(self, *, utxo_index: bool = False, unlock_wallet: bool = True) -> None:
            super().setUp()
            self.reactor = self.clock
            self.manager = self.create_peer(
                'testnet',
                wallet_index=True,
                utxo_index=utxo_index,
                unlock_wallet=unlock_wallet
            )
            self.manager.allow_mining_without_peers()
            self.manager.daa.TEST_MODE = TestMode.TEST_ALL_WEIGHT

        def tearDown(self):
            return self.manager.stop()


class RequestBody(object):
    """
    Dummy request body object to represent content
    """

    def __init__(self):
        self.content = None

    def setvalue(self, value):
        self.content = value

    def read(self):
        return self.content


class TestDummyRequest(DummyRequest):
    __test__ = False

    def __init__(self, method, url, args=None, headers=None):
        slash = b'/' if isinstance(url, bytes) else '/'
        path = url.split(slash)
        DummyRequest.__init__(self, path)
        self.method = method
        self.headers = headers or {}
        self.content = RequestBody()

        # Set request args
        args = args or {}
        if isinstance(args, dict):
            for k, v in args.items():
                self.addArg(k, v)
        elif isinstance(args, list):
            for k, v in args:
                if k not in self.args:
                    self.args[k] = [v]
                else:
                    self.args[k].append(v)
        else:
            raise TypeError(f'unsupported type {type(args)} for args')

    def json_value(self):
        return json_loadb(self.written[0])


class StubSite(server.Site):
    def get(self, url, args=None, headers=None):
        return self._request('GET', url, None, args, headers)

    def post(self, url, body=None, args=None, headers=None):
        return self._request('POST', url, body, args, headers)

    def put(self, url, body=None, args=None, headers=None):
        return self._request('PUT', url, body, args, headers)

    def delete(self, url, body=None, args=None, headers=None):
        return self._request('DELETE', url, body, args, headers)

    def options(self, url, args=None, headers=None):
        return self._request('OPTIONS', url, None, args, headers)

    def _request(self, method, url, body, args, headers):
        request = TestDummyRequest(method, url, args, headers)
        # body content
        if (method == 'POST' or method == 'PUT' or method == 'DELETE') and body:
            # Creating post content exactly the same as twisted resource
            request.content.setvalue(json_dumpb(body))

        resource = self.getResourceFor(request)
        result = resource.render(request)
        return self._resolveResult(request, result)

    def _resolveResult(self, request, result):
        if isinstance(result, bytes):
            request.write(result)
            request.finish()
            return succeed(request)
        elif result == server.NOT_DONE_YET:
            if request.finished:
                return succeed(request)
            else:
                deferred = request.notifyFinish().addCallback(lambda _: request)
                deferred.request = request
                return deferred
        else:
            raise ValueError('Unexpected return value: %r' % (result,))
