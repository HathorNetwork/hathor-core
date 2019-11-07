import json
from abc import ABC, abstractmethod
from itertools import count
from typing import Any, Callable, Dict, Iterator, List, Optional, Union

from structlog import get_logger
from twisted.internet.defer import Deferred
from twisted.internet.interfaces import IReactorTCP
from twisted.python.failure import Failure
from twisted.web import client
from twisted.web.http_headers import Headers

from hathor.util import abbrev

logger = get_logger()


class RPCFailure(Failure):
    def __init__(self, message: str, code: Optional[int] = None):
        super().__init__(message)
        self.code = code


class QuietHTTP11ClientFactory(client._HTTP11ClientFactory):
    noisy = False


class IBitcoinRPC(ABC):
    @abstractmethod
    def get_block_template(self, *, rules: List[str] = ['segwit'],
                           capabilities: List[str] = ['coinbasetxn', 'workid', 'coinbase/append']) -> Deferred:
        """ Method for the [GetBlockTemplate call](https://bitcoin.org/en/developer-reference#getblocktemplate).
        """
        raise NotImplementedError

    @abstractmethod
    def submit_block(self, block: bytes) -> Deferred:
        """ Method for the [SubmitBlock call](https://bitcoin.org/en/developer-reference#submitblock).
        """
        raise NotImplementedError


class BitcoinRPC(client.Agent, IBitcoinRPC):
    """ Class for making calls to Bitcoin's RPC.

    References:

    - https://bitcoin.org/en/developer-reference#remote-procedure-calls-rpcs
    """

    USER_AGENT = 'hathor-merged-mining'

    def __init__(
            self,
            reactor: IReactorTCP,
            endpoint_url: str,
            id_generator: Optional[Callable[[], Iterator[Union[str, int]]]] = lambda: count(),
    ):
        """ Create a client for the Bitcoin RPC API.

        Arguments:

        - endpoint_url: example: 'http://user:password@host:port/'
        - id_generator: function/lambda that when called returns an iterator of ids, note: iterator must never stop
        """
        from base64 import b64encode
        from urllib.parse import urlparse

        self.log = logger.new()

        quietPool = client.HTTPConnectionPool(reactor)
        quietPool._factory = QuietHTTP11ClientFactory
        super().__init__(reactor, pool=quietPool)

        url = urlparse(endpoint_url)
        self._url = f'{url.scheme or "http"}://{url.hostname}:{url.port or 8332}{url.path or "/"}'.encode('ascii')
        self._base_headers = {
            'User-Agent': [self.USER_AGENT],
        }
        auth = ':'.join([url.username or '', url.password or '']) if url.username or url.password else None
        if auth:
            self._base_headers['Authorization'] = ['Basic ' + b64encode(auth.encode('ascii')).decode('ascii')]
        self._iter_id = id_generator and id_generator() or None

    def _rpc_request(self, method: str, *args: Any, **kwargs: Any) -> Deferred:
        """ Make a call to Bitcoin's RPC. Do not use both args and kwargs, use at most one of them.

        Examples:
        - `bitcoin_rpc._rpc_request('getblocktemplate', {'capabilities': ['coinbasetxn']})`
          Sends the following JSON:
          `{"id": 0, "method": "getblocktemplate", "params": [{"capabilities": ["coinbasetxn"]}]}`
        - `bitcoin_rpc._rpc_request('getblocktemplate', template_request={'capabilities': ['coinbasetxn']})`
          Sends the following JSON:
          `{"id": 0, "method": "getblocktemplate", "params": {"template_request": {"capabilities": ["coinbasetxn"]}}}`
        """
        from hathor.util import BytesProducer
        assert bool(args) + bool(kwargs) < 2, 'Use at most one of: args or kwargs, but not both'
        data: Dict = {'method': method}
        if self._iter_id:
            data['id'] = str(next(self._iter_id))
        params = args or kwargs or None
        if params:
            data['params'] = params
        body = json.dumps(data).encode('utf-8')
        d = self.request(b'POST', self._url, Headers(dict(self._base_headers, **{
            'Content-Type': ['text/plain'],
        })), BytesProducer(body))
        d.addCallback(client.readBody)
        d.addCallback(self._cb_rpc_request, request=data)
        self.log.debug('send request', body_short=abbrev(body))
        return d

    def _cb_rpc_request(self, response, request):
        """ Callback used for the async call on _rpc_request.
        """
        self.log.debug('receive response', body_short=abbrev(response))
        data = json.loads(response)
        if data['id'] != request['id']:
            return RPCFailure(Exception('response id does not match request id'))
        if data['error']:
            return RPCFailure(Exception(data['error']['message']), data['error']['code'])
        return data['result']

    def get_block_template(self, *, rules: List[str] = ['segwit'],
                           capabilities: List[str] = ['coinbasetxn', 'workid', 'coinbase/append']) -> Deferred:
        return self._rpc_request('getblocktemplate', {'capabilities': capabilities, 'rules': rules})

    def submit_block(self, block: bytes) -> Deferred:
        return self._rpc_request('submitblock', block.hex())
