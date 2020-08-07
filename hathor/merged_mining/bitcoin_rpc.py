from abc import ABC, abstractmethod
from itertools import count
from typing import Any, Callable, Dict, Iterator, List, Optional, Union, cast

from aiohttp import BasicAuth, ClientSession
from structlog import get_logger

logger = get_logger()


class RPCFailure(Exception):
    def __init__(self, message: str, code: Optional[int] = None):
        super().__init__(message)
        self.code = code


class IBitcoinRPC(ABC):
    @abstractmethod
    async def get_block_template(self, *, rules: List[str] = ['segwit'],
                                 capabilities: List[str] = ['coinbasetxn', 'workid', 'coinbase/append'],
                                 ) -> Dict[Any, Any]:
        """ Method for the [GetBlockTemplate call](https://developer.bitcoin.org/reference/rpc/getblocktemplate.html).
        """
        raise NotImplementedError

    @abstractmethod
    async def verify_block_proposal(self, *, block: bytes) -> Optional[str]:
        """ Method for the [GetBlockTemplate call](https://developer.bitcoin.org/reference/rpc/getblocktemplate.html).
        """
        raise NotImplementedError

    @abstractmethod
    async def submit_block(self, block: bytes) -> Optional[str]:
        """ Method for the [SubmitBlock call](https://developer.bitcoin.org/reference/rpc/submitblock.html).
        """
        raise NotImplementedError


class BitcoinRPC(IBitcoinRPC):
    """ Class for making calls to Bitcoin's RPC.

    References:

    - https://bitcoin.org/en/developer-reference#remote-procedure-calls-rpcs
    """

    USER_AGENT = 'hathor-merged-mining'

    def __init__(self, endpoint_url: str,
                 id_generator: Optional[Callable[[], Iterator[Union[str, int]]]] = lambda: count()):
        """ Create a client for the Bitcoin RPC API.

        Arguments:

        - endpoint_url: example: 'http://user:password@host:port/'
        - id_generator: function/lambda that when called returns an iterator of ids, note: iterator must never stop
        """
        from urllib.parse import urlparse

        self.log = logger.new()
        url = urlparse(endpoint_url)
        self._url = f'{url.scheme or "http"}://{url.hostname}:{url.port or 8332}{url.path or "/"}'
        self._base_headers = {
            'User-Agent': self.USER_AGENT,
        }
        auth = ':'.join([url.username or '', url.password or '']) if url.username or url.password else None
        self._auth: Optional[BasicAuth]
        if auth:
            login, password = auth.split(':')
            self._auth = BasicAuth(login, password)
        else:
            self._auth = None
        self._iter_id = id_generator and id_generator() or None
        self._session: Optional[ClientSession] = None

    @property
    def session(self) -> ClientSession:
        assert self._session is not None, 'Please call client.start() before using HathorClient'
        return self._session

    async def start(self) -> None:
        assert self._session is None
        self._session = ClientSession(auth=self._auth, headers=self._base_headers)

    async def stop(self) -> None:
        assert self._session is not None
        session = self._session
        self._session = None
        await session.close()

    async def _rpc_request(self, method: str, *args: Any, **kwargs: Any) -> Any:
        """ Make a call to Bitcoin's RPC. Do not use both args and kwargs, use at most one of them.

        Examples:
        - `bitcoin_rpc._rpc_request('getblocktemplate', {'capabilities': ['coinbasetxn']})`
          Sends the following JSON:
          `{"id": 0, "method": "getblocktemplate", "params": [{"capabilities": ["coinbasetxn"]}]}`
        - `bitcoin_rpc._rpc_request('getblocktemplate', template_request={'capabilities': ['coinbasetxn']})`
          Sends the following JSON:
          `{"id": 0, "method": "getblocktemplate", "params": {"template_request": {"capabilities": ["coinbasetxn"]}}}`
        """
        assert bool(args) + bool(kwargs) < 2, 'Use at most one of: args or kwargs, but not both'
        req_data: Dict = {'method': method}
        if self._iter_id:
            req_data['id'] = str(next(self._iter_id))
        params = args or kwargs or None
        if params:
            req_data['params'] = params
        headers = {
            'Content-Type': 'text/plain',
        }
        # self.log.debug('send request', data=req_data)
        async with self.session.post(self._url, json=req_data, headers=headers) as resp:
            self.log.debug('receive response', resp=resp)
            if resp.status != 200:
                raise RPCFailure(f'expected 200 OK got {resp.status} {resp.reason}')
            res_data = await resp.json(content_type=None)
            if not res_data:
                raise RPCFailure('empty response')
            if res_data['id'] != req_data['id']:
                raise RPCFailure('response id does not match request id')
            if res_data['error']:
                raise RPCFailure(res_data['error']['message'], res_data['error']['code'])
            return res_data['result']

    async def get_block_template(self, *, rules: List[str] = ['segwit'],
                                 capabilities: List[str] = ['coinbasetxn', 'workid', 'coinbase/append']) -> Dict:
        res = await self._rpc_request('getblocktemplate', {'capabilities': capabilities, 'rules': rules})
        return cast(Dict[Any, Any], res)

    async def verify_block_proposal(self, *, block: bytes) -> Optional[str]:
        res = await self._rpc_request('getblocktemplate', {'mode': 'proposal', 'data': block.hex()})
        return cast(Optional[str], res)

    async def submit_block(self, block: bytes) -> Optional[str]:
        res = await self._rpc_request('submitblock', block.hex())
        return cast(Optional[str], res)
