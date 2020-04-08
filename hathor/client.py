from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Set, Tuple
from urllib.parse import urljoin

from aiohttp import ClientSession
from multidict import MultiDict

from hathor.crypto.util import decode_address
from hathor.transaction import Block


class IHathorClient(ABC):
    """ Interface of a client that interacts with the Hathor fullnode API and exposes Python objects.
    """

    @abstractmethod
    async def version(self) -> Tuple[int, int, int]:
        """Get the parsed version returned from `/v1a/version`, a tuple with (major, minor, patch)"""
        raise NotImplementedError

    @abstractmethod
    async def status(self) -> Dict[str, Any]:
        """Get the parsed dict returned from `/v1a/status`, format described in `hathor.p2p.resources.status`"""
        raise NotImplementedError

    @abstractmethod
    async def get_block_template(self, address: Optional[str] = None, merged_mining: bool = False) -> Block:
        """Request a block template for mining"""
        raise NotImplementedError

    @abstractmethod
    async def submit_block(self, block: Block) -> bool:
        """Submit a freshly mined block to the network"""
        raise NotImplementedError


REQUIRED_HATHOR_API_VERSION = 'v1a'


class HathorClient(IHathorClient):
    """ Implementation of IHathorClient. Uses the HTTP API, defaults to the latest known API version known to work.
    """

    USER_AGENT = 'hathor-merged-mining'

    def __init__(self, server_url, api_version=REQUIRED_HATHOR_API_VERSION):
        server_url = server_url.rstrip('/') + '/'
        if not (server_url.startswith('http://') or server_url.startswith('https://')):
            server_url = 'http://' + server_url
        self._base_url = urljoin(server_url, api_version).rstrip('/') + '/'
        self._base_headers = {
            'User-Agent': self.USER_AGENT,
        }
        self._session: Optional[ClientSession] = None

    @property
    def session(self) -> ClientSession:
        assert self._session is not None, 'Please call client.start() before using HathorClient'
        return self._session

    async def start(self) -> None:
        assert self._session is None
        # TODO: consider using https://pypi.org/project/ujson/ ujson.dumps for json_serialize
        self._session = ClientSession(headers=self._base_headers)

    async def stop(self) -> None:
        assert self._session is not None
        session = self._session
        self._session = None
        await session.close()

    def _get_url(self, url: str) -> str:
        return urljoin(self._base_url, url.lstrip('/'))

    async def version(self) -> Tuple[int, int, int]:
        async with self.session.get(self._get_url('version')) as resp:
            data = await resp.json()
            ver = data['version']
            major, minor, patch = ver.split('.')
            return (int(major), int(minor), int(patch))

    async def status(self) -> Dict[str, Any]:
        async with self.session.get(self._get_url('status')) as resp:
            return await resp.json()

    async def get_block_template(self, address: Optional[str] = None, merged_mining: bool = False) -> Block:
        from hathor.transaction.resources.mining import Capabilities
        from hathor.transaction.base_transaction import BaseTransaction

        params: MultiDict[Any] = MultiDict()
        if address is not None:
            params.add('address', address)
        caps: Set[Capabilities] = set()
        if merged_mining:
            caps.add(Capabilities.MERGED_MINING)
        if caps:
            for cap in caps:
                params.add('capabilities', cap.value)

        async with self.session.get(self._get_url('get_block_template'), params=params) as resp:
            data = await resp.json()
            block = BaseTransaction.create_from_dict(data)
            assert isinstance(block, Block)
            return block

    async def submit_block(self, block: Block) -> bool:
        data = {
            'hexdata': bytes(block).hex(),
        }
        async with self.session.post(self._get_url('submit_block'), json=data) as resp:
            return (await resp.json())['result']


class HathorClientStub(IHathorClient):
    """ Dummy implementation that directly uses a manager instead of the HTTP API. Useful for tests.
    """

    def __init__(self, manager):
        self.manager = manager

    async def version(self) -> Tuple[int, int, int]:
        from hathor.version import __version__
        major, minor, patch = __version__.split('.')
        return (int(major), int(minor), int(patch))

    async def status(self) -> Dict[str, Any]:
        return {}

    async def get_block_template(self, address: Optional[str] = None, merged_mining: bool = False) -> Block:
        baddress = address and decode_address(address)
        return self.manager.generate_mining_block(address=baddress, merge_mined=merged_mining)

    async def submit_block(self, block: Block) -> bool:
        return self.manager.propagate_tx(block)
