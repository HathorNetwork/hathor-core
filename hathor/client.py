# Copyright 2021 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

""" Module that contains a Python API for interacting with a portion of the HTTP/WS APIs
"""

import asyncio
import random
import string
from abc import ABC, abstractmethod
from typing import Any, AsyncIterator, Optional, Union
from urllib.parse import urljoin

from aiohttp import ClientSession, ClientWebSocketResponse
from multidict import MultiDict
from structlog import get_logger

from hathor.crypto.util import decode_address
from hathor.exception import HathorError
from hathor.manager import HathorManager
from hathor.mining import BlockTemplate, BlockTemplates
from hathor.pubsub import EventArguments, HathorEvents
from hathor.transaction import BaseTransaction, Block, TransactionMetadata
from hathor.transaction.storage import TransactionStorage

logger = get_logger()


class APIError(HathorError):
    pass


class JsonRpcError(HathorError):
    def __init__(self, code: int, message: Optional[str] = None, data: Optional[dict] = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(message if message is not None else str(code))


class IMiningChannel(AsyncIterator[BlockTemplates]):
    @abstractmethod
    async def submit(self, block: Block) -> Optional[BlockTemplate]:
        """Submit a mined block, when valid get a follow up template that uses the given block as parent."""
        raise NotImplementedError


class IHathorClient(ABC):
    """ Interface of a client that interacts with the Hathor fullnode API and exposes Python objects.
    """

    @abstractmethod
    async def version(self) -> tuple[int, int, int]:
        """Get the parsed version returned from `/v1a/version`, a tuple with (major, minor, patch)"""
        raise NotImplementedError

    @abstractmethod
    async def status(self) -> dict[str, Any]:
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

    @abstractmethod
    async def mining(self) -> IMiningChannel:
        """Channel to receive a stream of block templates and submit blocks using `/v1a/mining_ws`"""
        raise NotImplementedError


REQUIRED_HATHOR_API_VERSION = 'v1a'


class HathorClient(IHathorClient):
    """ Implementation of IHathorClient. Uses the HTTP API, defaults to the latest known API version known to work.
    """

    USER_AGENT = 'hathor-merged-mining'

    def __init__(self, server_url: str, api_version: str = REQUIRED_HATHOR_API_VERSION) -> None:
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

    async def version(self) -> tuple[int, int, int]:
        async with self.session.get(self._get_url('version')) as resp:
            data = await resp.json()
            ver = data['version']
            major, minor, patch = ver.split('.')
            return (int(major), int(minor), int(patch))

    async def status(self) -> dict[str, Any]:
        async with self.session.get(self._get_url('status')) as resp:
            return await resp.json()

    async def get_block_template(self, address: Optional[str] = None, merged_mining: bool = False) -> Block:
        from hathor.transaction.resources.mining import Capabilities

        params: MultiDict[Any] = MultiDict()
        if address is not None:
            params.add('address', address)
        caps: set[Capabilities] = set()
        if merged_mining:
            caps.add(Capabilities.MERGED_MINING)
        if caps:
            for cap in caps:
                params.add('capabilities', cap.value)

        async with self.session.get(self._get_url('get_block_template'), params=params) as resp:
            resp.raise_for_status()
            data = await resp.json()
            block = create_tx_from_dict(data)
            assert isinstance(block, Block)
            return block

    async def submit_block(self, block: Block) -> bool:
        from hathor.transaction.vertex_parser import vertex_serializer
        data = {
            'hexdata': vertex_serializer.serialize(block).hex(),
        }
        async with self.session.post(self._get_url('submit_block'), json=data) as resp:
            resp.raise_for_status()
            return (await resp.json())['result']

    async def mining(self) -> 'MiningChannel':
        ws = await self.session.ws_connect(self._get_url('mining_ws'))
        return MiningChannel(ws)


class MiningChannel(IMiningChannel):
    _ws: ClientWebSocketResponse
    _requests: dict[str, asyncio.Future]
    _queue: asyncio.Future
    _task: asyncio.Task

    def __init__(self, ws: ClientWebSocketResponse):
        self.loop = asyncio.get_event_loop()
        self.log = logger.new()
        self._ws = ws
        self._requests = {}
        self._queue = self.loop.create_future()
        self._task = self.loop.create_task(self.__task())

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return await self._queue
        finally:
            self._queue = self.loop.create_future()

    async def __task(self) -> None:
        async for msg in self._ws:
            try:
                data = msg.json()
            except Exception as e:
                self.log.error('invalid message', msg=msg, exc_info=True)
                if self._queue.done():
                    self._queue = self.loop.create_future()
                self._queue.set_exception(e)
                break
            if 'method' in data:
                self._handle_request(data)
            else:
                self._handle_response(data)

    def _handle_request(self, data: dict) -> None:
        # only request accepted is a 'mining.notify' notification
        if data['method'] != 'mining.notify':
            self.log.warn('unknown method received', data=data)
            return
        block_templates = BlockTemplates(BlockTemplate.from_dict(d) for d in data.get('params', []))
        if self._queue.done():
            self._queue = self.loop.create_future()
        self._queue.set_result(block_templates)

    def _handle_response(self, data: dict) -> None:
        _id = data.get('id')
        id: Optional[str] = str(_id) if _id else None
        error = data.get('error')
        result = data.get('result')
        if id is None:
            if not error:
                self.log.warn('result without id', data=data)
            else:
                self.log.warn('error response', error=error)
            return
        request = self._requests.get(id)
        if not request:
            self.log.warn('invalid response id', data=data)
            return
        if request.done():
            self.log.warn('duplicate response', data=data)
            return
        if error:
            if result:
                self.log.warn('both error and result set', data=data)
            request.set_exception(JsonRpcError(**error))
        else:
            request.set_result(result)

    async def close(self) -> None:
        self._task.cancel()
        self._queue.cancel()
        await self._task
        await self._ws.close()

    async def submit(self, block: Block) -> Optional[BlockTemplate]:
        from hathor.transaction.vertex_parser import vertex_serializer
        resp: Union[bool, dict] = await self._do_request('mining.submit', {
            'hexdata': vertex_serializer.serialize(block).hex(),
        })
        if isinstance(resp, dict):
            error = resp.get('error')
            if error:
                raise APIError(error)
            return BlockTemplate.from_dict(resp['result'])
        return None

    async def _do_request(self, method: str, params: Union[dict, list]) -> Any:
        while True:
            id = ''.join(random.choices(string.printable, k=10))
            if id not in self._requests:
                break
        future = self._requests[id] = self.loop.create_future()
        await self._ws.send_json({
            'method': method,
            'params': params,
            'id': id,
        })
        try:
            resp = await future
        finally:
            del self._requests[id]
        return resp


class HathorClientStub(IHathorClient):
    """ Dummy implementation that directly uses a manager instead of the HTTP API. Useful for tests.
    """

    def __init__(self, manager: HathorManager):
        self.manager = manager

    async def version(self) -> tuple[int, int, int]:
        from hathor.version import __version__
        major, minor, patch = __version__.split('.')
        return (int(major), int(minor), int(patch))

    async def status(self) -> dict[str, Any]:
        return {}

    async def get_block_template(self, address: Optional[str] = None, merged_mining: bool = False) -> Block:
        baddress = decode_address(address) if address is not None else None
        return self.manager.generate_mining_block(address=baddress, merge_mined=merged_mining)

    async def submit_block(self, block: Block) -> bool:
        return self.manager.submit_block(block)

    async def mining(self) -> IMiningChannel:
        return MiningChannelStub(self.manager)


class MiningChannelStub(IMiningChannel):
    manager: HathorManager
    _queue: asyncio.Future

    def __init__(self, manager: HathorManager):
        self.manager = manager
        self._reset_queue()
        event = HathorEvents.NETWORK_NEW_TX_ACCEPTED
        self._on_new_tx(event, EventArguments())  # call once to get an initial value
        manager.pubsub.subscribe(event, self._on_new_tx)

    def __aiter__(self):
        return self

    async def __anext__(self):
        try:
            return await self._queue
        finally:
            self._reset_queue()

    def _reset_queue(self) -> None:
        # SPSC queue with no buffer, using asyncio.Future as bridge from pubsub callback
        loop = asyncio.get_event_loop()
        self._queue = loop.create_future()

    def _on_new_tx(self, key: HathorEvents, args: EventArguments) -> None:
        if self._queue.done():
            self._reset_queue()
        try:
            self._queue.set_result(self.manager.get_block_templates())
        except Exception as e:
            self._queue.set_exception(e)

    async def submit(self, block: Block) -> Optional[BlockTemplate]:
        if await self.submit(block):
            return self.manager.make_block_template(block.hash)
        else:
            return None


def create_tx_from_dict(data: dict[str, Any], update_hash: bool = False,
                        storage: Optional[TransactionStorage] = None) -> BaseTransaction:
    import base64

    from hathor.transaction.aux_pow import BitcoinAuxPow
    from hathor.transaction.base_transaction import TxInput, TxOutput, TxVersion

    hash_bytes = bytes.fromhex(data['hash']) if 'hash' in data else None
    if 'data' in data:
        data['data'] = base64.b64decode(data['data'])

    parents = []
    for parent in data['parents']:
        parents.append(bytes.fromhex(parent))
    data['parents'] = parents

    inputs = []
    for input_tx in data.get('inputs', []):
        tx_id = bytes.fromhex(input_tx['tx_id'])
        index = input_tx['index']
        input_data = base64.b64decode(input_tx['data'])
        inputs.append(TxInput(tx_id, index, input_data))
    if len(inputs) > 0:
        data['inputs'] = inputs
    else:
        data.pop('inputs', [])

    outputs = []
    for output in data['outputs']:
        value = output['value']
        script = base64.b64decode(output['script'])
        token_data = output['token_data']
        outputs.append(TxOutput(value, script, token_data))
    if len(outputs) > 0:
        data['outputs'] = outputs

    tokens = [bytes.fromhex(uid) for uid in data['tokens']]
    if len(tokens) > 0:
        data['tokens'] = tokens
    else:
        del data['tokens']

    if 'aux_pow' in data:
        data['aux_pow'] = BitcoinAuxPow.from_bytes(bytes.fromhex(data['aux_pow']))

    if storage:
        data['storage'] = storage

    cls = TxVersion(data['version']).get_cls()
    metadata = data.pop('metadata', None)
    tx = cls(**data)
    if update_hash:
        tx.update_hash()
    if hash_bytes:
        assert tx.hash == hash_bytes, f'Hashes differ: {tx.hash!r} != {hash_bytes!r}'
    if metadata:
        tx._metadata = TransactionMetadata.create_from_json(metadata)
        if tx._metadata.hash and hash_bytes:
            assert tx._metadata.hash == hash_bytes
    return tx
