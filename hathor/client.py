from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Set, Tuple
from urllib.parse import urljoin

from aiohttp import ClientSession
from multidict import MultiDict

from hathor.crypto.util import decode_address
from hathor.transaction import BaseTransaction, Block, TransactionMetadata
from hathor.transaction.storage import TransactionStorage


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
            block = create_tx_from_dict(data)
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


def create_tx_from_dict(data: Dict[str, Any], update_hash: bool = False,
                        storage: Optional[TransactionStorage] = None) -> BaseTransaction:
    import base64

    from hathor.transaction.aux_pow import BitcoinAuxPow
    from hathor.transaction.base_transaction import TxOutput, TxInput, TxVersion

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
        assert tx.hash is not None
    if hash_bytes:
        assert tx.hash == hash_bytes, f'Hashes differ: {tx.hash!r} != {hash_bytes!r}'
    if metadata:
        tx._metadata = TransactionMetadata.create_from_json(metadata)
        if tx._metadata.hash and hash_bytes:
            assert tx._metadata.hash == hash_bytes
    return tx
