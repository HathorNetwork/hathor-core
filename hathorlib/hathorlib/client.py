# Copyright (c) Hathor Labs and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.
import json
import re
from typing import Any, Dict, List, NamedTuple, Optional, cast
from urllib.parse import urljoin

from hathorlib.base_transaction import tx_or_block_from_bytes
from hathorlib.exceptions import PushTxFailed

try:
    from aiohttp import ClientSession
    from structlog import get_logger
except ImportError as e:
    raise ImportError('Missing dependency, please install extras: hathorlib[client]') from e

from hathorlib import Block, TxOutput

REQUIRED_HATHOR_API_VERSION = 'v1a'

logger = get_logger()


# This regex was copied from https://semver.org/#is-there-a-suggested-regular-expression-regex-to-check-a-semver-string
semver_pattern = (
    r"(?P<major>0|[1-9]\d*)\.(?P<minor>0|[1-9]\d*)\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<prerelease>(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+(?P<metadata>[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?"
)
semver_re = re.compile(semver_pattern)


class BlockTemplate(NamedTuple):
    """Block template."""

    data: bytes
    height: int

    def to_dict(self) -> Dict[str, Any]:
        """Return dict for json serialization."""
        return {
            'data': self.data.hex(),
            'height': self.height,
        }


class HathorVersion(NamedTuple):
    """Hathor backend version."""

    major: int
    minor: int
    patch: int
    prerelease: Optional[str] = None
    metadata: Optional[str] = None


class HathorClient:
    """Used to communicate with Hathor's full-node."""

    USER_AGENT = 'tx-mining-service'

    def __init__(self, server_url: str, api_version: str = REQUIRED_HATHOR_API_VERSION):
        """Init HathorClient with a Hathor's full-node backend."""
        self.log = logger.new()
        self._base_url = urljoin(server_url, api_version).rstrip('/') + '/'
        self._base_headers = {
            'User-Agent': self.USER_AGENT,
        }
        self._session: Optional[ClientSession] = None

    async def start(self) -> None:
        """Start a session with the backend."""
        self._session = ClientSession(headers=self._base_headers)

    async def stop(self) -> None:
        """Stop a session with the backend."""
        if self._session is not None:
            await self._session.close()
            self._session = None

    def _get_url(self, url: str) -> str:
        return urljoin(self._base_url, url.lstrip('/'))

    async def version(self) -> HathorVersion:
        """Return the version of the backend."""
        assert self._session is not None

        async with self._session.get(self._get_url('version')) as resp:
            data = await resp.json()
            version = data['version']

            match = semver_re.match(version)

            if match:
                result = match.groupdict()

                return HathorVersion(
                    major=int(result['major']),
                    minor=int(result['minor']),
                    patch=int(result['patch']),
                    prerelease=result.get('prerelease'),
                    metadata=result.get('metadata'),
                )
            else:
                raise RuntimeError(f'Cannot parse version {version}')

    async def health(self) -> Dict[str, Any]:
        """Return the health information of the backend."""
        assert self._session is not None

        async with self._session.get(self._get_url('health')) as resp:
            data = await resp.text()
            try:
                parsed_json: Dict[str, Any] = json.loads(data)
            except json.JSONDecodeError:
                raise RuntimeError('Cannot parse health response: {}'.format(data))
            return parsed_json

    async def get_block_template(self, address: Optional[str] = None) -> BlockTemplate:
        """Return a block template."""
        assert self._session is not None
        params = {}
        if address is not None:
            params['address'] = address
        resp = await self._session.get(self._get_url('get_block_template'), params=params)
        if resp.status != 200:
            self.log.error('Error getting block template', status=resp.status)
            raise RuntimeError('Cannot get block template (status {})'.format(resp.status))

        data = await resp.json()

        if data.get('error'):
            self.log.error('Error getting block template', data=data)
            raise RuntimeError('Cannot get block template')

        # Get height.
        metadata = data.get('metadata', {})
        height = metadata['height']

        # Build block.
        blk = Block()
        blk.signal_bits = data['signal_bits']
        blk.version = 0
        blk.timestamp = data['timestamp']
        blk.weight = data['weight']
        blk.parents = [bytes.fromhex(x) for x in data['parents']]
        blk.data = b''

        do = data['outputs'][0]
        txout = TxOutput(
            value=do['value'],
            token_data=0,
            script=b'',
        )
        blk.outputs = [txout]
        return BlockTemplate(data=bytes(blk), height=height)

    async def get_tx_parents(self) -> List[bytes]:
        """Return parents for a new transaction."""
        assert self._session is not None
        async with self._session.get(self._get_url('tx_parents')) as resp:
            data = await resp.json()
            if not data.get('success'):
                raise RuntimeError('Cannot get tx parents')
            return [bytes.fromhex(x) for x in data['tx_parents']]

    async def push_tx_or_block(self, raw: bytes) -> bool:
        """Push a new tx or block to the backend."""
        assert self._session is not None

        tx = tx_or_block_from_bytes(raw)

        if tx.is_block:
            data = {'hexdata': raw.hex()}
            resp = await self._session.post(self._get_url('submit_block'), json=data)
        else:
            data = {'hex_tx': raw.hex()}
            resp = await self._session.post(self._get_url('push_tx'), json=data)

        status = resp.status
        if status > 299:
            response = await resp.text()
            self.log.error('Error pushing tx or block', response=response, status=status)
            raise PushTxFailed('Cannot push tx or block')

        json = await resp.json()

        return cast(bool, json['result'])
