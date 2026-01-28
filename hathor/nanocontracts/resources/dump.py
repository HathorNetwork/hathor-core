# Copyright 2026 Hathor Labs
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

import gzip
import io
from typing import TYPE_CHECKING, Any, Optional

from twisted.internet.defer import ensureDeferred
from twisted.web.server import NOT_DONE_YET

from hathor._openapi.register import register_resource
from hathor.api_util import Resource, set_cors
from hathor.nanocontracts.nc_dump.local_nc_dumper import LocalNCDumper
from hathor.nanocontracts.nc_dump.nc_dumper import DumpMode, DumpUntilBlock, DumpUntilComplete, DumpUntilHeight
from hathor.transaction.storage import TransactionRocksDBStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.utils.api import ErrorResponse, QueryParams

if TYPE_CHECKING:
    from twisted.web.http import Request

    from hathor.manager import HathorManager


@register_resource
class NanoContractDumpResource(Resource):
    """Implements a web server GET API to dump nano contract storage."""
    isLeaf = True

    def __init__(self, manager: 'HathorManager') -> None:
        super().__init__()
        self.manager = manager

    def render_GET(self, request: 'Request') -> int | bytes:
        set_cors(request, 'GET')
        request.setHeader(b'content-type', b'application/json; charset=utf-8')

        params = NCDumpParams.from_request(request)
        if isinstance(params, ErrorResponse):
            request.setResponseCode(400)
            return params.json_dumpb()

        if params.until_block is not None and params.until_height is not None:
            request.setResponseCode(400)
            error_response = ErrorResponse(
                success=False,
                error='Parameters until_block and until_height cannot be used together.'
            )
            return error_response.json_dumpb()

        tx_storage = self.manager.tx_storage
        assert isinstance(tx_storage, TransactionRocksDBStorage)

        start_block: bytes | None = None
        if params.start_block:
            try:
                start_block = bytes.fromhex(params.start_block)
            except ValueError:
                request.setResponseCode(400)
                error_response = ErrorResponse(
                    success=False, error=f'Invalid start_block hash: {params.start_block}'
                )
                return error_response.json_dumpb()

            try:
                tx_storage.get_block(start_block)
            except TransactionDoesNotExist:
                request.setResponseCode(404)
                error_response = ErrorResponse(
                    success=False, error=f'Start block not found: {params.start_block}'
                )
                return error_response.json_dumpb()

        dump_mode: DumpMode
        if params.until_block:
            try:
                block_hash = bytes.fromhex(params.until_block)
            except ValueError:
                request.setResponseCode(400)
                error_response = ErrorResponse(success=False, error=f'Invalid block hash: {params.until_block}')
                return error_response.json_dumpb()

            try:
                tx_storage.get_block(block_hash)
            except TransactionDoesNotExist:
                request.setResponseCode(404)
                error_response = ErrorResponse(success=False, error=f'Block not found: {params.until_block}')
                return error_response.json_dumpb()

            dump_mode = DumpUntilBlock(block_hash)
        elif params.until_height is not None:
            best_block = tx_storage.get_best_block()
            if params.until_height > best_block.get_height():
                request.setResponseCode(400)
                error_response = ErrorResponse(
                    success=False,
                    error=f'Height {params.until_height} exceeds best block height {best_block.get_height()}'
                )
                return error_response.json_dumpb()
            dump_mode = DumpUntilHeight(params.until_height)
        else:
            dump_mode = DumpUntilComplete()

        buffer = io.StringIO()
        dumper = LocalNCDumper(
            settings=self.manager._settings,
            tx_storage=tx_storage,
            start_block=start_block,
            out=buffer,
            mode=dump_mode,
        )
        d = ensureDeferred(dumper.dump())

        def ok(_: Any) -> None:
            text_content = buffer.getvalue()
            compressed = gzip.compress(text_content.encode('utf-8'))
            request.setResponseCode(200)
            request.setHeader(b'content-type', b'application/gzip')
            request.setHeader(b'content-disposition', b'attachment; filename="nc_dump.txt.gz"')
            request.write(compressed)
            request.finish()

        def err(_: Any) -> None:
            request.setResponseCode(500)
            request.finish()

        d.addCallbacks(ok, err)
        return NOT_DONE_YET


class NCDumpParams(QueryParams):
    start_block: Optional[str] = None
    until_block: Optional[str] = None
    until_height: Optional[int] = None


NanoContractDumpResource.openapi = {
    '/nano_contract/dump': {
        'x-visibility': 'private',
        'get': {
            'tags': ['nano_contracts'],
            'operationId': 'nano_contracts_dump',
            'summary': 'Dump nano contract storage',
            'description': 'Returns a gzip-compressed dump of the nano contract storage. '
                           'This is a potentially long-running operation.',
            'parameters': [
                {
                    'name': 'start_block',
                    'in': 'query',
                    'description': 'Start at specific block hash (hex). Defaults to best block.',
                    'required': False,
                    'schema': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'until_block',
                    'in': 'query',
                    'description': 'Stop at specific block hash (hex). Cannot be used with until_height.',
                    'required': False,
                    'schema': {
                        'type': 'string'
                    }
                },
                {
                    'name': 'until_height',
                    'in': 'query',
                    'description': 'Stop at specific block height. Cannot be used with until_block.',
                    'required': False,
                    'schema': {
                        'type': 'integer'
                    }
                },
            ],
            'responses': {
                '200': {
                    'description': 'Success - returns gzip-compressed dump file',
                    'content': {
                        'application/gzip': {
                            'schema': {
                                'type': 'string',
                                'format': 'binary'
                            }
                        }
                    }
                },
                '400': {
                    'description': 'Bad request',
                    'content': {
                        'application/json': {
                            'examples': {
                                'invalid_params': {
                                    'summary': 'Invalid parameters',
                                    'value': {
                                        'success': False,
                                        'error': 'Parameters until_block and until_height cannot be used together.'
                                    }
                                },
                                'invalid_start_block': {
                                    'summary': 'Invalid start_block hash',
                                    'value': {
                                        'success': False,
                                        'error': 'Invalid start_block hash: xxx'
                                    }
                                },
                                'invalid_block': {
                                    'summary': 'Invalid block hash',
                                    'value': {
                                        'success': False,
                                        'error': 'Invalid block hash: xxx'
                                    }
                                }
                            }
                        }
                    }
                },
                '404': {
                    'description': 'Block not found',
                    'content': {
                        'application/json': {
                            'examples': {
                                'start_block_not_found': {
                                    'summary': 'Start block not found',
                                    'value': {
                                        'success': False,
                                        'error': 'Start block not found: abc123...'
                                    }
                                },
                                'block_not_found': {
                                    'summary': 'Block not found',
                                    'value': {
                                        'success': False,
                                        'error': 'Block not found: abc123...'
                                    }
                                }
                            }
                        }
                    }
                },
            }
        }
    }
}
