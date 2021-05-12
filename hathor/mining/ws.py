# Copyright 2019 Hathor Labs
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

"""
Module for mining websocket API discussed at https://github.com/HathorNetwork/hathor-core/issues/91
"""

from json import JSONDecodeError
from typing import Any, Dict, List, NamedTuple, Optional, Set, Union

from autobahn.twisted.websocket import WebSocketServerFactory, WebSocketServerProtocol
from structlog import get_logger

from hathor.conf import HathorSettings
from hathor.manager import HathorManager
from hathor.pubsub import EventArguments, HathorEvents
from hathor.transaction.base_transaction import tx_or_block_from_bytes
from hathor.util import json_dumpb, json_loadb

logger = get_logger()
settings = HathorSettings()

JsonRpcId = Union[str, int, float]
JsonValue = Optional[Union[Dict[str, Any], List[Any], str, int, float]]


class JsonRpcError(NamedTuple):
    code: int
    message: str
    data: Optional[JsonValue] = None
    fatal: bool = False

    def to_dict(self) -> JsonValue:
        error = {
            'code': self.code,
            'message': self.message,
        }
        if self.data:
            error['data'] = self.data
        return error


JSON_RPC_PARSE_ERROR = JsonRpcError(-32700, 'Parse error', fatal=True)
JSON_RPC_INVALID_REQUEST = JsonRpcError(-32600, 'Invalid Request', fatal=True)
JSON_RPC_METHOD_NOT_FOUND = JsonRpcError(-32601, 'Method not found')
JSON_RPC_INVALID_PARAMS = JsonRpcError(-32602, 'Invalid params')
JSON_RPC_INTERNAL_ERROR = JsonRpcError(-32603, 'Internal error', fatal=True)


class JsonRpcWebsocketServerProtocol(WebSocketServerProtocol):
    """Small JSONRPC 2.0 abstraction over WebSocket, will forward method calls to do_<method>"""

    def onMessage(self, payload: bytes, isBinary: bool) -> None:
        self.log.info('message', payload=payload)
        try:
            data: Union[List[Dict], Dict] = json_loadb(payload)
        except JSONDecodeError:
            return self.send_response(error=JSON_RPC_PARSE_ERROR)
        try:
            if isinstance(data, list):
                for batch_data in data:
                    self._handle_request(batch_data)
            else:
                self._handle_request(data)
        except Exception:
            self.log.warn('internal error', exc_info=True)
            return self.send_response(error=JSON_RPC_INTERNAL_ERROR)

    def _handle_request(self, data: Dict) -> None:
        try:
            id = data.get('id')
            method_name = data['method'].replace('.', '_')
            params: Union[Dict[str, Any], List[Any]] = data.get('params', [])
        except (KeyError, ValueError):
            return self.send_response(error=JSON_RPC_INVALID_REQUEST)
        try:
            method = getattr(self, 'do_' + method_name)
        except AttributeError:
            return self.send_response(error=JSON_RPC_METHOD_NOT_FOUND)
        try:
            # TODO: could be made async, right now no method needs it
            # TODO: could be changed into a design that allows for no response from a call
            if isinstance(params, list):
                result = method(*params)
            elif isinstance(params, dict):
                result = method(**params)
            else:
                raise TypeError('params has to be list, dict or null')
        except TypeError:
            return self.send_response(error=JSON_RPC_INVALID_PARAMS)
        # XXX: don't respond to notifications
        if id is not None:
            self.send_response(result=result, id=id)

    def send_response(self, *,
                      id: Optional[JsonRpcId] = None,
                      result: Optional[JsonValue] = None,
                      error: Optional[JsonRpcError] = None) -> None:
        response: Dict[str, JsonValue] = {
            'id': id,
            'error': None,
            'result': None,
        }
        if error is not None:
            assert result is None, 'Can\'t have both an error and a result'
            response['error'] = error.to_dict() if error is not None else None
        else:
            assert id is not None, '`id` is required for a success response'
            response['result'] = result
        self.sendMessage(json_dumpb(response))
        if error is not None and error.fatal:
            self.sendClose()

    def send_notification(self, *, method: str, params: Union[List, Dict]) -> None:
        request: Dict[str, JsonValue] = {
            'id': None,
            'method': method,
        }
        if params:
            request['params'] = params
        self.sendMessage(json_dumpb(request))


class MiningWebsocketProtocol(JsonRpcWebsocketServerProtocol):
    def __init__(self, factory):
        super().__init__()
        self._open = False
        self.log = logger.new()
        self.factory = factory

    def onConnect(self, request):
        self.log.info('connect', request=request)

    def onOpen(self) -> None:
        self.log.info('open')
        if self.factory.manager.can_start_mining():
            self.send_notification(method='mining.notify', params=self.do_mining_refresh())
        self.factory.connections.add(self)
        self._open = True

    def onClose(self, wasClean, code, reason):
        self.log.info('close', reason=reason)
        if self._open:
            self.factory.connections.remove(self)
            self._open = False

    def do_mining_refresh(self) -> List[Dict]:
        if not self.factory.manager.can_start_mining():
            self.log.warn('node syncing')
            return []
        return self.factory.get_block_templates()

    def do_mining_submit(self, hexdata: str, optimistic: bool = False) -> Union[bool, Dict]:
        if not self.factory.manager.can_start_mining():
            self.log.warn('node syncing')
            return False
        tx = tx_or_block_from_bytes(bytes.fromhex(hexdata), storage=self.factory.manager.tx_storage)
        if not tx.is_block:
            self.log.warn('expected Block, received Transaction', data=hexdata)
            return False
        res = self.factory.manager.submit_block(tx)
        if res and optimistic:
            return self.manager.make_block_template(tx.hash).to_dict()
        return res


class MiningWebsocketFactory(WebSocketServerFactory):
    """ Factory of the admin websocket protocol so we can subscribe to events and
        send messages in the Admin page to clients when the events are published
    """
    protocol = MiningWebsocketProtocol

    connections: Set[MiningWebsocketProtocol]

    def __init__(self, manager: HathorManager):
        super().__init__()
        self.connections = set()
        self.manager = manager
        self._last_broadcast: List[Dict] = []
        manager.pubsub.subscribe(HathorEvents.NETWORK_NEW_TX_ACCEPTED, self._on_new_tx)

    def buildProtocol(self, addr):
        return self.protocol(self)

    def _on_new_tx(self, key: HathorEvents, _args: EventArguments) -> None:
        """ Called when a new tx/block is received.
        """
        if self.manager.can_start_mining():
            block_templates = self.get_block_templates()
            if block_templates != self._last_broadcast:
                self.broadcast_notification(method='mining.notify', params=block_templates)
                self._last_broadcast = block_templates

    def get_block_templates(self) -> List[Dict]:
        """Serialized manager.get_block_templates()"""
        block_templates = self.manager.get_block_templates()
        return [t.to_dict() for t in block_templates]

    def broadcast_notification(self, *, method: str, params: Union[List, Dict]) -> None:
        """ Broadcast notification to all connections
        """
        for conn in self.connections:
            try:
                conn.send_notification(method=method, params=params)
            # XXX: unfortunately autobahn can raise 3 different exceptions and one of them is a bare Exception
            # https://github.com/crossbario/autobahn-python/blob/v20.12.3/autobahn/websocket/protocol.py#L2201-L2294
            except Exception:
                self.log.error('send failed, moving on', exc_info=True)
