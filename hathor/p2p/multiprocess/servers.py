#  Copyright 2024 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from concurrent import futures

import grpc

from hathor.p2p.manager import ConnectionsManager
from hathor.utils.grpc import twisted_grpc
from protos import p2p_pb2, p2p_pb2_grpc


class P2PManagerServicer(p2p_pb2_grpc.P2PManagerServicer):
    __slots__ = ('_p2p_manager',)

    def __init__(self, *, p2p_manager: ConnectionsManager) -> None:
        self._p2p_manager = p2p_manager

    def serve(self) -> None:
        server = grpc.server(futures.ThreadPoolExecutor())
        p2p_pb2_grpc.add_P2PManagerServicer_to_server(self, server)
        server.add_insecure_port('localhost:50051')
        server.start()

    @twisted_grpc
    def IsPeerWhitelisted(self, request, context):
        raise NotImplementedError('Method not implemented!')

    @twisted_grpc
    def GetEnabledSyncVersions(self, request, context):
        versions = self._p2p_manager.get_enabled_sync_versions()
        return p2p_pb2.StringList(values=[version.value for version in versions])

    @twisted_grpc
    def GetVerifiedPeers(self, request, context):
        raise NotImplementedError('Method not implemented!')

    @twisted_grpc
    def OnReceivePeer(self, request, context):
        raise NotImplementedError('Method not implemented!')

    @twisted_grpc
    def OnPeerConnect(self, request: p2p_pb2.StringValue, context):
        self._p2p_manager.on_peer_connect(request.value)
        return p2p_pb2.Empty()

    @twisted_grpc
    def OnPeerReady(self, request: p2p_pb2.StringValue, context):
        self._p2p_manager.on_peer_ready(request.value)
        return p2p_pb2.Empty()

    @twisted_grpc
    def OnPeerDisconnect(self, request: p2p_pb2.StringValue, context):
        self._p2p_manager.on_peer_disconnect(request.value)
        return p2p_pb2.Empty()

    @twisted_grpc
    def GetRandBytes(self, request, context):
        raise NotImplementedError('Method not implemented!')

    @twisted_grpc
    def IsPeerConnected(self, request, context):
        raise NotImplementedError('Method not implemented!')

    @twisted_grpc
    def SendTxToPeers(self, request, context):
        raise NotImplementedError('Method not implemented!')
