# Generated by the gRPC Python protocol compiler plugin. DO NOT EDIT!
"""Client and server classes corresponding to protobuf-defined services."""
import grpc
import warnings

from protos import p2p_pb2 as protos_dot_p2p__pb2

GRPC_GENERATED_VERSION = '1.67.0'
GRPC_VERSION = grpc.__version__
_version_not_supported = False

try:
    from grpc._utilities import first_version_is_lower
    _version_not_supported = first_version_is_lower(GRPC_VERSION, GRPC_GENERATED_VERSION)
except ImportError:
    _version_not_supported = True

if _version_not_supported:
    raise RuntimeError(
        f'The grpc package installed is at version {GRPC_VERSION},'
        + f' but the generated code in protos/p2p_pb2_grpc.py depends on'
        + f' grpcio>={GRPC_GENERATED_VERSION}.'
        + f' Please upgrade your grpc module to grpcio>={GRPC_GENERATED_VERSION}'
        + f' or downgrade your generated code using grpcio-tools<={GRPC_VERSION}.'
    )


class P2PManagerStub(object):
    """Missing associated documentation comment in .proto file."""

    def __init__(self, channel):
        """Constructor.

        Args:
            channel: A grpc.Channel.
        """
        self.IsPeerWhitelisted = channel.unary_unary(
                '/p2p.P2PManager/IsPeerWhitelisted',
                request_serializer=protos_dot_p2p__pb2.BytesValue.SerializeToString,
                response_deserializer=protos_dot_p2p__pb2.BoolValue.FromString,
                _registered_method=True)
        self.GetEnabledSyncVersions = channel.unary_unary(
                '/p2p.P2PManager/GetEnabledSyncVersions',
                request_serializer=protos_dot_p2p__pb2.Empty.SerializeToString,
                response_deserializer=protos_dot_p2p__pb2.StringList.FromString,
                _registered_method=True)
        self.GetVerifiedPeers = channel.unary_unary(
                '/p2p.P2PManager/GetVerifiedPeers',
                request_serializer=protos_dot_p2p__pb2.Empty.SerializeToString,
                response_deserializer=protos_dot_p2p__pb2.StringList.FromString,
                _registered_method=True)
        self.OnReceivePeer = channel.unary_unary(
                '/p2p.P2PManager/OnReceivePeer',
                request_serializer=protos_dot_p2p__pb2.StringValue.SerializeToString,
                response_deserializer=protos_dot_p2p__pb2.Empty.FromString,
                _registered_method=True)
        self.OnPeerConnect = channel.unary_unary(
                '/p2p.P2PManager/OnPeerConnect',
                request_serializer=protos_dot_p2p__pb2.StringValue.SerializeToString,
                response_deserializer=protos_dot_p2p__pb2.Empty.FromString,
                _registered_method=True)
        self.OnPeerReady = channel.unary_unary(
                '/p2p.P2PManager/OnPeerReady',
                request_serializer=protos_dot_p2p__pb2.StringValue.SerializeToString,
                response_deserializer=protos_dot_p2p__pb2.Empty.FromString,
                _registered_method=True)
        self.OnPeerDisconnect = channel.unary_unary(
                '/p2p.P2PManager/OnPeerDisconnect',
                request_serializer=protos_dot_p2p__pb2.StringValue.SerializeToString,
                response_deserializer=protos_dot_p2p__pb2.Empty.FromString,
                _registered_method=True)
        self.GetRandBytes = channel.unary_unary(
                '/p2p.P2PManager/GetRandBytes',
                request_serializer=protos_dot_p2p__pb2.Int32Value.SerializeToString,
                response_deserializer=protos_dot_p2p__pb2.BytesValue.FromString,
                _registered_method=True)
        self.IsPeerConnected = channel.unary_unary(
                '/p2p.P2PManager/IsPeerConnected',
                request_serializer=protos_dot_p2p__pb2.BytesValue.SerializeToString,
                response_deserializer=protos_dot_p2p__pb2.BoolValue.FromString,
                _registered_method=True)
        self.SendTxToPeers = channel.unary_unary(
                '/p2p.P2PManager/SendTxToPeers',
                request_serializer=protos_dot_p2p__pb2.BytesValue.SerializeToString,
                response_deserializer=protos_dot_p2p__pb2.Empty.FromString,
                _registered_method=True)


class P2PManagerServicer(object):
    """Missing associated documentation comment in .proto file."""

    def IsPeerWhitelisted(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetEnabledSyncVersions(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetVerifiedPeers(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def OnReceivePeer(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def OnPeerConnect(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def OnPeerReady(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def OnPeerDisconnect(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def GetRandBytes(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def IsPeerConnected(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')

    def SendTxToPeers(self, request, context):
        """Missing associated documentation comment in .proto file."""
        context.set_code(grpc.StatusCode.UNIMPLEMENTED)
        context.set_details('Method not implemented!')
        raise NotImplementedError('Method not implemented!')


def add_P2PManagerServicer_to_server(servicer, server):
    rpc_method_handlers = {
            'IsPeerWhitelisted': grpc.unary_unary_rpc_method_handler(
                    servicer.IsPeerWhitelisted,
                    request_deserializer=protos_dot_p2p__pb2.BytesValue.FromString,
                    response_serializer=protos_dot_p2p__pb2.BoolValue.SerializeToString,
            ),
            'GetEnabledSyncVersions': grpc.unary_unary_rpc_method_handler(
                    servicer.GetEnabledSyncVersions,
                    request_deserializer=protos_dot_p2p__pb2.Empty.FromString,
                    response_serializer=protos_dot_p2p__pb2.StringList.SerializeToString,
            ),
            'GetVerifiedPeers': grpc.unary_unary_rpc_method_handler(
                    servicer.GetVerifiedPeers,
                    request_deserializer=protos_dot_p2p__pb2.Empty.FromString,
                    response_serializer=protos_dot_p2p__pb2.StringList.SerializeToString,
            ),
            'OnReceivePeer': grpc.unary_unary_rpc_method_handler(
                    servicer.OnReceivePeer,
                    request_deserializer=protos_dot_p2p__pb2.StringValue.FromString,
                    response_serializer=protos_dot_p2p__pb2.Empty.SerializeToString,
            ),
            'OnPeerConnect': grpc.unary_unary_rpc_method_handler(
                    servicer.OnPeerConnect,
                    request_deserializer=protos_dot_p2p__pb2.StringValue.FromString,
                    response_serializer=protos_dot_p2p__pb2.Empty.SerializeToString,
            ),
            'OnPeerReady': grpc.unary_unary_rpc_method_handler(
                    servicer.OnPeerReady,
                    request_deserializer=protos_dot_p2p__pb2.StringValue.FromString,
                    response_serializer=protos_dot_p2p__pb2.Empty.SerializeToString,
            ),
            'OnPeerDisconnect': grpc.unary_unary_rpc_method_handler(
                    servicer.OnPeerDisconnect,
                    request_deserializer=protos_dot_p2p__pb2.StringValue.FromString,
                    response_serializer=protos_dot_p2p__pb2.Empty.SerializeToString,
            ),
            'GetRandBytes': grpc.unary_unary_rpc_method_handler(
                    servicer.GetRandBytes,
                    request_deserializer=protos_dot_p2p__pb2.Int32Value.FromString,
                    response_serializer=protos_dot_p2p__pb2.BytesValue.SerializeToString,
            ),
            'IsPeerConnected': grpc.unary_unary_rpc_method_handler(
                    servicer.IsPeerConnected,
                    request_deserializer=protos_dot_p2p__pb2.BytesValue.FromString,
                    response_serializer=protos_dot_p2p__pb2.BoolValue.SerializeToString,
            ),
            'SendTxToPeers': grpc.unary_unary_rpc_method_handler(
                    servicer.SendTxToPeers,
                    request_deserializer=protos_dot_p2p__pb2.BytesValue.FromString,
                    response_serializer=protos_dot_p2p__pb2.Empty.SerializeToString,
            ),
    }
    generic_handler = grpc.method_handlers_generic_handler(
            'p2p.P2PManager', rpc_method_handlers)
    server.add_generic_rpc_handlers((generic_handler,))
    server.add_registered_method_handlers('p2p.P2PManager', rpc_method_handlers)


 # This class is part of an EXPERIMENTAL API.
class P2PManager(object):
    """Missing associated documentation comment in .proto file."""

    @staticmethod
    def IsPeerWhitelisted(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/p2p.P2PManager/IsPeerWhitelisted',
            protos_dot_p2p__pb2.BytesValue.SerializeToString,
            protos_dot_p2p__pb2.BoolValue.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def GetEnabledSyncVersions(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/p2p.P2PManager/GetEnabledSyncVersions',
            protos_dot_p2p__pb2.Empty.SerializeToString,
            protos_dot_p2p__pb2.StringList.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def GetVerifiedPeers(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/p2p.P2PManager/GetVerifiedPeers',
            protos_dot_p2p__pb2.Empty.SerializeToString,
            protos_dot_p2p__pb2.StringList.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def OnReceivePeer(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/p2p.P2PManager/OnReceivePeer',
            protos_dot_p2p__pb2.StringValue.SerializeToString,
            protos_dot_p2p__pb2.Empty.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def OnPeerConnect(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/p2p.P2PManager/OnPeerConnect',
            protos_dot_p2p__pb2.StringValue.SerializeToString,
            protos_dot_p2p__pb2.Empty.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def OnPeerReady(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/p2p.P2PManager/OnPeerReady',
            protos_dot_p2p__pb2.StringValue.SerializeToString,
            protos_dot_p2p__pb2.Empty.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def OnPeerDisconnect(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/p2p.P2PManager/OnPeerDisconnect',
            protos_dot_p2p__pb2.StringValue.SerializeToString,
            protos_dot_p2p__pb2.Empty.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def GetRandBytes(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/p2p.P2PManager/GetRandBytes',
            protos_dot_p2p__pb2.Int32Value.SerializeToString,
            protos_dot_p2p__pb2.BytesValue.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def IsPeerConnected(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/p2p.P2PManager/IsPeerConnected',
            protos_dot_p2p__pb2.BytesValue.SerializeToString,
            protos_dot_p2p__pb2.BoolValue.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)

    @staticmethod
    def SendTxToPeers(request,
            target,
            options=(),
            channel_credentials=None,
            call_credentials=None,
            insecure=False,
            compression=None,
            wait_for_ready=None,
            timeout=None,
            metadata=None):
        return grpc.experimental.unary_unary(
            request,
            target,
            '/p2p.P2PManager/SendTxToPeers',
            protos_dot_p2p__pb2.BytesValue.SerializeToString,
            protos_dot_p2p__pb2.Empty.FromString,
            options,
            channel_credentials,
            insecure,
            call_credentials,
            compression,
            wait_for_ready,
            timeout,
            metadata,
            _registered_method=True)
