import grpc
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.logger import Logger

from hathor import protos
from hathor.exception import HathorError
from hathor.transaction.storage.transaction_storage import TransactionStorage
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.util import deprecated, skip_warning

from intervaltree import Interval
from math import inf


class RemoteCommunicationError(HathorError):
    pass


def convert_grpc_exceptions(func):
    """Decorator to catch and conver grpc excpetions for hathor expections.
    """
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except grpc.RpcError as e:
            if e.code() is grpc.StatusCode.NOT_FOUND:
                raise TransactionDoesNotExist
            else:
                raise RemoteCommunicationError from e

    return wrapper


def convert_grpc_exceptions_generator(func):
    """Decorator to catch and conver grpc excpetions for hathor expections. (for generators)
    """
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            yield from func(*args, **kwargs)
        except grpc.RpcError as e:
            if e.code() is grpc.StatusCode.NOT_FOUND:
                raise TransactionDoesNotExist
            else:
                raise RemoteCommunicationError from e

    return wrapper


def convert_hathor_exceptions(func):
    """Decorator to annotate better details and codes on the grpc context for known exceptions.
    """
    from functools import wraps

    @wraps(func)
    def wrapper(self, request, context):
        try:
            return func(self, request, context)
        except TransactionDoesNotExist:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details('Transaction does not exist.')
            raise

    return wrapper


def convert_hathor_exceptions_generator(func):
    """Decorator to annotate better details and codes on the grpc context for known exceptions. (for generators)
    """
    from functools import wraps

    @wraps(func)
    def wrapper(self, request, context):
        try:
            yield from func(self, request, context)
        except TransactionDoesNotExist:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details('Transaction does not exist.')
            raise

    return wrapper


class TransactionRemoteStorage(TransactionStorage):
    """Connects to a Storage API Server at given port and exposes standard storage interface.
    """
    log = Logger()

    def __init__(self, with_index=None):
        super().__init__()
        self._channel = None
        self._genesis_cache = None
        self.with_index = with_index

    def _create_genesis_cache(self):
        from hathor.transaction.genesis import genesis_transactions
        self._genesis_cache = {}
        for genesis in genesis_transactions(self):
            self._genesis_cache[genesis.hash] = genesis

    def connect_to(self, port):
        if self._channel:
            self._channel.close()
        self._channel = grpc.insecure_channel('127.0.0.1:{}'.format(port))
        self._stub = protos.TransactionStorageStub(self._channel)

    def _check_connection(self):
        """raise error if not connected"""
        from .subprocess_storage import SubprocessNotAliveError
        if not self._channel:
            raise SubprocessNotAliveError('subprocess not started')

    # TransactionStorageSync interface implementation:

    @deprecated('Use save_transaction_deferred instead')
    @convert_grpc_exceptions
    def save_transaction(self, tx, *, only_metadata=False):
        self._check_connection()

        # genesis txs and metadata are kept in memory
        if tx.is_genesis and not only_metadata:
            return

        tx_proto = tx.to_proto()
        request = protos.SaveRequest(transaction=tx_proto, only_metadata=only_metadata)
        result = self._stub.Save(request)  # noqa: F841
        # TODO: verify result.saved

    @deprecated('Use transaction_exists_deferred instead')
    @convert_grpc_exceptions
    def transaction_exists(self, hash_bytes):
        self._check_connection()
        request = protos.ExistsRequest(hash=hash_bytes)
        result = self._stub.Exists(request)
        return result.exists

    @deprecated('Use get_transaction_deferred instead')
    @convert_grpc_exceptions
    def get_transaction(self, hash_bytes):
        from hathor.transaction import tx_or_block_from_proto
        self._check_connection()
        request = protos.GetRequest(hash=hash_bytes)
        result = self._stub.Get(request)
        return tx_or_block_from_proto(result.transaction, storage=self)

    @deprecated('Use get_all_transactions_deferred instead')
    @convert_grpc_exceptions_generator
    def get_all_transactions(self):
        from hathor.transaction import tx_or_block_from_proto
        self._check_connection()
        request = protos.ListRequest()
        result = self._stub.List(request)
        for list_item in result:
            if not list_item.HasField('transaction'):
                break
            tx_proto = list_item.transaction
            yield tx_or_block_from_proto(tx_proto, storage=self)

    @deprecated('Use get_count_tx_blocks_deferred instead')
    @convert_grpc_exceptions
    def get_count_tx_blocks(self):
        self._check_connection()
        request = protos.CountRequest(tx_type=protos.ANY_TYPE)
        result = self._stub.Count(request)
        return result.count

    # TransactionStorageAsync interface implementation:

    @convert_grpc_exceptions
    def save_transaction_deferred(self, tx, *, only_metadata=False):
        # self._check_connection()
        raise NotImplementedError

    @inlineCallbacks
    @convert_grpc_exceptions_generator
    def transaction_exists_deferred(self, hash_bytes):
        self._check_connection()
        request = protos.ExistsRequest(hash=hash_bytes)
        result = yield Deferred.fromFuture(self._stub.Exists.future(request))
        return result.exists

    @convert_grpc_exceptions
    def get_transaction_deferred(self, hash_bytes):
        # self._check_connection()
        raise NotImplementedError

    @convert_grpc_exceptions
    def get_all_transactions_deferred(self):
        # self._check_connection()
        raise NotImplementedError

    @convert_grpc_exceptions
    def get_count_tx_blocks_deferred(self):
        # self._check_connection()
        raise NotImplementedError

    # TransactionStorage interface implementation:

    @property
    @convert_grpc_exceptions
    def latest_timestamp(self):
        self._check_connection()
        request = protos.LatestTimestampRequest()
        result = self._stub.LatestTimestamp(request)
        return result.timestamp

    @convert_grpc_exceptions
    def get_block_tips(self, timestamp=None):
        self._check_connection()
        if isinstance(timestamp, float) and timestamp != inf:
            self.log.warn('timestamp given in float will be truncated, use int instead')
            timestamp = int(timestamp)
        request = protos.ListTipsRequest(tx_type=protos.BLOCK_TYPE, timestamp=timestamp)
        result = self._stub.ListTips(request)
        tips = set()
        for interval_proto in result:
            tips.add(Interval(interval_proto.begin, interval_proto.end, interval_proto.data))
        return tips

    @convert_grpc_exceptions
    def get_tx_tips(self, timestamp=None):
        self._check_connection()
        if isinstance(timestamp, float) and timestamp != inf:
            self.log.warn('timestamp given in float will be truncated, use int instead')
            timestamp = int(timestamp)
        request = protos.ListTipsRequest(tx_type=protos.TRANSACTION_TYPE, timestamp=timestamp)
        result = self._stub.ListTips(request)
        tips = set()
        for interval_proto in result:
            tips.add(Interval(interval_proto.begin, interval_proto.end, interval_proto.data))
        return tips

    @convert_grpc_exceptions
    def get_newest_blocks(self, count):
        from hathor.transaction import tx_or_block_from_proto
        self._check_connection()
        request = protos.ListNewestRequest(tx_type=protos.BLOCK_TYPE, count=count)
        result = self._stub.ListNewest(request)
        tx_list = []
        has_more = None
        for list_item in result:
            if list_item.HasField('transaction'):
                tx_proto = list_item.transaction
                tx_list.append(tx_or_block_from_proto(tx_proto, storage=self))
            elif list_item.HasField('has_more'):
                has_more = list_item.has_more
                # assuming there are no more items after `has_more`, break soon
                break
            else:
                raise ValueError('unexpected list_item_oneof')
        assert has_more is not None
        return tx_list, has_more

    @convert_grpc_exceptions
    def get_newest_txs(self, count):
        from hathor.transaction import tx_or_block_from_proto
        self._check_connection()
        request = protos.ListNewestRequest(tx_type=protos.TRANSACTION_TYPE, count=count)
        result = self._stub.ListNewest(request)
        tx_list = []
        has_more = None
        for list_item in result:
            if list_item.HasField('transaction'):
                tx_proto = list_item.transaction
                tx_list.append(tx_or_block_from_proto(tx_proto, storage=self))
            elif list_item.HasField('has_more'):
                has_more = list_item.has_more
                # assuming there are no more items after `has_more`, break soon
                break
            else:
                raise ValueError('unexpected list_item_oneof')
        assert has_more is not None
        return tx_list, has_more

    @convert_grpc_exceptions
    def get_older_blocks_after(self, timestamp, hash_bytes, count):
        from hathor.transaction import tx_or_block_from_proto
        self._check_connection()
        if isinstance(timestamp, float):
            self.log.warn('timestamp given in float will be truncated, use int instead')
            timestamp = int(timestamp)
        request = protos.ListRequest(
            tx_type=protos.BLOCK_TYPE,
            time_filter=protos.ONLY_OLDER,
            timestamp=timestamp,
            hash=hash_bytes,
            max_count=count,
        )
        result = self._stub.List(request)
        tx_list = []
        has_more = None
        for list_item in result:
            if list_item.HasField('transaction'):
                tx_proto = list_item.transaction
                tx_list.append(tx_or_block_from_proto(tx_proto, storage=self))
            elif list_item.HasField('has_more'):
                has_more = list_item.has_more
                # assuming there are no more items after `has_more`, break soon
                break
            else:
                raise ValueError('unexpected list_item_oneof')
        assert has_more is not None
        return tx_list, has_more

    @convert_grpc_exceptions
    def get_newer_blocks_after(self, timestamp, hash_bytes, count):
        from hathor.transaction import tx_or_block_from_proto
        self._check_connection()
        if isinstance(timestamp, float):
            self.log.warn('timestamp given in float will be truncated, use int instead')
            timestamp = int(timestamp)
        request = protos.ListRequest(
            tx_type=protos.BLOCK_TYPE,
            time_filter=protos.ONLY_NEWER,
            timestamp=timestamp,
            hash=hash_bytes,
            max_count=count,
        )
        result = self._stub.List(request)
        tx_list = []
        has_more = None
        for list_item in result:
            if list_item.HasField('transaction'):
                tx_proto = list_item.transaction
                tx_list.append(tx_or_block_from_proto(tx_proto, storage=self))
            elif list_item.HasField('has_more'):
                has_more = list_item.has_more
                # assuming there are no more items after `has_more`, break soon
                break
            else:
                raise ValueError('unexpected list_item_oneof')
        assert has_more is not None
        return tx_list, has_more

    @convert_grpc_exceptions
    def get_older_txs_after(self, timestamp, hash_bytes, count):
        from hathor.transaction import tx_or_block_from_proto
        self._check_connection()
        if isinstance(timestamp, float):
            self.log.warn('timestamp given in float will be truncated, use int instead')
            timestamp = int(timestamp)
        request = protos.ListRequest(
            tx_type=protos.TRANSACTION_TYPE,
            time_filter=protos.ONLY_OLDER,
            timestamp=timestamp,
            hash=hash_bytes,
            max_count=count,
        )
        result = self._stub.List(request)
        tx_list = []
        has_more = None
        for list_item in result:
            if list_item.HasField('transaction'):
                tx_proto = list_item.transaction
                tx_list.append(tx_or_block_from_proto(tx_proto, storage=self))
            elif list_item.HasField('has_more'):
                has_more = list_item.has_more
                # assuming there are no more items after `has_more`, break soon
                break
            else:
                raise ValueError('unexpected list_item_oneof')
        assert has_more is not None
        return tx_list, has_more

    @convert_grpc_exceptions
    def get_newer_txs_after(self, timestamp, hash_bytes, count):
        from hathor.transaction import tx_or_block_from_proto
        self._check_connection()
        if isinstance(timestamp, float):
            self.log.warn('timestamp given in float will be truncated, use int instead')
            timestamp = int(timestamp)
        request = protos.ListRequest(
            tx_type=protos.TRANSACTION_TYPE,
            time_filter=protos.ONLY_NEWER,
            timestamp=timestamp,
            hash=hash_bytes,
            max_count=count,
        )
        result = self._stub.List(request)
        tx_list = []
        has_more = None
        for list_item in result:
            if list_item.HasField('transaction'):
                tx_proto = list_item.transaction
                tx_list.append(tx_or_block_from_proto(tx_proto, storage=self))
            elif list_item.HasField('has_more'):
                has_more = list_item.has_more
                # assuming there are no more items after `has_more`, break soon
                break
            else:
                raise ValueError('unexpected list_item_oneof')
        assert has_more is not None
        return tx_list, has_more

    def _manually_initialize(self):
        pass

    @convert_grpc_exceptions_generator
    def _call_list_request_generators(self, kwargs):
        """ Execute a call for the ListRequest and yield the blocks or txs

            :param kwargs: Parameters to be sent to ListRequest
            :type kwargs: Dict[str,]
        """
        from hathor.transaction import tx_or_block_from_proto
        self._check_connection()
        request = protos.ListRequest(**kwargs)
        result = self._stub.List(request)
        for list_item in result:
            if not list_item.HasField('transaction'):
                break
            tx_proto = list_item.transaction
            yield tx_or_block_from_proto(tx_proto, storage=self)

    @convert_grpc_exceptions_generator
    def _topological_sort(self):
        yield from self._call_list_request_generators({'order_by': protos.TOPOLOGICAL_ORDER})

    @convert_grpc_exceptions_generator
    def iter_bfs_children(self, root):
        yield from self._call_list_request_generators({
            'order_by': protos.LEFT_RIGHT_ORDER_CHILDREN,
            'tx': root.to_proto()
        })

    @convert_grpc_exceptions
    def iter_bfs_spent_by(self, root):
        yield from self._call_list_request_generators({
            'order_by': protos.LEFT_RIGHT_ORDER_SPENT,
            'tx': root.to_proto()
        })

    @convert_grpc_exceptions
    def _add_to_voided(self, tx):
        self._check_connection()
        tx_proto = tx.to_proto()
        request = protos.MarkAsRequest(transaction=tx_proto, mark_type=protos.VOIDED)
        result = self._stub.MarkAs(request)  # noqa: F841

    @convert_grpc_exceptions
    def _del_from_voided(self, tx):
        self._check_connection()
        tx_proto = tx.to_proto()
        request = protos.MarkAsRequest(transaction=tx_proto, mark_type=protos.VOIDED, remove_mark=True)
        result = self._stub.MarkAs(request)  # noqa: F841

    @convert_grpc_exceptions
    def _add_to_cache(self, tx):
        self._check_connection()
        tx_proto = tx.to_proto()
        request = protos.MarkAsRequest(transaction=tx_proto, mark_type=protos.FOR_CACHING)
        result = self._stub.MarkAs(request)  # noqa: F841

    @convert_grpc_exceptions
    def _del_from_cache(self, tx):
        self._check_connection()
        tx_proto = tx.to_proto()
        request = protos.MarkAsRequest(transaction=tx_proto, mark_type=protos.FOR_CACHING, remove_mark=True)
        result = self._stub.MarkAs(request)  # noqa: F841

    # @deprecated('Use get_block_count_deferred instead')
    @convert_grpc_exceptions
    def get_block_count(self):
        self._check_connection()
        request = protos.CountRequest(tx_type=protos.BLOCK_TYPE)
        result = self._stub.Count(request)
        return result.count

    # @deprecated('Use get_tx_count_deferred instead')
    @convert_grpc_exceptions
    def get_tx_count(self):
        self._check_connection()
        request = protos.CountRequest(tx_type=protos.TRANSACTION_TYPE)
        result = self._stub.Count(request)
        return result.count

    def get_genesis(self, hash_bytes):
        if not self._genesis_cache:
            self._create_genesis_cache()
        return self._genesis_cache.get(hash_bytes, None)

    def get_all_genesis(self):
        if not self._genesis_cache:
            self._create_genesis_cache()
        return self._genesis_cache.values()

    @convert_grpc_exceptions
    def get_transactions_before(self, hash_bytes, num_blocks=100):  # pragma: no cover
        from hathor.transaction import tx_or_block_from_proto
        self._check_connection()
        request = protos.ListRequest(
            tx_type=protos.TRANSACTION_TYPE,
            hash=hash_bytes,
            max_count=num_blocks,
            filter_before=True,
        )
        result = self._stub.List(request)
        tx_list = []
        for list_item in result:
            if not list_item.HasField('transaction'):
                break
            tx_proto = list_item.transaction
            tx_list.append(tx_or_block_from_proto(tx_proto, storage=self))
        return tx_list

    @convert_grpc_exceptions_generator
    def iter_bfs_ascendent_blocks(self, root, max_depth):
        yield from self._call_list_request_generators({
            'order_by': protos.ASC_ORDER,
            'tx_type': protos.BLOCK_TYPE,
            'tx': root.to_proto(),
            'max_count': max_depth
        })

    @convert_grpc_exceptions
    def get_blocks_before(self, hash_bytes, num_blocks=100):
        from hathor.transaction import tx_or_block_from_proto
        self._check_connection()
        request = protos.ListRequest(
            tx_type=protos.BLOCK_TYPE,
            hash=hash_bytes,
            max_count=num_blocks,
            filter_before=True,
        )
        result = self._stub.List(request)
        tx_list = []
        for list_item in result:
            if not list_item.HasField('transaction'):
                break
            tx_proto = list_item.transaction
            tx_list.append(tx_or_block_from_proto(tx_proto, storage=self))
        return tx_list


class TransactionStorageServicer(protos.TransactionStorageServicer):
    log = Logger()

    def __init__(self, tx_storage):
        self.storage = tx_storage

    @convert_hathor_exceptions
    def Exists(self, request, context):
        hash_bytes = request.hash
        exists = skip_warning(self.storage.transaction_exists)(hash_bytes)
        return protos.ExistsResponse(exists=exists)

    @convert_hathor_exceptions
    def Get(self, request, context):
        hash_bytes = request.hash
        exclude_metadata = request.exclude_metadata

        tx = skip_warning(self.storage.get_transaction)(hash_bytes)

        if exclude_metadata:
            del tx._metadata
        else:
            tx.get_metadata()

        return protos.GetResponse(transaction=tx.to_proto())

    @convert_hathor_exceptions
    def Save(self, request, context):
        from hathor.transaction import tx_or_block_from_proto

        tx_proto = request.transaction
        only_metadata = request.only_metadata

        result = protos.SaveResponse(saved=False)

        tx = tx_or_block_from_proto(tx_proto, storage=self.storage)
        skip_warning(self.storage.save_transaction)(tx, only_metadata=only_metadata)
        result.saved = True

        return result

    @convert_hathor_exceptions
    def Count(self, request, context):
        tx_type = request.tx_type
        if tx_type is protos.ANY_TYPE:
            count = skip_warning(self.storage.get_count_tx_blocks)()
        elif tx_type is protos.TRANSACTION_TYPE:
            count = skip_warning(self.storage.get_tx_count)()
        elif tx_type is protos.BLOCK_TYPE:
            count = skip_warning(self.storage.get_block_count)()
        else:
            raise ValueError('invalid tx_type')
        return protos.CountResponse(count=count)

    @convert_hathor_exceptions
    def LatestTimestamp(self, request, context):
        return protos.LatestTimestampResponse(timestamp=self.storage.latest_timestamp)

    @convert_hathor_exceptions
    def MarkAs(self, request, context):
        from hathor.transaction import tx_or_block_from_proto

        tx = tx_or_block_from_proto(request.transaction, storage=self.storage)

        if request.mark_type == protos.FOR_CACHING:
            if request.remove_mark:
                self.storage._del_from_cache(tx)
            else:
                self.storage._add_to_cache(tx)
        elif request.mark_type == protos.VOIDED:
            if request.remove_mark:
                self.storage._del_from_voided(tx)
            else:
                self.storage._add_to_voided(tx)
        else:
            raise ValueError('invalid mark_type')

        # TODO: correct value for `marked`
        return protos.MarkAsResponse(marked=True)

    @convert_hathor_exceptions_generator
    def List(self, request, context):
        from hathor.transaction import tx_or_block_from_proto

        exclude_metadata = request.exclude_metadata
        has_more = None

        hash_bytes = request.hash
        count = request.max_count
        timestamp = request.timestamp

        # TODO: more exceptions for unsupported cases
        if request.filter_before:
            if request.tx_type == protos.ANY_TYPE:
                raise NotImplementedError
            elif request.tx_type == protos.TRANSACTION_TYPE:
                tx_iter = self.storage.get_transactions_before(hash_bytes, count)
            elif request.tx_type == protos.BLOCK_TYPE:
                tx_iter = self.storage.get_blocks_before(hash_bytes, count)
            else:
                raise ValueError('invalid tx_type')
        elif request.time_filter is protos.ONLY_NEWER:
            if request.tx_type == protos.ANY_TYPE:
                raise NotImplementedError
            elif request.tx_type == protos.TRANSACTION_TYPE:
                tx_iter, has_more = self.storage.get_newer_txs_after(timestamp, hash_bytes, count)
            elif request.tx_type == protos.BLOCK_TYPE:
                tx_iter, has_more = self.storage.get_newer_blocks_after(timestamp, hash_bytes, count)
            else:
                raise ValueError('invalid tx_type')
        elif request.time_filter is protos.ONLY_OLDER:
            if request.tx_type == protos.ANY_TYPE:
                raise NotImplementedError
            elif request.tx_type == protos.TRANSACTION_TYPE:
                tx_iter, has_more = self.storage.get_older_txs_after(timestamp, hash_bytes, count)
            elif request.tx_type == protos.BLOCK_TYPE:
                tx_iter, has_more = self.storage.get_older_blocks_after(timestamp, hash_bytes, count)
            else:
                raise ValueError('invalid tx_type')
        elif request.time_filter is protos.NO_FILTER:
            if request.order_by is protos.ANY_ORDER:
                tx_iter = skip_warning(self.storage.get_all_transactions)()
            elif request.order_by is protos.TOPOLOGICAL_ORDER:
                tx_iter = self.storage._topological_sort()
            elif request.order_by is protos.ASC_ORDER:
                if request.tx_type is not protos.BLOCK_TYPE:
                    raise NotImplementedError
                root = tx_or_block_from_proto(request.tx, storage=self.storage)
                max_depth = request.max_count
                tx_iter = self.storage.iter_bfs_ascendent_blocks(root, max_depth)
            elif request.order_by is protos.LEFT_RIGHT_ORDER_CHILDREN:
                root = tx_or_block_from_proto(request.tx, storage=self.storage)
                tx_iter = self.storage.iter_bfs_children(root)
            elif request.order_by is protos.LEFT_RIGHT_ORDER_SPENT:
                root = tx_or_block_from_proto(request.tx, storage=self.storage)
                tx_iter = self.storage.iter_bfs_spent_by(root)
            else:
                raise ValueError('invalid order_by')
        else:
            raise ValueError('invalid request')

        for tx in tx_iter:
            if exclude_metadata:
                del tx._metadata
            else:
                tx.get_metadata()
            yield protos.ListItemResponse(transaction=tx.to_proto())
        if has_more is not None:
            yield protos.ListItemResponse(has_more=has_more)

    @convert_hathor_exceptions_generator
    def ListTips(self, request, context):
        # XXX: using HasField (and oneof) to differentiate None from 0, which is very important in this context
        timestamp = None
        if request.HasField('timestamp'):
            timestamp = request.timestamp

        if request.tx_type == protos.ANY_TYPE:
            raise NotImplementedError
        elif request.tx_type == protos.TRANSACTION_TYPE:
            tx_intervals = self.storage.get_tx_tips(timestamp)
        elif request.tx_type == protos.BLOCK_TYPE:
            tx_intervals = self.storage.get_block_tips(timestamp)
        else:
            raise ValueError('invalid tx_type')

        for interval in tx_intervals:
            yield protos.Interval(begin=interval.begin, end=interval.end, data=interval.data)

    @convert_hathor_exceptions_generator
    def ListNewest(self, request, context):
        has_more = False
        if request.tx_type == protos.ANY_TYPE:
            raise NotImplementedError
        elif request.tx_type == protos.TRANSACTION_TYPE:
            tx_list, has_more = self.storage.get_newest_txs(request.count)
        elif request.tx_type == protos.BLOCK_TYPE:
            tx_list, has_more = self.storage.get_newest_blocks(request.count)
        else:
            raise ValueError('invalid tx_type')

        for tx in tx_list:
            yield protos.ListItemResponse(transaction=tx.to_proto())
        yield protos.ListItemResponse(has_more=has_more)


def create_transaction_storage_server(server, tx_storage, port=None):
    """Create a GRPC servicer for the given storage, returns a (servicer, port) tuple.

    :param server: a GRPC server
    :type server: :py:class:`grpc.Server`

    :param tx_storage: an instance of TransactionStorage
    :type tx_storage: :py:class:`hathor.transaction.storage.TransactionStorage`

    :param port: optional listen port, if None a random port will be chosen (and returned)
    :type server: :py:class:`typing.Optional[int]`

    :rtype :py:class:`typing.Tuple[hathor.protos.TransactionStorageServicer, int]`
    """
    servicer = TransactionStorageServicer(tx_storage)
    protos.add_TransactionStorageServicer_to_server(servicer, server)
    port = server.add_insecure_port('127.0.0.1:0')
    return servicer, port
