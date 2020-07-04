from math import inf
from typing import TYPE_CHECKING, Any, Callable, Dict, Generator, Iterator, List, Optional, Set, Tuple, Union

import grpc
from grpc._server import _Context
from intervaltree import Interval
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.logger import Logger

from hathor import protos
from hathor.exception import HathorError
from hathor.indexes import TransactionIndexElement, TransactionsIndex
from hathor.transaction import Block
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.storage.transaction_storage import AllTipsCache, TransactionStorage

if TYPE_CHECKING:
    from hathor.transaction import BaseTransaction  # noqa: F401


class RemoteCommunicationError(HathorError):
    pass


def convert_grpc_exceptions(func: Callable) -> Callable:
    """Decorator to catch and conver grpc exceptions for hathor expections.
    """
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.NOT_FOUND:
                raise TransactionDoesNotExist
            else:
                raise RemoteCommunicationError from e

    return wrapper


def convert_grpc_exceptions_generator(func: Callable) -> Callable:
    """Decorator to catch and conver grpc excpetions for hathor expections. (for generators)
    """
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            yield from func(*args, **kwargs)
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.NOT_FOUND:
                raise TransactionDoesNotExist
            else:
                raise RemoteCommunicationError from e

    return wrapper


def convert_hathor_exceptions(func: Callable) -> Callable:
    """Decorator to annotate better details and codes on the grpc context for known exceptions.
    """
    from functools import wraps

    @wraps(func)
    def wrapper(self: Any, request: Any, context: _Context) -> Any:
        try:
            return func(self, request, context)
        except TransactionDoesNotExist:
            context.set_code(grpc.StatusCode.NOT_FOUND)
            context.set_details('Transaction does not exist.')
            raise

    return wrapper


def convert_hathor_exceptions_generator(func: Callable) -> Callable:
    """Decorator to annotate better details and codes on the grpc context for known exceptions. (for generators)
    """
    from functools import wraps

    @wraps(func)
    def wrapper(self: Any, request: Any, context: _Context) -> Iterator:
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
        self.with_index = with_index
        # Set initial value for _best_block_tips cache.
        self._best_block_tips = []

    def connect_to(self, port: int) -> None:
        if self._channel:
            self._channel.close()
        self._channel = grpc.insecure_channel('127.0.0.1:{}'.format(port))
        self._stub = protos.TransactionStorageStub(self._channel)

        # Initialize genesis.
        self._save_or_verify_genesis()

        # Set initial value for _best_block_tips cache.
        self._best_block_tips = [x.hash for x in self.get_all_genesis() if x.is_block]

    def _check_connection(self) -> None:
        """raise error if not connected"""
        from .subprocess_storage import SubprocessNotAliveError
        if not self._channel:
            raise SubprocessNotAliveError('subprocess not started')

    # TransactionStorageSync interface implementation:

    @convert_grpc_exceptions
    def remove_transaction(self, tx: 'BaseTransaction') -> None:
        self._check_connection()

        tx_proto = tx.to_proto()
        request = protos.RemoveRequest(transaction=tx_proto)
        result = self._stub.Remove(request)  # noqa: F841
        assert result.removed
        self._remove_from_weakref(tx)

    @convert_grpc_exceptions
    def save_transaction(self, tx: 'BaseTransaction', *, only_metadata: bool = False) -> None:
        self._check_connection()

        tx_proto = tx.to_proto()
        request = protos.SaveRequest(transaction=tx_proto, only_metadata=only_metadata)
        result = self._stub.Save(request)  # noqa: F841
        assert result.saved
        self._save_to_weakref(tx)

    @convert_grpc_exceptions
    def transaction_exists(self, hash_bytes: bytes) -> bool:
        self._check_connection()
        request = protos.ExistsRequest(hash=hash_bytes)
        result = self._stub.Exists(request)
        return result.exists

    @convert_grpc_exceptions
    def _get_transaction(self, hash_bytes: bytes) -> 'BaseTransaction':
        tx = self.get_transaction_from_weakref(hash_bytes)
        if tx is not None:
            return tx

        from hathor.transaction import tx_or_block_from_proto
        self._check_connection()
        request = protos.GetRequest(hash=hash_bytes)
        result = self._stub.Get(request)

        tx = tx_or_block_from_proto(result.transaction, storage=self)
        self._save_to_weakref(tx)
        return tx

    @convert_grpc_exceptions_generator
    def get_all_transactions(self) -> Iterator['BaseTransaction']:
        yield from self._call_list_request_generators()

    @convert_grpc_exceptions
    def get_count_tx_blocks(self) -> int:
        self._check_connection()
        request = protos.CountRequest(tx_type=protos.ANY_TYPE)
        result = self._stub.Count(request)
        return result.count

    # TransactionStorageAsync interface implementation:

    @convert_grpc_exceptions
    def save_transaction_deferred(self, tx: 'BaseTransaction', *, only_metadata: bool = False) -> None:
        # self._check_connection()
        raise NotImplementedError

    @convert_grpc_exceptions
    def remove_transaction_deferred(self, tx: 'BaseTransaction') -> None:
        # self._check_connection()
        raise NotImplementedError

    @inlineCallbacks
    @convert_grpc_exceptions_generator
    def transaction_exists_deferred(self, hash_bytes: bytes) -> Generator[None, protos.ExistsResponse, bool]:
        self._check_connection()
        request = protos.ExistsRequest(hash=hash_bytes)
        result = yield Deferred.fromFuture(self._stub.Exists.future(request))
        return result.exists

    @convert_grpc_exceptions
    def get_transaction_deferred(self, hash_bytes: bytes) -> Deferred:
        # self._check_connection()
        raise NotImplementedError

    @convert_grpc_exceptions
    def get_all_transactions_deferred(self) -> Deferred:
        # self._check_connection()
        raise NotImplementedError

    @convert_grpc_exceptions
    def get_count_tx_blocks_deferred(self) -> Deferred:
        # self._check_connection()
        raise NotImplementedError

    # TransactionStorage interface implementation:

    @property
    def latest_timestamp(self) -> int:
        return self._latest_timestamp()

    @convert_grpc_exceptions
    def _latest_timestamp(self) -> int:
        self._check_connection()
        request = protos.LatestTimestampRequest()
        result = self._stub.LatestTimestamp(request)
        return result.timestamp

    @property
    def first_timestamp(self) -> int:
        if not hasattr(self, '_cached_first_timestamp'):
            timestamp = self._first_timestamp()
            if timestamp:
                setattr(self, '_cached_first_timestamp', timestamp)
        return getattr(self, '_cached_first_timestamp', None)

    @convert_grpc_exceptions
    def _first_timestamp(self) -> int:
        self._check_connection()
        request = protos.FirstTimestampRequest()
        result = self._stub.FirstTimestamp(request)
        return result.timestamp

    def get_best_block_tips(self, timestamp: Optional[float] = None, *, skip_cache: bool = False) -> List[bytes]:
        return super().get_best_block_tips(timestamp, skip_cache=skip_cache)

    @convert_grpc_exceptions
    def get_all_tips(self, timestamp: Optional[Union[int, float]] = None) -> Set[Interval]:
        self._check_connection()
        if isinstance(timestamp, float) and timestamp != inf:
            self.log.warn('timestamp given in float will be truncated, use int instead')
            timestamp = int(timestamp)

        if self._all_tips_cache is not None and timestamp is not None and timestamp >= self._all_tips_cache.timestamp:
            return self._all_tips_cache.tips

        request = protos.ListTipsRequest(tx_type=protos.ANY_TYPE, timestamp=timestamp)
        result = self._stub.ListTips(request)
        tips = set()
        for interval_proto in result:
            tips.add(Interval(interval_proto.begin, interval_proto.end, interval_proto.data))

        if timestamp is not None and timestamp >= self.latest_timestamp:
            merkle_tree, hashes = self.calculate_merkle_tree(tips)
            self._all_tips_cache = AllTipsCache(self.latest_timestamp, tips, merkle_tree, hashes)

        return tips

    @convert_grpc_exceptions
    def get_block_tips(self, timestamp: Optional[float] = None) -> Set[Interval]:
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
    def get_tx_tips(self, timestamp: Optional[float] = None) -> Set[Interval]:
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
    def get_newest_blocks(self, count: int) -> Tuple[List['Block'], bool]:
        from hathor.transaction import tx_or_block_from_proto
        self._check_connection()
        request = protos.ListNewestRequest(tx_type=protos.BLOCK_TYPE, count=count)
        result = self._stub.ListNewest(request)
        tx_list: List['Block'] = []
        has_more = None
        for list_item in result:
            if list_item.HasField('transaction'):
                tx_proto = list_item.transaction
                blk = tx_or_block_from_proto(tx_proto, storage=self)
                assert isinstance(blk, Block)
                tx_list.append(blk)
            elif list_item.HasField('has_more'):
                has_more = list_item.has_more
                # assuming there are no more items after `has_more`, break soon
                break
            else:
                raise ValueError('unexpected list_item_oneof')
        assert isinstance(has_more, bool)
        return tx_list, has_more

    @convert_grpc_exceptions
    def get_newest_txs(self, count: int) -> Tuple[List['BaseTransaction'], bool]:
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
    def get_older_blocks_after(self, timestamp: int, hash_bytes: bytes,
                               count: int) -> Tuple[List['BaseTransaction'], bool]:
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
    def get_newer_blocks_after(self, timestamp: int, hash_bytes: bytes,
                               count: int) -> Tuple[List['BaseTransaction'], bool]:
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
    def get_older_txs_after(self, timestamp: int, hash_bytes: bytes,
                            count: int) -> Tuple[List['BaseTransaction'], bool]:
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
    def get_newer_txs_after(self, timestamp: int, hash_bytes: bytes,
                            count: int) -> Tuple[List['BaseTransaction'], bool]:
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

    def _manually_initialize(self) -> None:
        pass

    @convert_grpc_exceptions_generator
    def _call_list_request_generators(self, kwargs: Optional[Dict[str, Any]] = None):
        """ Execute a call for the ListRequest and yield the blocks or txs

            :param kwargs: Parameters to be sent to ListRequest
            :type kwargs: Dict[str,]
        """
        from hathor.transaction import tx_or_block_from_proto
        def get_tx(tx):
            tx2 = self.get_transaction_from_weakref(tx.hash)
            if tx2:
                tx = tx2
            else:
                self._save_to_weakref(tx)
            return tx

        self._check_connection()
        if kwargs:
            request = protos.ListRequest(**kwargs)
        else:
            request = protos.ListRequest()
        result = self._stub.List(request)
        for list_item in result:
            if not list_item.HasField('transaction'):
                break
            tx_proto = list_item.transaction
            tx = tx_or_block_from_proto(tx_proto, storage=self)
            lock = self._get_lock(tx.hash)

            if lock:
                with lock:
                    tx = get_tx(tx)
            else:
                tx = get_tx(tx)
            yield tx

    @convert_grpc_exceptions_generator
    def _topological_sort(self):
        yield from self._call_list_request_generators({'order_by': protos.TOPOLOGICAL_ORDER})

    @convert_grpc_exceptions
    def _add_to_cache(self, tx):
        self._check_connection()
        tx_proto = tx.to_proto()
        request = protos.MarkAsRequest(transaction=tx_proto, mark_type=protos.FOR_CACHING, relax_assert=False)
        result = self._stub.MarkAs(request)  # noqa: F841

    @convert_grpc_exceptions
    def _del_from_cache(self, tx: 'BaseTransaction', *, relax_assert: bool = False) -> None:
        self._check_connection()
        tx_proto = tx.to_proto()
        request = protos.MarkAsRequest(transaction=tx_proto, mark_type=protos.FOR_CACHING, remove_mark=True,
                                       relax_assert=relax_assert)
        result = self._stub.MarkAs(request)  # noqa: F841

    @convert_grpc_exceptions
    def get_block_count(self) -> int:
        self._check_connection()
        request = protos.CountRequest(tx_type=protos.BLOCK_TYPE)
        result = self._stub.Count(request)
        return result.count

    @convert_grpc_exceptions
    def get_tx_count(self) -> int:
        self._check_connection()
        request = protos.CountRequest(tx_type=protos.TRANSACTION_TYPE)
        result = self._stub.Count(request)
        return result.count

    def get_genesis(self, hash_bytes: bytes) -> Optional['BaseTransaction']:
        assert self._genesis_cache is not None
        return self._genesis_cache.get(hash_bytes, None)

    def get_all_genesis(self) -> Set['BaseTransaction']:
        assert self._genesis_cache is not None
        return set(self._genesis_cache.values())

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

    @convert_grpc_exceptions
    def get_blocks_before(self, hash_bytes: bytes, num_blocks: int = 100) -> List[Block]:
        from hathor.transaction import tx_or_block_from_proto
        self._check_connection()
        request = protos.ListRequest(
            tx_type=protos.BLOCK_TYPE,
            hash=hash_bytes,
            max_count=num_blocks,
            filter_before=True,
        )
        result = self._stub.List(request)
        tx_list: List[Block] = []
        for list_item in result:
            if not list_item.HasField('transaction'):
                break
            tx_proto = list_item.transaction
            block = tx_or_block_from_proto(tx_proto, storage=self)
            assert isinstance(block, Block)
            tx_list.append(block)
        return tx_list

    @convert_grpc_exceptions
    def get_all_sorted_txs(self, timestamp: int, count: int, offset: int) -> TransactionsIndex:
        self._check_connection()
        request = protos.SortedTxsRequest(
            timestamp=timestamp,
            count=count,
            offset=offset
        )
        result = self._stub.SortedTxs(request)
        tx_list = []
        for tx_proto in result:
            tx_list.append(TransactionIndexElement(tx_proto.timestamp, tx_proto.hash))

        all_sorted = TransactionsIndex()
        all_sorted.update(tx_list)
        return all_sorted


class TransactionStorageServicer(protos.TransactionStorageServicer):
    log = Logger()

    def __init__(self, tx_storage):
        self.storage = tx_storage
        # We must always disable weakref because it will run remotely, which means
        # each call will create a new instance of the block/transaction during the
        # deserialization process.
        self.storage._disable_weakref()

    @convert_hathor_exceptions
    def Exists(self, request: protos.ExistsRequest, context: _Context) -> protos.ExistsResponse:
        hash_bytes = request.hash
        exists = self.storage.transaction_exists(hash_bytes)
        return protos.ExistsResponse(exists=exists)

    @convert_hathor_exceptions
    def Get(self, request: protos.GetRequest, context: _Context) -> protos.GetResponse:
        hash_bytes = request.hash
        exclude_metadata = request.exclude_metadata

        tx = self.storage.get_transaction(hash_bytes)

        if exclude_metadata:
            del tx._metadata
        else:
            tx.get_metadata()

        return protos.GetResponse(transaction=tx.to_proto())

    @convert_hathor_exceptions
    def Save(self, request: protos.SaveRequest, context: _Context) -> protos.SaveResponse:
        from hathor.transaction import tx_or_block_from_proto

        tx_proto = request.transaction
        only_metadata = request.only_metadata

        result = protos.SaveResponse(saved=False)

        tx = tx_or_block_from_proto(tx_proto, storage=self.storage)
        self.storage.save_transaction(tx, only_metadata=only_metadata)
        result.saved = True

        return result

    @convert_hathor_exceptions
    def Remove(self, request: protos.RemoveRequest, context: _Context) -> protos.RemoveResponse:
        from hathor.transaction import tx_or_block_from_proto

        tx_proto = request.transaction

        result = protos.RemoveResponse(removed=False)

        tx = tx_or_block_from_proto(tx_proto, storage=self.storage)
        self.storage.remove_transaction(tx)
        result.removed = True

        return result

    @convert_hathor_exceptions
    def Count(self, request: protos.CountRequest, context: _Context) -> protos.CountResponse:
        tx_type = request.tx_type
        if tx_type == protos.ANY_TYPE:
            count = self.storage.get_count_tx_blocks()
        elif tx_type == protos.TRANSACTION_TYPE:
            count = self.storage.get_tx_count()
        elif tx_type == protos.BLOCK_TYPE:
            count = self.storage.get_block_count()
        else:
            raise ValueError('invalid tx_type %s' % (tx_type,))
        return protos.CountResponse(count=count)

    @convert_hathor_exceptions
    def LatestTimestamp(self, request: protos.LatestTimestampRequest,
                        context: _Context) -> protos.LatestTimestampResponse:
        return protos.LatestTimestampResponse(timestamp=self.storage.latest_timestamp)

    @convert_hathor_exceptions
    def FirstTimestamp(self, request: protos.FirstTimestampRequest,
                       context: _Context) -> protos.FirstTimestampResponse:
        return protos.FirstTimestampResponse(timestamp=self.storage.first_timestamp)

    @convert_hathor_exceptions
    def MarkAs(self, request, context):
        from hathor.transaction import tx_or_block_from_proto

        tx = tx_or_block_from_proto(request.transaction, storage=self.storage)

        if request.mark_type == protos.FOR_CACHING:
            if request.remove_mark:
                self.storage._del_from_cache(tx, relax_assert=request.relax_assert)
            else:
                self.storage._add_to_cache(tx)
        else:
            raise ValueError('invalid mark_type')

        # TODO: correct value for `marked`
        return protos.MarkAsResponse(marked=True)

    @convert_hathor_exceptions_generator
    def List(self, request: protos.ListRequest, context: _Context) -> Iterator[protos.ListItemResponse]:
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
                raise ValueError('invalid tx_type %s' % (request.tx_type,))
        elif request.time_filter == protos.ONLY_NEWER:
            if request.tx_type == protos.ANY_TYPE:
                raise NotImplementedError
            elif request.tx_type == protos.TRANSACTION_TYPE:
                tx_iter, has_more = self.storage.get_newer_txs_after(timestamp, hash_bytes, count)
            elif request.tx_type == protos.BLOCK_TYPE:
                tx_iter, has_more = self.storage.get_newer_blocks_after(timestamp, hash_bytes, count)
            else:
                raise ValueError('invalid tx_type %s' % (request.tx_type,))
        elif request.time_filter == protos.ONLY_OLDER:
            if request.tx_type == protos.ANY_TYPE:
                raise NotImplementedError
            elif request.tx_type == protos.TRANSACTION_TYPE:
                tx_iter, has_more = self.storage.get_older_txs_after(timestamp, hash_bytes, count)
            elif request.tx_type == protos.BLOCK_TYPE:
                tx_iter, has_more = self.storage.get_older_blocks_after(timestamp, hash_bytes, count)
            else:
                raise ValueError('invalid tx_type %s' % (request.tx_type,))
        elif request.time_filter == protos.NO_FILTER:
            if request.order_by == protos.ANY_ORDER:
                tx_iter = self.storage.get_all_transactions()
            elif request.order_by == protos.TOPOLOGICAL_ORDER:
                tx_iter = self.storage._topological_sort()
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
    def ListTips(self, request: protos.ListTipsRequest, context: _Context) -> Iterator[protos.Interval]:
        # XXX: using HasField (and oneof) to differentiate None from 0, which is very important in this context
        timestamp = None
        if request.HasField('timestamp'):
            timestamp = request.timestamp

        if request.tx_type == protos.ANY_TYPE:
            tx_intervals = self.storage.get_all_tips(timestamp)
        elif request.tx_type == protos.TRANSACTION_TYPE:
            tx_intervals = self.storage.get_tx_tips(timestamp)
        elif request.tx_type == protos.BLOCK_TYPE:
            tx_intervals = self.storage.get_block_tips(timestamp)
        else:
            raise ValueError('invalid tx_type %s' % (request.tx_type,))

        for interval in tx_intervals:
            yield protos.Interval(begin=interval.begin, end=interval.end, data=interval.data)

    @convert_hathor_exceptions_generator
    def ListNewest(self, request: protos.ListNewestRequest, context: _Context) -> Iterator[protos.ListItemResponse]:
        has_more = False
        if request.tx_type == protos.ANY_TYPE:
            raise NotImplementedError
        elif request.tx_type == protos.TRANSACTION_TYPE:
            tx_list, has_more = self.storage.get_newest_txs(request.count)
        elif request.tx_type == protos.BLOCK_TYPE:
            tx_list, has_more = self.storage.get_newest_blocks(request.count)
        else:
            raise ValueError('invalid tx_type %s' % (request.tx_type,))

        for tx in tx_list:
            yield protos.ListItemResponse(transaction=tx.to_proto())
        yield protos.ListItemResponse(has_more=has_more)

    @convert_hathor_exceptions_generator
    def SortedTxs(self, request: protos.SortedTxsRequest, context: _Context) -> Iterator[protos.Transaction]:
        timestamp = request.timestamp
        offset = request.offset
        count = request.count

        txs_index = self.storage.get_all_sorted_txs(timestamp, count, offset)
        for tx_element in txs_index[:]:
            yield protos.Transaction(timestamp=tx_element.timestamp, hash=tx_element.hash)


def create_transaction_storage_server(server: grpc.Server, tx_storage: TransactionStorage,
                                      port: Optional[int] = None) -> Tuple[protos.TransactionStorageServicer, int]:
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
    assert port is not None
    return servicer, port
