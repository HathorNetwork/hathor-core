import base64
import hashlib
import json
from collections import OrderedDict
from math import inf
from typing import TYPE_CHECKING, Callable, Dict, Iterator, List, Optional, Set, Tuple, Union, cast

from intervaltree.interval import Interval
from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.internet.interfaces import IDelayedCall, IProtocol, IPushProducer, IReactorCore
from twisted.internet.task import Clock
from twisted.logger import Logger
from zope.interface import implementer

from hathor.conf import HathorSettings
from hathor.p2p.messages import GetNextPayload, GetTipsPayload, NextPayload, ProtocolMessages, TipsPayload
from hathor.p2p.plugin import Plugin
from hathor.transaction import BaseTransaction
from hathor.transaction.base_transaction import tx_or_block_from_bytes
from hathor.transaction.storage.exceptions import TransactionDoesNotExist

settings = HathorSettings()

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol  # noqa: F401


@implementer(IPushProducer)
class SendDataPush:
    """ Prioritize blocks over transactions when pushing data to peers.
    """
    def __init__(self, node_sync: 'NodeSyncTimestamp'):
        self.node_sync = node_sync
        self.protocol: IProtocol = node_sync.protocol
        self.consumer = self.protocol.transport

        self.is_running: bool = False
        self.is_producing: bool = False

        self.queue: OrderedDict[bytes, Tuple[BaseTransaction, List[bytes]]] = OrderedDict()
        self.priority_queue: OrderedDict[bytes, Tuple[BaseTransaction, List[bytes]]] = OrderedDict()

        self.delayed_call = None

    def start(self) -> None:
        """ Start pushing data.
        """
        self.is_running = True
        self.consumer.registerProducer(self, True)
        self.resumeProducing()

    def stop(self) -> None:
        """ Stop pushing data.
        """
        self.is_running = False
        self.pauseProducing()
        self.consumer.unregisterProducer()

    def schedule_if_needed(self) -> None:
        """ Schedule `send_next` if needed.
        """
        if not self.is_running:
            return

        if not self.is_producing:
            return

        if self.delayed_call and self.delayed_call.active():
            return

        if len(self.queue) > 0 or len(self.priority_queue) > 0:
            self.delayed_call = self.node_sync.reactor.callLater(0, self.send_next)

    def _get_deps(self, tx: BaseTransaction) -> Iterator[bytes]:
        """ Internal method to get dependencies of a block/transaction.
        """
        for h in tx.parents:
            yield h
        for txin in tx.inputs:
            yield txin.tx_id

    def add(self, tx: BaseTransaction) -> None:
        """ Add a new block/transaction to be pushed.
        """
        assert tx.hash is not None
        if tx.is_block:
            self.add_to_priority(tx)
        else:
            deps = list(self._get_deps(tx))
            self.queue[tx.hash] = (tx, deps)
            self.schedule_if_needed()

    def add_to_priority(self, tx: BaseTransaction) -> None:
        """ Add a new block/transaction to be pushed with priority.
        """
        assert tx.hash is not None
        assert tx.hash not in self.queue
        if tx.hash in self.priority_queue:
            return
        deps = list(self._get_deps(tx))
        for h in deps:
            if h in self.queue:
                tx2, _ = self.queue.pop(h)
                self.add_to_priority(tx2)
        self.priority_queue[tx.hash] = (tx, deps)
        self.schedule_if_needed()

    def send_next(self) -> None:
        """ Push next block/transaction to peer.
        """
        assert self.is_running
        assert self.is_producing

        if len(self.priority_queue) > 0:
            # Send blocks first.
            _, (tx, _) = self.priority_queue.popitem(last=False)

        elif len(self.queue) > 0:
            # Otherwise, send in order.
            _, (tx, _) = self.queue.popitem(last=False)

        else:
            # Nothing to send.
            self.delayed_call = None
            return

        self.node_sync.send_data(tx)
        self.schedule_if_needed()

    def resumeProducing(self) -> None:
        """ This method is automatically called to resume pushing data.
        """
        self.is_producing = True
        self.schedule_if_needed()

    def pauseProducing(self) -> None:
        """ This method is automatically called to pause pushing data.
        """
        self.is_producing = False
        if self.delayed_call and self.delayed_call.active():
            self.delayed_call.cancel()

    def stopProducing(self) -> None:
        """ This method is automatically called to stop pushing data.
        """
        self.pauseProducing()
        self.queue.clear()
        self.priority_queue.clear()


class NodeSyncTimestamp(Plugin):
    """ An algorithm to sync the DAG between two peers using the timestamp of the transactions.

    This algorithm must assume that a new item may arrive while it is running. The item's timestamp
    may be recent or old, changing the tips of any timestamp.
    """
    log = Logger()

    MAX_HASHES = 40

    def __init__(self, protocol: 'HathorProtocol', reactor: Clock = None) -> None:
        """
        :param protocol: Protocol of the connection.
        :type protocol: HathorProtocol

        :param reactor: Reactor to schedule later calls. (default=twisted.internet.reactor)
        :type reactor: Reactor
        """
        self.protocol = protocol
        self.manager = protocol.node

        if reactor is None:
            from twisted.internet import reactor as twisted_reactor
            reactor = twisted_reactor
        self.reactor: IReactorCore = reactor

        self.call_later_id: Optional[IDelayedCall] = None
        self.call_later_interval: int = 1  # seconds

        self.peer_timestamp: int = 0

        self.send_data_queue: SendDataPush = SendDataPush(self)

        # Latest data timestamp of the peer.
        self.peer_merkle_hash: Optional[int] = None
        self.previous_timestamp: int = 0

        # Latest deferred waiting for a reply.
        self.deferred_by_key: Dict[str, Deferred] = {}

        # Latest timestamp in which we're synced.
        # This number may decrease if a new transaction/block arrives in a timestamp smaller than it.
        self.synced_timestamp: int = 0

        # Maximum difference between our latest timestamp and synced timestamp to consider
        # that the peer is synced (in seconds).
        self.sync_threshold: int = settings.P2P_SYNC_THRESHOLD

        # Indicate whether the synchronization is running.
        self.is_running: bool = False

    def get_status(self):
        """ Return the status of the sync.
        """
        return {
            'latest_timestamp': self.peer_timestamp,
            'synced_timestamp': self.synced_timestamp,
        }

    @property
    def short_peer_id(self) -> str:
        """ Returns the id of the peer (only 7 first chars)
        """
        assert self.protocol.peer is not None
        assert self.protocol.peer.id is not None
        return self.protocol.peer.id[:7]

    def get_cmd_dict(self) -> Dict[ProtocolMessages, Callable]:
        """ Return a dict of messages of the plugin.
        """
        return {
            ProtocolMessages.NOTIFY_DATA: self.handle_notify_data,
            ProtocolMessages.GET_DATA: self.handle_get_data,
            ProtocolMessages.DATA: self.handle_data,
            ProtocolMessages.GET_TIPS: self.handle_get_tips,
            ProtocolMessages.TIPS: self.handle_tips,
            ProtocolMessages.GET_NEXT: self.handle_get_next,
            ProtocolMessages.NEXT: self.handle_next,
        }

    def start(self) -> None:
        """ Start sync.
        """
        if self.send_data_queue:
            self.send_data_queue.start()
        self.next_step()

    def stop(self) -> None:
        """ Stop sync.
        """
        if self.send_data_queue:
            self.send_data_queue.stop()
        if self.call_later_id and self.call_later_id.active():
            self.call_later_id.cancel()

    def is_synced(self) -> bool:
        """ Return True if we are synced.
        """
        return self.manager.tx_storage.latest_timestamp - self.synced_timestamp <= self.sync_threshold

    def send_tx_to_peer_if_possible(self, tx: BaseTransaction) -> None:
        if self.peer_timestamp is None:
            return
        if self.synced_timestamp is None:
            return

        if not self.is_synced():
            # When a peer has not synced yet, we just propagate the transactions whose
            # parents' timestamps are below synced_timestamp, i.e., we know that the peer
            # has all the parents.
            for parent_hash in tx.parents:
                parent = self.protocol.node.tx_storage.get_transaction(parent_hash)
                if parent.timestamp > self.synced_timestamp:
                    return

        if self.send_data_queue:
            self.send_data_queue.add(tx)
        else:
            self.send_data(tx)

    def get_merkle_tree(self, timestamp: int) -> Tuple[bytes, List[bytes]]:
        """ Generate a hash to check whether the DAG is the same at that timestamp.

        :rtype: Tuple[bytes(hash), List[bytes(hash)]]
        """
        intervals = self.manager.tx_storage.get_all_tips(timestamp)
        return self.calculate_merkle_tree(intervals)

    def calculate_merkle_tree(self, intervals: Set[Interval]) -> Tuple[bytes, List[bytes]]:
        """ Generate a hash of the transactions at the intervals

        :rtype: Tuple[bytes(hash), List[bytes(hash)]]
        """
        hashes = [x.data for x in intervals]
        hashes.sort()

        merkle = hashlib.sha256()
        for h in hashes:
            merkle.update(h)

        return merkle.digest(), hashes

    def get_peer_next(self, timestamp: Optional[int] = None, offset: int = 0) -> Deferred:
        """ A helper that returns a deferred that is called when the peer replies.

        :param timestamp: Timestamp of the GET-NEXT message
        :type timestamp: int

        :rtype: Deferred
        """
        key = 'next'
        if self.deferred_by_key.get(key, None) is not None:
            raise Exception('latest_deferred is not None')
        self.send_get_next(timestamp, offset)
        deferred = Deferred()
        self.deferred_by_key[key] = deferred
        return deferred

    def get_peer_tips(self, timestamp: Optional[int] = None, include_hashes: bool = False,
                      offset: int = 0) -> Deferred:
        """ A helper that returns a deferred that is called when the peer replies.

        :param timestamp: Timestamp of the GET-TIPS message
        :type timestamp: int

        :param include_hashes: Indicates whether the tx/blk hashes should be included
        :type include_hashes: bool

        :rtype: Deferred
        """
        key = 'tips'
        if self.deferred_by_key.get(key, None) is not None:
            raise Exception('latest_deferred is not None')
        self.send_get_tips(timestamp, include_hashes, offset)
        deferred = Deferred()
        self.deferred_by_key[key] = deferred
        return deferred

    def get_data(self, hash_bytes: bytes) -> Deferred:
        """ A helper that returns a deferred that is called when the peer replies.

        :param hash_bytes: Hash of the data to be downloaded
        :type hash_bytes: bytes(hash)

        :rtype: Deferred
        """
        key = 'get-data-{}'.format(hash_bytes.hex())
        if self.deferred_by_key.get(key, None) is not None:
            raise Exception('latest_deferred is not None')
        self.send_get_data(hash_bytes.hex())
        deferred = Deferred()
        self.deferred_by_key[key] = deferred
        return deferred

    @inlineCallbacks
    def sync_from_timestamp(self, next_timestamp: int) -> Iterator[Deferred]:
        """ Download all unknown hashes until synced timestamp reaches `timestamp`.
        It assumes that we're synced in all timestamps smaller than `next_timestamp`.

        :param next_timestamp: Timestamp to start the sync
        """
        self.log.debug('sync-{p} Sync starting at {next_timestamp}', p=self.short_peer_id,
                       next_timestamp=next_timestamp)
        assert next_timestamp < inf
        pending = []
        next_offset = 0
        while True:
            payload = cast(NextPayload, (yield self.get_peer_next(next_timestamp, offset=next_offset)))
            self.log.debug('sync-{p} NextPayload ts={ts} next_ts={nts} next_offset={noff} hashes={hs}',
                           p=self.short_peer_id, ts=payload.timestamp, nts=payload.next_timestamp,
                           noff=payload.next_offset, hs=len(payload.hashes))
            count = 0
            for h in payload.hashes:
                if not self.manager.tx_storage.transaction_exists(h):
                    pending.append(self.get_data(h))
                    count += 1
            self.log.debug('sync-{p} next_ts={ts} count={c} pending={pen}', p=self.short_peer_id,
                           ts=next_timestamp, c=count, pen=len(pending))
            if next_timestamp != payload.next_timestamp and count == 0:
                break
            next_timestamp = payload.next_timestamp
            next_offset = payload.next_offset
            if next_timestamp == inf:
                break
            if next_timestamp > self.peer_timestamp:
                break
        for deferred in pending:
            yield deferred

    @inlineCallbacks
    def find_synced_timestamp(self) -> Iterator[Union[Iterator, Iterator[Deferred]]]:
        """ Search for the highest timestamp in which we are synced.

        It uses an exponential search followed by a binary search.
        """
        # self.log.debug('Running find_synced_timestamp...')
        tips = cast(TipsPayload, (yield self.get_peer_tips()))
        if self.peer_timestamp:
            # Peer's timestamp cannot go backwards.
            assert tips.timestamp >= self.peer_timestamp, '{} < {}'.format(tips.timestamp, self.peer_timestamp)
        self.peer_timestamp = tips.timestamp

        # Assumption: Both exponential search and binary search are safe to run even when new
        #             items are arriving in the network.

        # Exponential search to find an interval.
        # Maximum of ceil(log(k)), where k is the number of items between the new one and the latest item.
        prev_cur = None
        cur = self.peer_timestamp
        local_merkle_tree, _ = self.get_merkle_tree(cur)
        step = 1
        while tips.merkle_tree != local_merkle_tree:
            if cur <= self.manager.tx_storage.first_timestamp:
                raise Exception('We cannot go before genesis. Is it an attacker?!')
            prev_cur = cur
            cur = max(cur - step, self.manager.tx_storage.first_timestamp)
            tips = cast(TipsPayload, (yield self.get_peer_tips(cur)))
            local_merkle_tree, _ = self.get_merkle_tree(cur)
            step *= 2

        # Here, both nodes are synced at timestamp `cur` and not synced at timestamp `prev_cur`.
        if prev_cur is None:
            self.synced_timestamp = cur
            return None

        # Binary search to find inside the interval.
        # Maximum of ceil(log(k)) - 1, where k is the number of items between the new one and the latest item.
        # During the binary search, we are synced at `low` and not synced at `high`.
        low = cur
        high = prev_cur
        while high - low > 1:
            mid = (low + high + 1) // 2
            tips = cast(TipsPayload, (yield self.get_peer_tips(mid)))
            local_merkle_tree, _ = self.get_merkle_tree(mid)
            if tips.merkle_tree == local_merkle_tree:
                low = mid
            else:
                high = mid

        # Synced timestamp found.
        self.synced_timestamp = low
        assert self.synced_timestamp <= self.peer_timestamp

        if low == high:
            assert low == tips.timestamp
            return None

        assert low + 1 == high
        self.log.debug('sync-{log_source.short_peer_id} Synced at {log_source.synced_timestamp} \
                       (latest timestamp {log_source.peer_timestamp})')
        return self.synced_timestamp + 1

    @inlineCallbacks
    def _next_step(self) -> Iterator[Union[Iterator, Iterator[Deferred]]]:
        """ Run the next step to keep nodes synced.
        """
        next_timestamp = yield self.find_synced_timestamp()
        self.log.debug('sync-{p} _next_step next_timestamp={ts}', p=self.short_peer_id, ts=next_timestamp)
        if next_timestamp is None:
            return

        yield self.sync_from_timestamp(next_timestamp)

    @inlineCallbacks
    def next_step(self) -> Iterator[Union[Iterator, Iterator[Deferred]]]:
        """ Execute next step and schedule next execution.
        """
        if self.is_running:
            # Already running...
            # self.log.debug('Already running: {log_source.is_running}')
            return

        try:
            self.is_running = True
            yield self._next_step()
        except Exception as e:
            self.log.warn('Exception: {e!r}', e=e)
            raise
        else:
            if self.call_later_id and self.call_later_id.active():
                self.call_later_id.cancel()
            self.call_later_id = self.reactor.callLater(self.call_later_interval, self.next_step)
        finally:
            self.is_running = False

    def send_message(self, cmd: ProtocolMessages, payload: Optional[str] = None) -> None:
        """ Helper to send a message.
        """
        assert self.protocol.state is not None
        self.protocol.state.send_message(cmd, payload)

    def send_get_next(self, timestamp: Optional[int], offset: int = 0) -> None:
        """ Send a GET-NEXT message.
        """
        # XXX: is `timestamp = None` actually valid?
        payload = json.dumps(dict(
            timestamp=timestamp,
            offset=offset,
        ))
        self.send_message(ProtocolMessages.GET_NEXT, payload)

    def handle_get_next(self, payload: str) -> None:
        """ Handle a received GET-NEXT message.
        """
        data = json.loads(payload)
        args = GetNextPayload(**data)
        self.send_next(args.timestamp, args.offset)

    def send_next(self, timestamp: int, offset: int = 0) -> None:
        """ Send a NEXT message.
        """
        count = self.MAX_HASHES

        all_sorted = self.manager.tx_storage.get_all_sorted_txs(timestamp, count, offset)
        ret_txs = all_sorted[offset:offset+count]
        hashes = [tx.hash.hex() for tx in ret_txs]

        if len(ret_txs) < count:
            # this means we've reached the end and there's nothing else to sync
            next_offset = 0
            next_timestamp = inf
        else:
            next_offset = offset + count
            next_timestamp = ret_txs[-1].timestamp
            if next_timestamp != timestamp:
                next_idx = all_sorted.find_first_at_timestamp(next_timestamp)
                next_offset -= next_idx

        data = {
            'timestamp': timestamp,
            'next_timestamp': next_timestamp,
            'next_offset': next_offset,
            'hashes': hashes,
        }
        self.send_message(ProtocolMessages.NEXT, json.dumps(data))

    def handle_next(self, payload: str) -> None:
        """ Handle a received NEXT messages.
        """
        data = json.loads(payload)
        data['hashes'] = [bytes.fromhex(h) for h in data['hashes']]
        args = NextPayload(**data)

        key = 'next'
        deferred = self.deferred_by_key.pop(key, None)
        if deferred:
            deferred.callback(args)

    def send_get_tips(self, timestamp: Optional[int] = None, include_hashes: bool = False, offset: int = 0) -> None:
        """ Send a GET-TIPS message.
        """
        if timestamp is None:
            self.send_message(ProtocolMessages.GET_TIPS)
        else:
            payload = json.dumps(dict(
                timestamp=timestamp,
                include_hashes=include_hashes,
                offset=offset,
            ))
            self.send_message(ProtocolMessages.GET_TIPS, payload)

    def handle_get_tips(self, payload: str) -> None:
        """ Handle a received GET-TIPS message.
        """
        if not payload:
            self.send_tips()
        else:
            data = json.loads(payload)
            args = GetTipsPayload(**data)
            self.send_tips(args.timestamp, args.include_hashes, args.offset)

    def send_tips(self, timestamp: Optional[int] = None, include_hashes: bool = False, offset: int = 0) -> None:
        """ Send a TIPS message.
        """
        if timestamp is None:
            timestamp = self.manager.tx_storage.latest_timestamp

        # All tips
        intervals = self.manager.tx_storage.get_all_tips(timestamp)

        if len(intervals) == 0:
            raise Exception('No tips for timestamp {}'.format(timestamp))

        # Calculate list of hashes to be sent
        merkle_tree, hashes = self.calculate_merkle_tree(intervals)
        has_more = False

        if not include_hashes:
            hashes = []
        else:
            hashes = hashes[offset:]
            if len(hashes) > self.MAX_HASHES:
                hashes = hashes[:self.MAX_HASHES]
                has_more = True

        data = {
            'length': len(intervals),
            'timestamp': timestamp,
            'merkle_tree': merkle_tree.hex(),
            'hashes': [h.hex() for h in hashes],
            'has_more': has_more,
        }

        self.send_message(ProtocolMessages.TIPS, json.dumps(data))

    def handle_tips(self, payload: str) -> None:
        """ Handle a received TIPS messages.
        """
        data = json.loads(payload)
        data['merkle_tree'] = bytes.fromhex(data['merkle_tree'])
        data['hashes'] = [bytes.fromhex(h) for h in data['hashes']]
        args = TipsPayload(**data)

        key = 'tips'
        deferred = self.deferred_by_key.pop(key, None)
        if deferred:
            deferred.callback(args)

    def send_notify_data(self, tx):
        """ Send a NOTIFY-DATA message, notifying a peer about a new hash.

        TODO Send timestamp and parents.
        """
        payload = '{} {} {}'.format(
            tx.timestamp,
            tx.hash.hex(),
            json.dumps([x.hex() for x in tx.parents]),
        )
        self.send_message(ProtocolMessages.NOTIFY_DATA, payload)

    def handle_notify_data(self, payload):
        """ Handle a NOTIFY-DATA message, downloading the new data when we don't have it.
        """
        timestamp, _, payload2 = payload.partition(' ')
        hash_hex, _, parents_json = payload2.partition(' ')
        parents = json.loads(parents_json)

        if self.manager.tx_storage.transaction_exists(bytes.fromhex(hash_hex)):
            return

        for parent_hash in parents:
            if not self.manager.tx_storage.transaction_exists(bytes.fromhex(parent_hash)):
                # Are we out-of-sync with this peer?
                return

        self.send_get_data(hash_hex)

    def send_get_data(self, hash_hex: str) -> None:
        """ Send a GET-DATA message, requesting the data of a given hash.
        """
        self.send_message(ProtocolMessages.GET_DATA, hash_hex)

    def handle_get_data(self, payload: str) -> None:
        """ Handle a received GET-DATA message.
        """
        hash_hex = payload
        # self.log.debug('handle_get_data {hash_hex}', hash_hex=hash_hex)
        try:
            tx = self.protocol.node.tx_storage.get_transaction(bytes.fromhex(hash_hex))
            self.send_data(tx)
        except TransactionDoesNotExist:
            # TODO Send NOT-FOUND?
            pass

    def send_data(self, tx: BaseTransaction) -> None:
        """ Send a DATA message.
        """
        # self.log.debug('Sending {tx.hash_hex}...', tx=tx)
        payload = base64.b64encode(tx.get_struct()).decode('ascii')
        self.send_message(ProtocolMessages.DATA, payload)

    def handle_data(self, payload: str) -> None:
        """ Handle a received DATA message.
        """
        if not payload:
            return
        data = base64.b64decode(payload)
        tx = tx_or_block_from_bytes(data)

        assert tx.hash is not None
        if self.protocol.node.tx_storage.get_genesis(tx.hash):
            # We just got the data of a genesis tx/block. What should we do?
            # Will it reduce peer reputation score?
            return
        tx.storage = self.protocol.node.tx_storage
        assert tx.hash is not None

        key = 'get-data-{}'.format(tx.hash.hex())
        deferred = self.deferred_by_key.pop(key, None)
        if deferred:
            # If we have requested the data, we do not propagate to our peers.
            propagate_to_peers = False
        else:
            # If we have not requested the data, it is a new transaction being propagated
            # in the network, thus, we propagate it as well.
            propagate_to_peers = True

        result = self.manager.on_new_tx(tx, conn=self.protocol, propagate_to_peers=propagate_to_peers)

        # Update statistics.
        if result:
            if tx.is_block:
                self.protocol.metrics.received_blocks += 1
            else:
                self.protocol.metrics.received_txs += 1
        else:
            if tx.is_block:
                self.protocol.metrics.discarded_blocks += 1
            else:
                self.protocol.metrics.discarded_txs += 1

        if deferred:
            assert tx.timestamp is not None
            if tx.timestamp - 1 > self.synced_timestamp:
                self.synced_timestamp = tx.timestamp - 1
            deferred.callback((tx, result))
