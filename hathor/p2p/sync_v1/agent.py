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

import base64
import struct
from math import inf
from typing import TYPE_CHECKING, Any, Callable, Generator, Iterator, Optional
from weakref import WeakSet

from structlog import get_logger
from twisted.internet.defer import CancelledError, Deferred, inlineCallbacks
from twisted.internet.interfaces import IDelayedCall

from hathor.conf.get_settings import get_global_settings
from hathor.p2p.messages import GetNextPayload, GetTipsPayload, NextPayload, ProtocolMessages, TipsPayload
from hathor.p2p.sync_agent import SyncAgent
from hathor.p2p.sync_v1.downloader import Downloader
from hathor.reactor import ReactorProtocol as Reactor
from hathor.transaction import BaseTransaction
from hathor.transaction.base_transaction import tx_or_block_from_bytes
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.util import json_dumps, json_loads

logger = get_logger()

if TYPE_CHECKING:
    from twisted.python.failure import Failure  # noqa: F401

    from hathor.p2p.protocol import HathorProtocol  # noqa: F401
    from hathor.p2p.rate_limiter import RateLimiter


def _get_deps(tx: BaseTransaction) -> Iterator[bytes]:
    """ Method to get dependencies of a block/transaction.
    """
    for h in tx.parents:
        yield h
    for txin in tx.inputs:
        yield txin.tx_id


class NodeSyncTimestamp(SyncAgent):
    """ An algorithm to sync the DAG between two peers using the timestamp of the transactions.

    This algorithm must assume that a new item may arrive while it is running. The item's timestamp
    may be recent or old, changing the tips of any timestamp.
    """
    name: str = 'node-sync-timestamp'

    MAX_HASHES: int = 40

    def __init__(self, protocol: 'HathorProtocol', downloader: Downloader, reactor: Reactor) -> None:
        """
        :param protocol: Protocol of the connection.
        :type protocol: HathorProtocol

        :param reactor: Reactor to schedule later calls. (default=twisted.internet.reactor)
        :type reactor: Reactor
        """
        self._settings = get_global_settings()
        self.protocol = protocol
        self.manager = protocol.node
        self.downloader = downloader

        self.reactor: Reactor = reactor

        # Rate limit for this connection.
        assert protocol.connections is not None
        self.global_rate_limiter: 'RateLimiter' = protocol.connections.rate_limiter
        self.GlobalRateLimiter = protocol.connections.GlobalRateLimiter

        self.call_later_id: Optional[IDelayedCall] = None
        self.call_later_interval: int = 1  # seconds

        # Keep track of call laters.
        self._send_tips_call_later: list[IDelayedCall] = []

        # Timestamp of the peer's latest block (according to the peer itself)
        self.peer_timestamp: int = 0

        # Latest timestamp in which we're synced.
        # This number may decrease if a new transaction/block arrives in a timestamp smaller than it.
        self.synced_timestamp: int = 0

        # Latest data timestamp of the peer.
        self.previous_timestamp: int = 0

        # Latest deferred waiting for a reply.
        self.deferred_by_key: dict[str, Deferred[Any]] = {}

        # Maximum difference between our latest timestamp and synced timestamp to consider
        # that the peer is synced (in seconds).
        self.sync_threshold: int = self._settings.P2P_SYNC_THRESHOLD

        # Indicate whether the sync manager has been started.
        self._started: bool = False

        # Indicate whether the synchronization is enabled.
        # When the sync is disabled, it will keep the last synced_timestamp.
        self.is_enabled: bool = False

        # Indicate whether the synchronization is running.
        self.is_running: bool = False

        # Create logger with context
        self.log = logger.new(**self.protocol.get_logger_context())

    def get_status(self):
        """ Return the status of the sync.
        """
        return {
            'is_enabled': self.is_enabled,
            'latest_timestamp': self.peer_timestamp,
            'synced_timestamp': self.synced_timestamp,
        }

    def get_cmd_dict(self) -> dict[ProtocolMessages, Callable[[str], None]]:
        """ Return a dict of messages.
        """
        return {
            ProtocolMessages.GET_DATA: self.handle_get_data,
            ProtocolMessages.DATA: self.handle_data,
            ProtocolMessages.GET_TIPS: self.handle_get_tips,
            ProtocolMessages.TIPS: self.handle_tips,
            ProtocolMessages.GET_NEXT: self.handle_get_next,
            ProtocolMessages.NEXT: self.handle_next,
            ProtocolMessages.NOT_FOUND: self.handle_not_found,
        }

    def is_started(self) -> bool:
        return self._started

    def start(self) -> None:
        """ Start sync.
        """
        if self._started:
            raise Exception('NodeSyncTimestamp is already running')
        self._started = True
        self.next_step()

    def stop(self) -> None:
        """ Stop sync.
        """
        if not self._started:
            raise Exception('NodeSyncTimestamp is already stopped')
        self._started = False
        if self.call_later_id and self.call_later_id.active():
            self.call_later_id.cancel()
        for call_later in self._send_tips_call_later:
            if call_later.active():
                call_later.cancel()
        # XXX: force remove this connection from _all_ pending downloads
        self.downloader.drop_connection(self)

    # XXX[jansegre]: maybe we should rename this to `out_of_sync` and invert the condition, would be easier to
    #                understand its usage on `send_tx_to_peer_if_possible` IMO
    def is_synced(self) -> bool:
        """ Test whether we have sent (or received) txs in storage to/from the remote peer up a certain threshold.

        When `True` we will send any new tx to the remote peer, since we're confident it can process it. When `False`
        we will have to explicitly check if we have synced up to the parents of the new tx to determine if we will send
        it.

        This condition is used to decide if we will send a new tx to that peer, but this isn't the only requirement.
        See the `send_tx_to_peer_if_possible` method for the exact process and to understand why this condition has to
        be this way.
        """
        return self.manager.tx_storage.latest_timestamp - self.synced_timestamp <= self.sync_threshold

    def is_errored(self) -> bool:
        # XXX: this sync manager does not have an error state, this method exists for API parity with sync-v2
        return False

    def send_tx_to_peer_if_possible(self, tx: BaseTransaction) -> None:
        if not self.is_enabled:
            return
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

        self.send_data(tx)

    def get_peer_next(self, timestamp: Optional[int] = None, offset: int = 0) -> Deferred[NextPayload]:
        """ A helper that returns a deferred that is called when the peer replies.

        :param timestamp: Timestamp of the GET-NEXT message
        :type timestamp: int

        :rtype: Deferred
        """
        key = 'next'
        if self.deferred_by_key.get(key, None) is not None:
            raise Exception('latest_deferred is not None')
        self.send_get_next(timestamp, offset)
        deferred: Deferred[NextPayload] = Deferred()
        self.deferred_by_key[key] = deferred
        return deferred

    def get_peer_tips(self, timestamp: Optional[int] = None, include_hashes: bool = False,
                      offset: int = 0) -> Deferred[TipsPayload]:
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
        deferred: Deferred[TipsPayload] = Deferred()
        self.deferred_by_key[key] = deferred
        return deferred

    def get_data(self, hash_bytes: bytes) -> Deferred:
        """ A helper that returns a deferred that is called when the peer replies.

        :param hash_bytes: Hash of the data to be downloaded
        :type hash_bytes: bytes(hash)

        :rtype: Deferred
        """
        d = self.downloader.get_tx(hash_bytes, self)
        d.addCallback(self.on_tx_success)
        d.addErrback(self.on_get_data_failed, hash_bytes)
        return d

    def request_data(self, hash_bytes: bytes) -> Deferred[BaseTransaction]:
        key = self.get_data_key(hash_bytes)
        if self.deferred_by_key.get(key, None) is not None:
            raise Exception('latest_deferred is not None')
        self.send_get_data(hash_bytes.hex())
        deferred: Deferred[BaseTransaction] = Deferred()
        self.deferred_by_key[key] = deferred
        # In case the deferred fails we just remove it from the dictionary
        deferred.addErrback(self.remove_deferred, hash_bytes)
        return deferred

    @inlineCallbacks
    def sync_from_timestamp(self, next_timestamp: int) -> Generator[Deferred, Any, None]:
        """ Download all unknown hashes until synced timestamp reaches `timestamp`.
        It assumes that we're synced in all timestamps smaller than `next_timestamp`.

        :param next_timestamp: Timestamp to start the sync
        """
        self.log.debug('sync start', ts=next_timestamp)
        assert next_timestamp < inf
        pending: WeakSet[Deferred] = WeakSet()
        next_offset = 0
        while True:
            payload: NextPayload = (yield self.get_peer_next(next_timestamp, offset=next_offset))
            self.log.debug('next payload', ts=payload.timestamp, next_ts=payload.next_timestamp,
                           next_offset=payload.next_offset, hashes=len(payload.hashes))
            count = 0
            for h in payload.hashes:
                if not self.manager.tx_storage.transaction_exists(h):
                    pending.add(self.get_data(h))
                    count += 1
            self.log.debug('...', next_ts=next_timestamp, count=count, pending=len(pending))
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
    def find_synced_timestamp(self) -> Generator[Deferred, Any, Optional[int]]:
        """ Search for the highest timestamp in which we are synced.

        It uses an exponential search followed by a binary search.
        """
        self.log.debug('find synced timestamp')
        tips: TipsPayload = (yield self.get_peer_tips())
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
        local_merkle_tree, _ = self.manager.tx_storage.get_merkle_tree(cur)
        step = 1
        while tips.merkle_tree != local_merkle_tree:
            if cur <= self.manager.tx_storage.first_timestamp:
                raise Exception(
                    'We cannot go before genesis. Peer is probably running with wrong configuration or database.'
                )
            prev_cur = cur
            assert self.manager.tx_storage.first_timestamp > 0
            cur = max(cur - step, self.manager.tx_storage.first_timestamp)
            tips = (yield self.get_peer_tips(cur))
            local_merkle_tree, _ = self.manager.tx_storage.get_merkle_tree(cur)
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
            tips = (yield self.get_peer_tips(mid))
            local_merkle_tree, _ = self.manager.tx_storage.get_merkle_tree(mid)
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
        self.log.debug('synced', latest_ts=self.peer_timestamp, synced_at=self.synced_timestamp)
        return self.synced_timestamp + 1

    @inlineCallbacks
    def _next_step(self) -> Generator[Deferred, Any, None]:
        """ Run the next step to keep nodes synced.
        """
        if not self.is_enabled:
            self.log.debug('sync is disabled')
            return
        if not self.is_running or not self._started:
            self.log.debug('already stopped')
            return
        next_timestamp: int = (yield self.find_synced_timestamp())
        self.log.debug('_next_step', next_timestamp=next_timestamp)
        if next_timestamp is None:
            return
        yield self.sync_from_timestamp(next_timestamp)

    @inlineCallbacks
    def next_step(self) -> Generator[Deferred, Any, None]:
        """ Execute next step and schedule next execution.
        """
        if self.is_running:
            # Already running...
            self.log.debug('already running')
            return

        if not self.is_enabled:
            self.log.debug('sync is disabled')
            self.schedule_next_step_call()
            return

        try:
            self.is_running = True
            yield self._next_step()
        except Exception:
            self.log.warn('_next_step error', exc_info=True)
            raise
        else:
            self.schedule_next_step_call()
        finally:
            self.is_running = False

    def schedule_next_step_call(self) -> None:
        """Schedule `next_step()` call."""
        if self.call_later_id and self.call_later_id.active():
            self.call_later_id.cancel()
        self.call_later_id = self.reactor.callLater(self.call_later_interval, self.next_step)

    def send_message(self, cmd: ProtocolMessages, payload: Optional[str] = None) -> None:
        """ Helper to send a message.
        """
        assert self.protocol.state is not None
        self.protocol.state.send_message(cmd, payload)

    def send_get_next(self, timestamp: Optional[int], offset: int = 0) -> None:
        """ Send a GET-NEXT message.
        """
        # XXX: is `timestamp = None` actually valid?
        payload = json_dumps(dict(
            timestamp=timestamp,
            offset=offset,
        ))
        self.send_message(ProtocolMessages.GET_NEXT, payload)

    def handle_get_next(self, payload: str) -> None:
        """ Handle a received GET-NEXT message.
        """
        data = json_loads(payload)
        args = GetNextPayload(**data)
        self.send_next(args.timestamp, args.offset)

    def send_next(self, timestamp: int, offset: int = 0) -> None:
        """ Send a NEXT message.
        """
        from hathor.indexes.timestamp_index import RangeIdx
        count = self.MAX_HASHES

        assert self.manager.tx_storage.indexes is not None
        from_idx = RangeIdx(timestamp, offset)
        hashes, next_idx = self.manager.tx_storage.indexes.sorted_all.get_hashes_and_next_idx(from_idx, count)
        if next_idx is None:
            # this means we've reached the end and there's nothing else to sync
            next_timestamp, next_offset = inf, 0
        else:
            next_timestamp, next_offset = next_idx

        data = {
            'timestamp': timestamp,
            'next_timestamp': next_timestamp,
            'next_offset': next_offset,
            'hashes': [i.hex() for i in hashes],
        }
        self.send_message(ProtocolMessages.NEXT, json_dumps(data))

    def handle_next(self, payload: str) -> None:
        """ Handle a received NEXT messages.
        """
        data = json_loads(payload)
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
            payload = json_dumps(dict(
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
            data = json_loads(payload)
            args = GetTipsPayload(**data)
            self.send_tips(args.timestamp, args.include_hashes, args.offset)

    def send_tips(self, timestamp: Optional[int] = None, include_hashes: bool = False, offset: int = 0) -> None:
        """Try to send a TIPS message. If rate limit has been reached, it schedules to send it later."""

        # Filter for active delayed calls once one is executing
        self._send_tips_call_later = [
            call_later
            for call_later in self._send_tips_call_later
            if call_later.active()
        ]

        if not self.global_rate_limiter.add_hit(self.GlobalRateLimiter.SEND_TIPS):
            self.log.debug('send_tips throttled')
            if len(self._send_tips_call_later) >= self._settings.MAX_GET_TIPS_DELAYED_CALLS:
                self.protocol.send_error_and_close_connection(
                    'Too many GET_TIPS message'
                )
                return
            self._send_tips_call_later.append(
                self.reactor.callLater(
                    1, self.send_tips, timestamp, include_hashes, offset
                )
            )
            return

        self._send_tips(timestamp, include_hashes, offset)

    def _send_tips(self, timestamp: Optional[int] = None, include_hashes: bool = False, offset: int = 0) -> None:
        """ Send a TIPS message.
        """
        if timestamp is None:
            timestamp = self.manager.tx_storage.latest_timestamp

        # All tips
        # intervals = self.manager.tx_storage.get_all_tips(timestamp)
        # if len(intervals) == 0:
        #     raise Exception('No tips for timestamp {}'.format(timestamp))

        # Calculate list of hashes to be sent
        merkle_tree, hashes = self.manager.tx_storage.get_merkle_tree(timestamp)
        has_more = False

        if not include_hashes:
            hashes = []
        else:
            hashes = hashes[offset:]
            if len(hashes) > self.MAX_HASHES:
                hashes = hashes[:self.MAX_HASHES]
                has_more = True

        data = {
            'length': 0,  # len(intervals),
            'timestamp': timestamp,
            'merkle_tree': merkle_tree.hex(),
            'hashes': [h.hex() for h in hashes],
            'has_more': has_more,
        }

        self.send_message(ProtocolMessages.TIPS, json_dumps(data))

    def handle_tips(self, payload: str) -> None:
        """ Handle a received TIPS messages.
        """
        data = json_loads(payload)
        data['merkle_tree'] = bytes.fromhex(data['merkle_tree'])
        data['hashes'] = [bytes.fromhex(h) for h in data['hashes']]
        args = TipsPayload(**data)

        key = 'tips'
        deferred = self.deferred_by_key.pop(key, None)
        if deferred:
            deferred.callback(args)

    def send_get_data(self, hash_hex: str) -> None:
        """ Send a GET-DATA message, requesting the data of a given hash.
        """
        self.send_message(ProtocolMessages.GET_DATA, hash_hex)

    def handle_get_data(self, payload: str) -> None:
        """ Handle a received GET-DATA message.
        """
        hash_hex = payload
        # self.log.debug('handle_get_data', payload=hash_hex)
        try:
            tx = self.protocol.node.tx_storage.get_transaction(bytes.fromhex(hash_hex))
            self.send_data(tx)
        except TransactionDoesNotExist:
            # In case the tx does not exist we send a NOT-FOUND message
            self.send_message(ProtocolMessages.NOT_FOUND, hash_hex)

    def handle_not_found(self, payload: str) -> None:
        """ Handle a received NOT-FOUND message.
        """
        hash_hex = payload
        # We ask for the downloader to retry the request
        self.downloader.retry(bytes.fromhex(hash_hex))

    def send_data(self, tx: BaseTransaction) -> None:
        """ Send a DATA message.
        """
        self.log.debug('send tx', tx=tx.hash_hex)
        payload = base64.b64encode(tx.get_struct()).decode('ascii')
        self.send_message(ProtocolMessages.DATA, payload)

    def handle_data(self, payload: str) -> None:
        """ Handle a received DATA message.
        """
        if not payload:
            return
        data = base64.b64decode(payload)

        try:
            tx = tx_or_block_from_bytes(data)
        except struct.error:
            # Invalid data for tx decode
            return

        assert tx is not None

        self.log.debug('tx received from peer', tx=tx.hash_hex, peer=self.protocol.get_peer_id())

        if self.protocol.node.tx_storage.get_genesis(tx.hash):
            # We just got the data of a genesis tx/block. What should we do?
            # Will it reduce peer reputation score?
            return
        tx.storage = self.protocol.node.tx_storage

        key = self.get_data_key(tx.hash)
        deferred = self.deferred_by_key.pop(key, None)
        if deferred:
            # Adding to the DAG will be done after the downloader validates the correct order
            assert tx.timestamp is not None
            self.requested_data_arrived(tx.timestamp)
            deferred.callback(tx)
        elif self.manager.tx_storage.transaction_exists(tx.hash):
            # transaction already added to the storage, ignore it
            # XXX: maybe we could add a hash blacklist and punish peers propagating known bad txs
            self.manager.tx_storage.compare_bytes_with_local_tx(tx)
            return
        else:
            self.log.info('tx received in real time from peer', tx=tx.hash_hex, peer=self.protocol.get_peer_id())
            # If we have not requested the data, it is a new transaction being propagated
            # in the network, thus, we propagate it as well.
            result = self.manager.on_new_tx(tx, conn=self.protocol, propagate_to_peers=True)
            self.update_received_stats(tx, result)

    def update_received_stats(self, tx: 'BaseTransaction', result: bool) -> None:
        """ Update protocol metrics when receiving a new tx
        """
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

    def requested_data_arrived(self, timestamp: int) -> None:
        """ Update synced timestamp when a requested data arrives
        """
        if timestamp - 1 > self.synced_timestamp:
            self.synced_timestamp = timestamp - 1

    def get_data_key(self, hash_bytes: bytes) -> str:
        """ Return data key corresponding a tx to be used in the deferred dict
        """
        key = 'get-data-{}'.format(hash_bytes.hex())
        return key

    def remove_deferred(self, reason: 'Failure', hash_bytes: bytes) -> None:
        """ Remove the deferred from the deferred_by_key
            Used when a requested tx deferred fails for some reason (not found, or timeout)
        """
        key = self.get_data_key(hash_bytes)
        self.deferred_by_key.pop(key, None)

    def on_tx_success(self, tx: 'BaseTransaction') -> 'BaseTransaction':
        """ Callback for the deferred when we add a new tx to the DAG
        """
        # When we have multiple callbacks in a deferred
        # the parameter of the second callback is the return of the first
        # so I need to return the same tx to guarantee that all peers will receive it
        if tx:
            if self.manager.tx_storage.transaction_exists(tx.hash):
                self.manager.tx_storage.compare_bytes_with_local_tx(tx)
                success = True
            else:
                # Add tx to the DAG.
                success = self.manager.on_new_tx(tx)
            # Updating stats data
            self.update_received_stats(tx, success)
        return tx

    def on_get_data_failed(self, failure: 'Failure', hash_bytes: bytes) -> None:
        """ Method called when get_data deferred fails.
            We need this errback because otherwise the sync crashes when the deferred is canceled.
            We should just log a warning because it will continue the sync and will try to get this tx again.
        """
        log_func = self.log.debug if isinstance(failure.value, CancelledError) else self.log.warn
        log_func('failed to download tx', tx=hash_bytes.hex(), reason=failure)

    def is_sync_enabled(self) -> bool:
        """Return True if sync is enabled for this connection."""
        return self.is_enabled

    def enable_sync(self) -> None:
        """Enable sync for this connection."""
        self.is_enabled = True

    def disable_sync(self) -> None:
        """Disable sync for this connection."""
        self.is_enabled = False
