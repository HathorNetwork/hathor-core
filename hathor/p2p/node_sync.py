import base64
import hashlib
import json
from math import inf
from typing import TYPE_CHECKING, Callable, Dict, Iterator, List, Optional, Tuple, Union, cast

from twisted.internet.defer import Deferred, inlineCallbacks
from twisted.internet.interfaces import IDelayedCall, IReactorCore
from twisted.internet.task import Clock
from twisted.logger import Logger

from hathor.p2p.messages import GetNextPayload, GetTipsPayload, NextPayload, ProtocolMessages, TipsPayload
from hathor.p2p.plugin import Plugin
from hathor.transaction import BaseTransaction, Block, Transaction
from hathor.transaction.storage.exceptions import TransactionDoesNotExist

if TYPE_CHECKING:
    from hathor.p2p.protocol import HathorProtocol


class NodeSyncTimestamp(Plugin):
    """ An algorithm to sync the DAG between two peers using the timestamp of the transactions.
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

        # Latest data timestamp of the peer.
        self.peer_timestamp: int = 0
        self.peer_merkle_hash: Optional[int] = None
        self.next_timestamp: int = 0
        self.previous_timestamp: int = 0

        # Latest deferred waiting for a reply.
        self.deferred_by_key: Dict[str, Deferred] = {}

        # Latest timestamp in which we're synced.
        self.synced_timestamp: int = 0

        self.is_running: bool = False

    def get_status(self):
        """ Return the status of the sync.
        """
        return {
            'latest_timestamp': self.peer_timestamp,
            'synced_timestamp': self.synced_timestamp,
        }

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
        self.next_step()

    def stop(self) -> None:
        """ Stop sync.
        """
        if self.call_later_id and self.call_later_id.active():
            self.call_later_id.cancel()

    def send_tx_to_peer_if_possible(self, tx: BaseTransaction) -> None:
        if self.peer_timestamp is None:
            return
        if self.synced_timestamp is None:
            return
        # for parent_hash in tx.parents:
        #     parent = self.protocol.node.tx_storage.get_transaction(parent_hash)
        #     if parent.timestamp > self.synced_timestamp:
        #         # print('send_tx_to_peer_if_possible(): discarded')
        #         return
        self.send_data(tx)

    def get_merkle_tree(self, timestamp: int) -> Tuple[bytes, List[bytes]]:
        """ Generate a hash to check whether the DAG is the same at that timestamp.

        :rtype: Tuple[bytes(hash), List[bytes(hash)]]
        """
        tx_intervals = self.manager.tx_storage.get_tx_tips(timestamp)
        blk_intervals = self.manager.tx_storage.get_block_tips(timestamp)

        hashes = [x.data for x in tx_intervals]
        hashes.extend(x.data for x in blk_intervals)
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
    def find_synced_timestamp(self) -> Iterator[Union[Iterator, Iterator[Deferred]]]:
        """ Search time highest timestamp in which we are synced.

        It uses an exponential search followed by a binary search.
        """
        # self.log.debug('Running find_synced_timestamp...')
        tips = cast(TipsPayload, (yield self.get_peer_tips()))
        if self.peer_timestamp:
            assert tips.timestamp >= self.peer_timestamp, '{} < {}'.format(tips.timestamp, self.peer_timestamp)
        self.peer_timestamp = tips.timestamp

        # Exponential search to find an interval.
        cur = min(self.manager.tx_storage.latest_timestamp, tips.timestamp)
        local_merkle_tree, _ = self.get_merkle_tree(cur)
        step = 1
        while tips.merkle_tree != local_merkle_tree:
            if cur <= self.manager.tx_storage.first_timestamp:
                raise Exception('Should never happen.')
            cur = max(cur - step, self.manager.tx_storage.first_timestamp)
            tips = cast(TipsPayload, (yield self.get_peer_tips(cur)))
            local_merkle_tree, _ = self.get_merkle_tree(cur)
            step *= 2

        # Binary search to find inside the interval.
        low = cur
        high = cur + step - 1
        while low < high:
            mid = (low + high + 1) // 2
            tips = cast(TipsPayload, (yield self.get_peer_tips(mid)))
            local_merkle_tree, _ = self.get_merkle_tree(mid)
            if tips.merkle_tree == local_merkle_tree:
                low = mid
            else:
                high = tips.prev_timestamp

        # Timestamp found.
        assert low == high
        self.synced_timestamp = low

        tips = cast(TipsPayload, (yield self.get_peer_tips(self.synced_timestamp)))
        local_merkle_tree, _ = self.get_merkle_tree(self.synced_timestamp)
        assert tips.merkle_tree == local_merkle_tree

        self.next_timestamp = tips.next_timestamp
        # self.log.debug('Synced at {} (latest timestamp {})'.format(self.synced_timestamp, self.peer_timestamp))

    @inlineCallbacks
    def sync_until_timestamp(self, timestamp: int) -> Iterator[Deferred]:
        """ Download all unknown hashes until synced timestamp reaches `timestamp`.

        :param timestamp: Timestamp to be reached
        :type timestamp: int
        """
        # self.log.debug('Syncing at {}'.format(timestamp))
        assert self.next_timestamp < inf
        pending = []
        next_timestamp = self.next_timestamp
        next_offset = 0
        while True:
            payload = cast(NextPayload, (yield self.get_peer_next(next_timestamp, offset=next_offset)))
            count = 0
            for h in payload.hashes:
                if not self.manager.tx_storage.transaction_exists(h):
                    pending.append(self.get_data(h))
                    count += 1
            if count == 0:
                break
            next_timestamp = payload.next_timestamp
            next_offset = payload.next_offset
            if next_timestamp == inf:
                break
            if next_timestamp > self.peer_timestamp:
                self.peer_timestamp = next_timestamp
        for deferred in pending:
            yield deferred
        if self.synced_timestamp > self.peer_timestamp:
            self.peer_timestamp = self.synced_timestamp

    @inlineCallbacks
    def sync_at_timestamp(self, timestamp):
        """ Download all unknown hashes at a given timestamp.

        :param timestamp: Timestamp to be synced
        :type timestamp: int
        """

    @inlineCallbacks
    def _next_step(self) -> Iterator[Union[Iterator, Iterator[Deferred]]]:
        """ Run the next step to keep nodes synced.
        """
        yield self.find_synced_timestamp()

        delta = self.peer_timestamp - self.synced_timestamp
        assert delta >= 0

        if delta > 0:
            assert self.next_timestamp <= self.peer_timestamp
            assert self.next_timestamp > self.synced_timestamp
            yield self.sync_until_timestamp(self.peer_timestamp)

    @inlineCallbacks
    def next_step(self) -> Iterator[Union[Iterator, Iterator[Deferred]]]:
        """ Execute next step and schedule next execution.
        """
        if self.is_running:
            # Already running...
            # self.log.debug('Already running: {}'.format(self.is_running))
            return

        try:
            self.is_running = True
            yield self._next_step()
        except Exception as e:
            self.log.warn('Exception: {}'.format(repr(e)))
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
        # Tips that won't be sent.
        ignore_intervals = self.manager.tx_storage.get_tx_tips(timestamp - 1)
        ignore_intervals.update(self.manager.tx_storage.get_block_tips(timestamp - 1))
        ignore_hashes = set(x.data for x in ignore_intervals)

        hashes = []

        next_timestamp = timestamp
        next_offset = 0
        while True:
            partial = self.manager.tx_storage.get_tx_tips(next_timestamp)
            partial.update(self.manager.tx_storage.get_block_tips(next_timestamp))

            if len(partial) == 0:
                break

            partial_hashes = [x.data for x in partial]
            partial_hashes.sort()
            if offset > 0:
                partial_hashes = partial_hashes[offset:]
                offset = 0
            for idx, h in enumerate(partial_hashes):
                if h not in ignore_hashes:
                    ignore_hashes.add(h)
                    hashes.append(h)
                    assert len(hashes) <= self.MAX_HASHES
                    if len(hashes) == self.MAX_HASHES:
                        next_offset = idx
                        break

            # Next timestamp in which tips have changed
            min_end = min(x.end for x in partial)

            # Look for transactions confirming already confirmed transactions
            while min_end != inf:
                tmp = self.manager.tx_storage.get_tx_tips(min_end - 1)
                tmp.update(self.manager.tx_storage.get_block_tips(min_end - 1))
                tmp.difference_update(partial)
                if not tmp:
                    break
                min_end = min(x.begin for x in tmp)

            if len(hashes) == self.MAX_HASHES:
                if next_offset == len(partial_hashes):
                    next_timestamp = min_end
                    next_offset = 0
                break

            next_timestamp = min_end

        data = {
            'timestamp': timestamp,
            'next_timestamp': next_timestamp,
            'next_offset': next_offset,
            'hashes': [h.hex() for h in hashes],
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
        tx_intervals = self.manager.tx_storage.get_tx_tips(timestamp)
        blk_intervals = self.manager.tx_storage.get_block_tips(timestamp)
        intervals = tx_intervals.union(blk_intervals)

        if len(intervals) == 0:
            raise Exception('No tips for timestamp {}'.format(timestamp))

        # Previous timestamp in which tips have changed
        max_begin = max(x.begin for x in intervals)

        # Next timestamp in which tips have changed
        min_end = min(x.end for x in intervals)

        # Look for transactions confirming already confirmed transactions
        while min_end != inf:
            tx_tmp = self.manager.tx_storage.get_tx_tips(min_end - 1)
            blk_tmp = self.manager.tx_storage.get_block_tips(min_end - 1)
            tmp = tx_tmp.union(blk_tmp)
            tmp.difference_update(intervals)
            if not tmp:
                break
            min_end = min(x.begin for x in tmp)

        # Calculate list of hashes to be sent
        merkle_tree, hashes = self.get_merkle_tree(timestamp)
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
            'prev_timestamp': max_begin - 1,
            'next_timestamp': min_end,
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
        # self.log.debug('handle_get_data {}'.format(hash_hex))
        try:
            tx = self.protocol.node.tx_storage.get_transaction(bytes.fromhex(hash_hex))
            self.send_data(tx)
        except TransactionDoesNotExist:
            # TODO Send NOT-FOUND?
            pass

    def send_data(self, tx: BaseTransaction) -> None:
        """ Send a DATA message.
        """
        # self.log.debug('Sending {}...'.format(tx.hash.hex()))
        payload_type = 'tx' if not tx.is_block else 'block'
        payload = base64.b64encode(tx.get_struct()).decode('ascii')
        self.send_message(ProtocolMessages.DATA, '{}:{}'.format(payload_type, payload))

    def handle_data(self, payload: str) -> None:
        """ Handle a received DATA message.
        """
        if not payload:
            return
        payload_type, _, payload = payload.partition(':')
        data = base64.b64decode(payload)
        if payload_type == 'tx':
            tx = Transaction.create_from_struct(data)
        elif payload_type == 'block':
            tx = Block.create_from_struct(data)
        else:
            raise ValueError('Unknown payload load')

        if self.protocol.node.tx_storage.get_genesis(tx.hash):
            # We just got the data of a genesis tx/block. What should we do?
            # Will it reduce peer reputation score?
            return
        tx.storage = self.protocol.node.tx_storage
        result = self.manager.on_new_tx(tx, conn=self.protocol)

        assert tx.hash is not None
        key = 'get-data-{}'.format(tx.hash.hex())
        deferred = self.deferred_by_key.pop(key, None)
        if deferred:
            assert tx.timestamp is not None
            if tx.timestamp - 1 > self.synced_timestamp:
                self.synced_timestamp = tx.timestamp - 1
            deferred.callback((tx, result))
