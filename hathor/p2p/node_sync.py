# encoding: utf-8

from twisted.internet import reactor
from twisted.internet.defer import inlineCallbacks, Deferred

from hathor.p2p.exceptions import InvalidBlockHashesSequence
from hathor.transaction import Block, Transaction
from hathor.transaction.storage.exceptions import TransactionDoesNotExist
from hathor.transaction.storage.memory_storage import TransactionMemoryStorage
from hathor.p2p.messages import ProtocolMessages, GetTipsPayload, TipsPayload

import base64
import hashlib
import random
import json


class NodeSyncTimestamp(object):
    """ An algorithm to sync the DAG between two peers using the timestamp of the transactions.
    """

    def __init__(self, protocol, reactor=None):
        """
        :param protocol: Protocol of the connection.
        :type protocol: HathorProtocol

        :param reactor: Reactor to schedule later calls. (default=twisted.internet.reactor)
        :type reactor: Reactor
        """
        self.protocol = protocol
        self.manager = protocol.node

        if reactor is None:
            from twisted.internet import reactor
        self.reactor = reactor

        self.call_later_id = None
        self.call_later_interval = 1  # seconds

        # Latest data timestamp of the peer.
        self.peer_timestamp = None  # Unknown
        self.peer_merkle_hash = None  # Unkwnown
        self.next_timestamp = None
        self.previous_timestamp = None

        # Latest deferred waiting for a reply.
        self.deferred_by_key = {}  # Dict[str, Deferred]

        # Latest timestamp in which we're synced.
        self.synced_timestamp = None

        self.is_running = None

    def get_status(self):
        """ Return the status of the sync.
        """
        return {
            'latest_timestamp': self.peer_timestamp,
            'synced_timestamp': self.synced_timestamp,
        }

    def get_name(self):
        """ Return the name of the plugin.
        """
        return 'node-sync-timestamp'

    def get_cmd_dict(self):
        """ Return a dict of messages of the plugin.
        """
        return {
            ProtocolMessages.NOTIFY_DATA: self.handle_notify_data,
            ProtocolMessages.GET_DATA: self.handle_get_data,
            ProtocolMessages.DATA: self.handle_data,

            ProtocolMessages.GET_TIPS: self.handle_get_tips,
            ProtocolMessages.TIPS: self.handle_tips,
        }

    def start(self):
        """ Start sync.
        """
        self.next_step()

    def stop(self):
        """ Stop sync.
        """
        if self.call_later_id and self.call_later_id.active():
            self.call_later_id.cancel()

    def send_tx_to_peer_if_possible(self, tx):
        #if self.synced_timestamp is None:
        #    return
        #if tx.timestamp <= self.peer_timestamp:
        #    return
        #for parent_hash in tx.parents:
        #    parent = self.protocol.node.tx_storage.get_transaction_by_hash_bytes(parent_hash)
        #    if parent.timestamp > self.synced_timestamp:
        #        # print('send_tx_to_peer_if_possible(): discarded')
        #        return
        # print('send_tx_to_peer_if_possible(): SEND-DATA')
        self.send_data(tx)

    def get_merkle_tree(self, timestamp):
        """ Generate a hash to check whether the DAG is the same at that timestamp.

        :rtype: Tuple[bytes(hash), List[bytes(hash)]]
        """
        tx_intervals = self.manager.tx_tips_index[timestamp]
        blk_intervals = self.manager.block_tips_index[timestamp]

        hashes = [x.data for x in tx_intervals]
        hashes.extend(x.data for x in blk_intervals)
        hashes.sort()

        merkle = hashlib.sha256()
        for h in hashes:
            merkle.update(h)

        return merkle.digest(), hashes

    def get_peer_tips(self, timestamp=None, include_hashes=False):
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
        self.send_get_tips(timestamp, include_hashes)
        deferred = Deferred()
        self.deferred_by_key[key] = deferred
        return deferred

    def get_data(self, hash_bytes):
        """ A helper that returns a deferred that is called when the peer replies.

        :param hash_bytes: Hash of the data to be downloaded
        :type hash_bytes: bytes(hash)

        :rtype: Deferred
        """
        key = 'get-data-{}'.format(hash_bytes)
        if self.deferred_by_key.get(key, None) is not None:
            raise Exception('latest_deferred is not None')
        #self.reactor.callLater(1, self.send_get_data, hash_bytes.hex())
        self.send_get_data(hash_bytes.hex())
        deferred = Deferred()
        self.deferred_by_key[key] = deferred
        return deferred

    @inlineCallbacks
    def find_synced_timestamp(self):
        """ Search time highest timestamp in which we are synced.

        It uses an exponential search followed by a binary search.
        """
        # print('Running find_synced_timestamp...')
        self.is_running = 'find_synced_timestamp'

        tips = yield self.get_peer_tips()
        if self.peer_timestamp is not None:
            assert tips.timestamp >= self.peer_timestamp
        self.peer_timestamp = tips.timestamp

        # Exponential search to find an interval.
        cur = tips.timestamp
        local_merkle_tree, _ = self.get_merkle_tree(cur)
        step = 1
        while tips.merkle_tree != local_merkle_tree:
            if cur == self.manager.first_timestamp:
                raise Exception('Should never happen.')
            cur = max(cur - step, self.manager.first_timestamp)
            tips = yield self.get_peer_tips(cur)
            local_merkle_tree, _ = self.get_merkle_tree(cur)
            step *= 2

        # Binary search to find inside the interval.
        low = cur
        high = cur + step - 1
        while low < high:
            mid = (low + high + 1) // 2
            tips = yield self.get_peer_tips(mid)
            local_merkle_tree, _ = self.get_merkle_tree(mid)
            if tips.merkle_tree == local_merkle_tree:
                low = mid
            else:
                high = tips.prev_timestamp

        # Timestamp found.
        assert low == high
        self.synced_timestamp = low

        tips = yield self.get_peer_tips(self.synced_timestamp)
        local_merkle_tree, _ = self.get_merkle_tree(self.synced_timestamp)
        assert tips.merkle_tree == local_merkle_tree

        #self.next_timestamp = tips.next_timestamp
        self.next_timestamp = self.synced_timestamp + 1
        self.is_running = None
        # print('Synced at {} (latest timestamp {})'.format(self.synced_timestamp, self.peer_timestamp))

    @inlineCallbacks
    def sync_until_timestamp(self, timestamp):
        """ Download all unknown hashes until synced timestamp reaches `timestamp`.

        :param timestamp: Timestamp to be reached
        :type timestamp: int
        """
        while self.synced_timestamp < timestamp:
            assert self.next_timestamp > self.synced_timestamp
            next_timestamp = yield self.sync_at_timestamp(self.next_timestamp)
            assert next_timestamp > self.next_timestamp
            self.synced_timestamp = self.next_timestamp
            self.next_timestamp = next_timestamp
        self.peer_timestamp = self.synced_timestamp

    @inlineCallbacks
    def sync_at_timestamp(self, timestamp):
        """ Download all unknown hashes at a given timestamp.

        :param timestamp: Timestamp to be synced
        :type timestamp: int
        """
        self.is_running = 'sync_at_timestamp'
        # print('Syncing at {}'.format(timestamp))
        tips = yield self.get_peer_tips(timestamp, include_hashes=True)
        pending = []
        for h in tips.hashes:
            if not self.manager.tx_storage.transaction_exists_by_hash_bytes(h):
                pending.append(self.get_data(h))
        for deferred in pending:
            yield deferred
        self.is_running = None
        return tips.next_timestamp

    def _next_step(self):
        """ Run the next step to keep nodes synced.
        """
        if self.is_running is not None:
            # Already running...
            # print('Already running: {}'.format(self.is_running))
            return

        if self.peer_timestamp is None:
            self.find_synced_timestamp()
            return

        if self.synced_timestamp is None:
            self.find_synced_timestamp()
            return

        delta = self.peer_timestamp - self.synced_timestamp
        assert delta >= 0

        if delta > 0:
            assert self.next_timestamp <= self.peer_timestamp
            assert self.next_timestamp > self.synced_timestamp
            self.sync_until_timestamp(self.peer_timestamp)
            return

        else:
            # We always find our synced timestamp, does not matter whether we are behind or in front of our peer.
            self.find_synced_timestamp()

    def next_step(self):
        """ Execute next step and schedule next execution.
        """
        try:
            self._next_step()
        except Exception as e:
            print('Exception:', repr(e))
            raise

        if self.call_later_id and self.call_later_id.active():
            self.call_later_id.cancel()
        self.call_later_id = self.reactor.callLater(self.call_later_interval, self.next_step)

    def send_message(self, cmd, payload=None):
        """ Helper to send a message.
        """
        return self.protocol.state.send_message(cmd, payload)

    def send_get_tips(self, timestamp=None, include_hashes=False):
        """ Send a GET-TIPS message.
        """
        if timestamp is None:
            self.send_message(ProtocolMessages.GET_TIPS)
        else:
            payload = json.dumps(dict(
                timestamp=timestamp,
                include_hashes=include_hashes,
            ))
            self.send_message(ProtocolMessages.GET_TIPS, payload)

    def handle_get_tips(self, payload):
        """ Handle a received GET-TIPS message.
        """
        if not payload:
            self.send_tips()
        else:
            data = json.loads(payload)
            args = GetTipsPayload(**data)
            self.send_tips(args.timestamp, args.include_hashes)

    def send_tips(self, timestamp=None, include_hashes=False):
        """ Send a TIPS message.
        """
        if timestamp is None:
            timestamp = self.manager.latest_timestamp

        # All tips
        tx_intervals = self.manager.tx_tips_index[timestamp]
        blk_intervals = self.manager.block_tips_index[timestamp]
        intervals = tx_intervals.union(blk_intervals)

        # Previous timestamp in which tips have changed
        max_begin = max(x.begin for x in intervals)

        # Next timestamp in which tips have changed
        # min_end = min(x.end for x in intervals)

        # Calculate list of hashes to be sent
        merkle_tree, hashes = self.get_merkle_tree(timestamp)

        if not include_hashes:
            hashes = []

        data = {
            'length': len(intervals),
            'timestamp': timestamp,
            'prev_timestamp': max_begin - 1,
            # 'next_timestamp': min_end,
            'next_timestamp': timestamp + 1,
            'merkle_tree': merkle_tree.hex(),
            'hashes': [h.hex() for h in hashes],
        }

        self.send_message(ProtocolMessages.TIPS, json.dumps(data))

    def handle_tips(self, payload):
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
            json.dumps(x.hex() for x in tx.parents),
        )
        self.send_message(ProtocolMessages.NOTIFY_DATA, payload)

    def handle_notify_data(self, payload):
        """ Send a NOTIFY-DATA message, notifying a peer about a new hash.
        """
        timestamp, _, payload2 = payload.partition(' ')
        hash_hex, _, parents_json = payload2.partition(' ')
        parents = json.loads(parents_json)

        if self.protocol.tx_storage.transaction_exists_by_hash(hash_hex):
            return

        for parent_hash in parents:
            if not self.protocol.tx_storage.transaction_exists_by_hash(parent_hash):
                # Are we out-of-sync with this peer?
                return

        self.send_get_data(hash_hex)

    def send_get_data(self, hash_hex):
        """ Send a GET-DATA message, requesting the data of a given hash.
        """
        self.send_message(ProtocolMessages.GET_DATA, hash_hex)

    def handle_get_data(self, payload):
        """ Handle a received GET-DATA message.
        """
        hash_hex = payload
        # print('handle_get_data', hash_hex)
        try:
            tx = self.protocol.node.tx_storage.get_transaction_by_hash(hash_hex)
            self.send_data(tx)
        except TransactionDoesNotExist:
            # TODO Send NOT-FOUND?
            #self.send_data('')
            pass
        except Exception as e:
            print(e)

    def send_data(self, tx):
        """ Send a DATA message.
        """
        print('Sending {}...'.format(tx.hash.hex()))
        payload_type = 'tx' if not tx.is_block else 'block'
        payload = base64.b64encode(tx.get_struct()).decode('ascii')
        self.send_message(ProtocolMessages.DATA, '{}:{}'.format(payload_type, payload))

    def handle_data(self, payload):
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

        if self.protocol.node.tx_storage.get_genesis_by_hash_bytes(tx.hash):
            # We just got the data of a genesis tx/block. What should we do?
            # Will it reduce peer reputation score?
            return
        tx.storage = self.protocol.node.tx_storage
        self.manager.on_new_tx(tx, conn=self.protocol)

        key = 'get-data-{}'.format(tx.hash)
        deferred = self.deferred_by_key.pop(key, None)
        if deferred:
            deferred.callback(tx)


class NodeSyncLeftToRightManager(object):  # pragma: no cover
    """NodeSyncManager will handle the synchonization of blocks and transactions of this node.
    It will do from left to right, which means it will discover a path with one known transactions
    and a sequence of unknown transactions.

    It will be used as soon as we connect to the p2p network. New transactions and blocks will be
    downloaded and connected to our DAG, but no inconsistency will be allowed.

    Syncing algorithm
    -----------------

    1. Send GET-TIPS
    2. Recv TIPS

    Then, if we don't know any block, run:

    3. Send GET-BLOCKS
    4. Recv BLOCKS

    Repeat steps 3 and 4 until we get a known block.

    For each block, do:

        5. Send GET-TRANSACTIONS
        6. Recv TRANSACTIONS

        Repeat steps 5 and 6 until we get a known transaction.

        7. Send GET-DATA
        8. Recv DATA

        Repeat steps 7 and 8 until all transactions have been downloaded.

    Now, all blocks are sync'ed. Thus,

    9. Send GET-TIPS
    10. Recv TIPS

    If there is any tip we don't know, we run:

    11. Send GET-TRANSACTIONS
    12. Recv TRANSACTIONS

    Repeat steps 11 and 12 until we get a known transactions.

    13. Send GET-DATA
    14. Recv DATA

    Repeat steps 13 and 14 until all transactions have been downloaded.

    15. GET-TIP
    16. TIP

    Probably we are sync'ed. But, if something new has appeared, do it again.


    Synchronous Algorithm
    ---------------------

    1. Send GET-TIPS
    2. Call `on_tips_received`
    3. Repeat until we find a known block:
        3.1. Send GET-BLOCKS for an unknown block
        3.2. Call `on_block_hashes_received`
    4. Repeat for all unknown blocks, from left to right:
        4.1. Send GET-TRANSACTIONS for an unknown block
        4.2. Call `on_transactions_hashes_received`
        4.3. Repeat until we find a known transactions:
            4.3.1. Send GET-TRANSACTIONS for an unknown transaction
            4.3.2. Call `on_transactions_hashes_received`
        4.4. Repeat until all transactions have been downloaded
            4.4.1 Send GET-DATA for an unknown transactions
            4.4.2 Call `on_new_tx`
        4.5. Send GET-DATA for the unknown block
        4.6. Call `on_new_tx`
    5. Send GET-TIPS
    6. Call `on_tips_received`
    7. Repeat until we find a known transaction:
        7.1. Send GET-TRANSACTIONS for an unknown tip transaction
        7.2. Call `on_transactions_hashes_received`
    8. Repeat until all transactions have been downloaded
        8.1. Send GET-DATA for the unknown block
        8.2. Call `on_new_tx`
    """

    def __init__(self, manager):
        self.manager = manager

        self.syncing_with = None  # PeerId whom you are syncing with.

        self.unknown_blocks = []
        self.unknown_transactions = []

    def check_state(self):
        """Check whether we are sync'ed or not.

        If there is a tip we don't know, we have to download it.
        If we know all tips and they are tips in our DAG, we are totally sync'ed.
        If we know all tips but some are not tips in our DAG, our peer needs to sync.
        """
        for peer, conn in self.manager.connected_peers.items():
            conn.state.send_get_tips()

    def on_new_tx(self, tx, conn=None):
        """Called when new transactions and blocks arrive from the network.
        """
        if self.manager.state != self.manager.NodeState.SYNCING:
            return

        if self.syncing_with != conn:
            return

        if tx.is_block:
            self.pre_download_next_unkown_block(conn)
        else:
            self.download_next_unknown_transaction(conn)

    def sync_tip_if_needed(self, tip, conn):
        """ Do different sync tasks depending on the tip.

        If we know the tip, there's nothing to be done.

        If we don't know the tip, let's check its parents. Then, if we know
        all the parents, we can download this tip. Otherwise, we need to find
        a path between this tip and a known transaction.
        """
        def are_parents_known(tip):
            for parent_hash in tip.parents:
                if not self.manager.tx_storage.transaction_exists_by_hash_bytes(parent_hash):
                    return False
            return True

        def is_known(tip):
            if not self.manager.tx_storage.transaction_exists_by_hash_bytes(tip.hash):
                return False
            return True

        if is_known(tip):
            # We already have this tip. Nothing to do.
            print('sync_tip_if_needed(): Already have tip {}'.format(tip.hash.hex()))
            return True

        if are_parents_known(tip):
            # We don't have this tip, but we have its parents.
            # So, let's download it.
            print('sync_tip_if_needed(): Schedule to download {}'.format(tip.hash.hex()))
            self.schedule_transaction_download(tip.hash.hex())
            return True

        # We don't have at least one of the parents. Let's sync this block.
        print('sync_tip_if_needed(): Need to sync {}'.format(tip.hash.hex()))
        return False

    def schedule_transaction_download(self, hash_hex):
        """Schedule a new transaction download using GET-DATA.
        """
        # TODO We should use PeerDataRequestManager to throttle messages.
        print('schedule_transaction_download({})'.format(hash_hex))
        conn = random.choice(list(self.manager.connections.connected_peers.values()))
        conn.state.send_get_data(hash_hex)

    def on_tips_received(self, tip_blocks, tip_transactions, conn=None):
        """ When tips are received, we check what we have to do.

        If we already have the transaction, nothing is done.
        If we known all its parents, we just download it.
        Otherwise, we find a path between the tip and our known transactions.
        """
        if self.manager.state == self.manager.NodeState.SYNCED:
            return

        if self.syncing_with is None:
            self.syncing_with = conn

        if self.syncing_with != conn:
            return

        all_block_tips_known = True
        print('on_tips_received(): Checking tip blocks...')
        for tip in tip_blocks:
            if not self.sync_tip_if_needed(tip, conn):
                all_block_tips_known = False
                self.unknown_blocks.extend([tip.hash.hex()])
                conn.state.send_get_blocks(tip.hash.hex())

        if not all_block_tips_known:
            # First, we sync the blocks. Then, the transactions.
            print('on_tips_received(): Syncing blocks...')
            self.manager.state = self.manager.NodeState.SYNCING
            return

        print('on_tips_received(): All blocks are known. Checking tip transactions...')
        for tip in tip_transactions:
            if not self.manager.tx_storage.transaction_exists_by_hash(tip.hash.hex()):
                print('on_tips_received(): Syncing transactions...')
                conn.state.send_get_transactions(tip.hash.hex())
                self.manager.state = self.manager.NodeState.SYNCING
                break
        else:
            print('on_tips_received(): All transactions are known. Nothing to do.')
            self.manager.state = self.manager.NodeState.SYNCED

    def on_block_hashes_received(self, block_hashes, conn=None):
        """Called when a list of hashes of blocks is received from a peer.
        """
        if self.manager.state != self.manager.NodeState.SYNCING:
            return

        if self.syncing_with != conn:
            return

        print('on_block_hashes_received()', block_hashes)

        # We receive hashes from right-to-left.
        # Let's reverse it to work with hashes from left-to-right.
        block_hashes = block_hashes[::-1]

        # Let's check whether we know these received hashes.
        for i, h in enumerate(block_hashes):
            if not self.manager.tx_storage.transaction_exists_by_hash(h):
                first_unknown = i
                break
        else:
            # All hashes are known. It seems we're sync'ed.
            self.pre_download_next_unkown_block(conn)
            return

        # Validate block hashes sequence.
        for h in block_hashes[first_unknown:]:
            if self.manager.tx_storage.transaction_exists_by_hash(h):
                # Something is wrong. We're supposed to unknown all hashes after the first unknown.
                raise InvalidBlockHashesSequence()

        if first_unknown == 0:
            # All hashes are unknown.
            self.unknown_blocks = block_hashes + self.unknown_blocks
            conn.state.send_get_blocks(block_hashes[0])
            return

        # Part is known, part is unknown.
        self.unknown_blocks = block_hashes[first_unknown:] + self.unknown_blocks
        # Now, self.unknown_blocks[0].parents are known.
        # So, we have a hash that connects to our valid DAG. Let's merge the DAG and download the data.
        self.pre_download_next_unkown_block(conn)

    def on_transactions_hashes_received(self, txs_hashes, conn=None):
        """Called when a list of hashes of blocks is received from a peer.

        :type txs_hashes: List[string(hex)]
        """
        if self.manager.state != self.manager.NodeState.SYNCING:
            return

        if self.syncing_with != conn:
            return

        # Let's check whether we know these received hashes.
        for i, h in enumerate(txs_hashes):
            if not self.manager.tx_storage.transaction_exists_by_hash(h):
                first_unknown = i
                break
        else:
            # All hashes are known. It seems we're sync'ed.
            print('--> all hashes are known')
            self.download_next_unknown_transaction(conn)
            return

        # Validate block hashes sequence.
        for h in txs_hashes[first_unknown:]:
            if self.manager.tx_storage.transaction_exists_by_hash(h):
                # Something is wrong. We're supposed to unknown all hashes after the first unknown.
                raise InvalidBlockHashesSequence(h)

        if first_unknown == 0:
            # All hashes are unknown.
            self.unknown_transactions = txs_hashes + self.unknown_transactions
            print('--> all hashes are unknown')
            conn.state.send_get_transactions(txs_hashes[0])
            return

        # Part is known, part is unknown.
        print('--> part is known, part is unknown')
        self.unknown_transactions = txs_hashes[first_unknown:] + self.unknown_transactions
        # Now, self.unknown_blocks[0].parents are known.
        # So, we have a hash that connects to our valid DAG. Let's merge the DAG and download the data.
        self.download_next_unknown_transaction(conn)

    def pre_download_next_unkown_block(self, conn):
        if not self.unknown_blocks:
            conn.state.send_get_tips()
            return
        hash_hex = self.unknown_blocks[0]
        print('Preparing list of transactions needed to download the block {}'.format(hash_hex))
        conn.state.send_get_transactions(hash_hex)

    def download_next_unknown_transaction(self, conn):
        if not self.unknown_transactions:
            self.download_next_unknown_block(conn)
            return
        hash_hex = self.unknown_transactions.pop(0)
        print('download_next_unknown_transaction', hash_hex)
        self.schedule_transaction_download(hash_hex)

    def download_next_unknown_block(self, conn):
        if not self.unknown_blocks:
            conn.state.send_get_tips()
            return
        hash_hex = self.unknown_blocks.pop(0)
        self.schedule_transaction_download(hash_hex)


class NodeSyncManager(object):  # pragma: no cover
    """NodeSyncManager will handle the synchonization of blocks and transactions of this node.

    It will be used as soon as we connect to the p2p network. New transactions and blocks will be
    downloaded and connected to our DAG, but no inconsistency will be allowed.
    """

    def __init__(self, manager):
        self.manager = manager
        self.peer_data_requests_manager = PeerDataRequestsManager(manager, self)

        # A set of blocks that we should download, according to peers.
        self.blocks_to_download = set()  # TODO: use this or "unknown blocks"; not both.

        # A set of transactions that we want to download, to validate blocks we've received.
        self.txs_to_download = set()

        # Temporary storage for transactions we're downloading while syncing. These transactions/blocks have not
        # yet been connected with the genesis DAG. Once they connect, we move them to the main tx_storage.
        self.tx_storage_sync = TransactionMemoryStorage()  # TODO: Should there be a file storage option?

        self.node_sync_state = self.manager.NodeSyncState.SYNCING

    def check_state(self):
        """Check whether we are sync'ed or not.

        If there is a tip we don't know, we have to download it.
        If we know all tips and they are tips in our DAG, we are totally sync'ed.
        If we know all tips but some are not tips in our DAG, our peer needs to sync.
        """
        for peer, conn in self.manager.connected_peers.items():
            conn.state.send_get_tips()

    def on_new_tx(self, tx, conn=None):
        """Called when new transactions and blocks arrive from the network.
        """

        # Save the transaction if we don't have it.
        if not self.manager.tx_storage.transaction_exists_by_hash_bytes(tx.hash):
            # However, if the transaction doesn't connect to the genesis DAG, just save in temporary storage.
            if tx.compute_genesis_dag_connectivity(self.manager.tx_storage, self.tx_storage_sync):
                self.manager.tx_storage.save_transaction(tx)
            elif not self.tx_storage_sync.transaction_exists_by_hash_bytes(tx.hash):
                self.tx_storage_sync.save_transaction(tx)

        # meta = self.tx_storage.get_metadata_by_hash_bytes(tx.hash)
        # meta.peers.add(conn.peer_id.id)
        # self.tx_storage.save_metadata(meta)

        # If we're still syncing, let's check if we're ready now.
        # if self.node_sync_state == self.manager.NodeSyncState.SYNCING:
        #     self.try_to_synchronize()

    def try_to_synchronize_blocks(self):
        """Tries to perform sync to receive block data.

        :return: None
        """
        hashes_to_remove = set()
        for hash_hex in self.blocks_to_download:
            # Check if we already have this hash, either in temp or permanent storage. If so, remove from list.
            if (self.manager.tx_storage.transaction_exists_by_hash(hash_hex) or
                    self.tx_storage_sync.transaction_exists_by_hash(hash_hex)):
                hashes_to_remove.add(hash_hex)
                continue

            # Need to download.
            self.peer_data_requests_manager.schedule_transaction_download(hash_hex)

        # Remove blocks we already downloaded.
        self.blocks_to_download.difference_update(hashes_to_remove)

    def try_to_synchronize_transactions(self):
        """Tries to perform sync for non-block transactions.

        Move from genesis block towards the latest block, requesting all transactions required to confirm
        each block before moving on to the next block.

        :return: None
        """
        # Find the first unconfirmed block in the sync-DAG. This is one that has at least one parent block that is
        # confirmed.

        # TODO: speed this up using topological sort / list of blocks by height.

        block_to_sync = None
        confirmed_parent_bytes = None
        for tx in self.tx_storage_sync.get_all_transactions():
            if not tx.is_block:
                continue
            for parent_hash_bytes in tx.parents:
                # Find the parent.
                if not self.manager.tx_storage.transaction_exists_by_hash_bytes(parent_hash_bytes):
                    # If the parent isn't in the main storage, it's not confirmed.
                    continue
                # The parent is in storage. Get the data.
                parent = self.manager.tx_storage.get_transaction_by_hash_bytes(parent_hash_bytes)
                if not parent.is_block:
                    continue
                # We have a confirmed parent block. So this is the first unconfirmed block!
                block_to_sync = tx
                confirmed_parent_bytes = parent_hash_bytes
                break
            if block_to_sync:
                break
        else:
            # Didn't find a block to sync. Apparently we're all synced up!
            self.node_sync_state = self.manager.NodeSyncState.SYNCED
            return

        # We have a node to sync. Grab its parents' transactions/blocks, but skip the confirmed block parent.
        for parent_hash_bytes in tx.parents:
            if parent_hash_bytes == confirmed_parent_bytes:
                continue
            # Did we already store it in sync storage?
            if self.tx_storage_sync.transaction_exists_by_hash_bytes(parent_hash_bytes):
                # Nothing to do -- we already have this queued up.
                continue
            # We have a new transaction/block! Request its data.
            self.txs_to_download.add(parent_hash_bytes.hex())
            self.peer_data_requests_manager.schedule_transaction_download(parent_hash_bytes.hex())

    def migrate_transactions_from_storage_sync(self):
        """Move transactions from self.storage_sync to self.storage once they are verified and connect to the
        genesis DAG.

        :return: None
        """
        # TODO(epnichols).

        pass

    def try_to_synchronize(self):
        """Checks the current blocks/transactions to determine if this nodes is sufficiently synced up with the rest
        of the network.  If not, request the missing blocks/transactions.

        Updates the NodeSyncState enum.

        :return: None
        """
        # print('sync attempt...')
        if self.node_sync_state == self.NodeSyncState.SYNCED:
            # Nothing to do.
            return

        self.try_to_synchronize_blocks()
        self.try_to_synchronize_transactions()
        self.migrate_transactions_from_storage_sync()

        # We're up-to-date once our set of blocks and transactions to download is empty.
        if not (self.blocks_to_download or self.txs_to_download):
            self.node_sync_state = self.NodeSyncState.SYNCED
            print('Done synchronizing!')
        else:
            # TODO(epnichols): This seems to call this function way too often...fix!
            reactor.callLater(0.5, self.try_to_synchronize)
