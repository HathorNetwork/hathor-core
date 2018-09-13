# encoding: utf-8

from twisted.internet import reactor

from hathor.p2p.exceptions import InvalidBlockHashesSequence
from hathor.p2p.peer_data_requests_manager import PeerDataRequestsManager
from hathor.transaction.storage.memory_storage import TransactionMemoryStorage

import random


class NodeSyncLeftToRightManager(object):
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
        conn = random.choice(list(self.manager.connected_peers.values()))
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
            return
        hash_hex = self.unknown_blocks.pop(0)
        self.schedule_transaction_download(hash_hex)


class NodeSyncManager(object):
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
