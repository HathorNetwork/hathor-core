from hathor.p2p.exceptions import InvalidBlockHashesSequence


class NodeSyncManager(object):
    """NodeSyncManager will handle the synchonization of blocks and transactions of this node.

    It will be used as soon as we connect to the p2p network. New transactions and blocks will be
    downloaded and connected to our DAG, but no inconsistency will be allowed.
    """

    def __init__(self):
        self.manager = None
        self.unknown_blocks = []

    def check_state(self):
        """Check whether we are sync'ed or not.

        If there is a tip we don't know, we have to download it.
        If we know all tips and they are tips in our DAG, we are totally sync'ed.
        If we know all tips but some are not tips in our DAG, our peer needs to sync.
        """
        for peer, conn in self.manager.connected_peers.items():
            conn.send_get_tips()

    def on_new_tx(self, tx, conn=None):
        """Called when new transactions and blocks arrive from the network.
        """
        if tx.is_block:
            pass
        else:
            pass

    def on_block_hashes_received(self, block_hashes, conn=None):
        """Called when a list of hashes of blocks is received from a peer.
        """

        # We receive hashes from right-to-left.
        # Let's reverse it to work with hashes from left-to-right.
        block_hashes = block_hashes[::-1]

        # Let's check whether we know these received hashes.
        for i, h in enumerate(block_hashes):
            if not self.tx_storage.transaction_exists_by_hash(h):
                first_unknown = i
                break
        else:
            # All hashes are known. It seems we're sync'ed.
            return

        # Validate block hashes sequence.
        for h in block_hashes[first_unknown:]:
            if self.tx_storage.transaction_exists_by_hash(h):
                # Something is wrong. We're supposed to unknown all hashes after the first unknown.
                raise InvalidBlockHashesSequence()

        if first_unknown == 0:
            # All hashes are unknown.
            self.unknown_blocks.extend(block_hashes)
            self.state.send_get_blocks(block_hashes[0])
            return

        # Part is known, part is unknown.
        self.unknown_blocks.extend(block_hashes[first_unknown:])
        # Now, self.unknown_blocks[0].parents are known.
        # So, let's sync block after block.
        raise NotImplementedError

        self.try_to_synchronize()
