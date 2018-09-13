import time


class PeerDataRequestsManager(object):
    """PeerDataRequestsManager will handle scheduling outgoing calls to peers to request blocks and transactions data.

    This class helps assign requests to different peers in a round-robin style, retry requests when results aren't
    found, and keep track of what has been received.

    """

    def __init__(self, manager, node_sync_manager):
        self.manager = manager
        self.node_sync_manager = node_sync_manager

        # Next peer to bother with download requests.
        self.prev_peer_idx = 0

    def schedule_transaction_download(self, hash_hex):
        """Schedule/request the download of the given transaction from peers.

        Self-throttle to avoid spamming peers. Spread requests out across known peers.  Send retries
        to different peers.

        :param hash_hex: string
        :return: None
        """
        # TODO: Refactor this functionality into a separate PeerRequestManager class.
        # TODO: Throttle request rate.
        # TODO: Send a repeat request to a different peer each time.

        # Try to find a peer we haven't bothered recently.
        for idx in range(len(self.manager.connected_peers)):
            # Move to next peer.
            next_peer_idx = (self.prev_peer_idx + idx) % len(self.manager.connected_peers)
            conn = list(self.manager.connected_peers.values())[next_peer_idx]
            self.prev_peer_idx = next_peer_idx

            # Check how long it's been since we last bothered this peer.
            cur_time = time.time()
            dt_sec = cur_time - conn.last_request

            if dt_sec > 0.5:  # TODO: Pick a good time. 0.5 seconds for now.
                # Send request.
                conn.state.send_get_data(hash_hex)
                conn.last_request = cur_time
                break
        else:
            # Couldn't find anyone to bother. Will try again later.
            pass
