from collections import deque
from functools import partial
from typing import TYPE_CHECKING, Deque, Dict, List, Optional

from twisted.internet import defer
from twisted.internet.defer import Deferred
from twisted.logger import Logger

from hathor.conf import HathorSettings
from hathor.transaction.storage.exceptions import TransactionDoesNotExist

settings = HathorSettings()

if TYPE_CHECKING:
    from hathor.p2p.node_sync import NodeSyncTimestamp  # noqa: F401
    from hathor.transaction import BaseTransaction  # noqa: F401
    from hathor.manager import HathorManager  # noqa: F401


class TxDetails:
    # Hash of the transaction.
    tx_id: bytes

    # This will be resolved after the transactions has been added to
    # the DAG.
    deferred: Deferred

    # List of connections that requested this transaction.
    connections: List['NodeSyncTimestamp']

    # This will be resolved after the transaction has been downloaded,
    # but not necessarily added to the DAG.
    downloading_deferred: Optional[Deferred]

    # Index of the list of connections that requested the data
    # Useful when we need to retry the request and want to select a new connection
    requested_index: int

    def __init__(self, tx_id: bytes, deferred: Deferred, connections: List['NodeSyncTimestamp']):
        self.tx_id = tx_id
        self.deferred = deferred
        self.connections = connections
        self.downloading_deferred = None
        self.requested_index = 0

    def get_connection(self) -> Optional['NodeSyncTimestamp']:
        """ Get a connection to start the download for this tx detail

            We start from the first connection because it's the first one that requested
            so it's supposed to be the one with lowest rtt that is available this time

            We tried to do a random choice but it was getting too slow because sometimes
            we were choosing a peer that is far

            We use the requested_index to get the next connection, in case of a retry
        """
        connection = None
        while connection is None:
            if len(self.connections) <= self.requested_index:
                # We don't have more connections available
                break

            connection = self.connections[self.requested_index]
            self.requested_index += 1

            if not connection.protocol.connected:
                # Connection was already closed, so try the next one
                connection = None

        return connection


class Downloader:
    """ It manages the download of all transactions from peers. It is used to do
    several optimizations instead of downloading the same transactions multiple times,
    one from each peer.

    TODO: Should we have a flag to sync only the best blockchain? Or to sync the
    best blockchain first?
    """
    log = Logger()

    # All transactions that must be downloaded.
    pending_transactions: Dict[bytes, TxDetails]

    # Transactions waiting to be downloaded.
    waiting_deque: Deque[bytes]

    # Transactions that are being downloaded.
    downloading_deque: Deque[bytes]

    # Transactions that have been downloaded but are not ready to be
    # added to the DAG.
    downloading_buffer: Dict[bytes, 'BaseTransaction']

    # Size of the sliding window used to download transactions.
    window_size: int

    def __init__(self, manager: 'HathorManager', window_size: int = 100):
        self.manager = manager

        self.pending_transactions = {}
        self.waiting_deque = deque()
        self.downloading_deque = deque()
        self.downloading_buffer = {}
        self.window_size = window_size

    def get_tx(self, tx_id: bytes, connection: 'NodeSyncTimestamp') -> Deferred:
        """ Add a transaction to be downloaded and add to the DAG.
        """
        try:
            # If I already have this tx in the storage just return a defer already success
            # In the node_sync code we already handle this case but in a race condition situation
            # we might get here but it's not common
            tx = self.manager.tx_storage.get_transaction(tx_id)
            self.log.debug(
                'Downloader: requesting to download a tx that is already in the storage. Tx {}'.format(tx_id.hex())
            )
            return defer.succeed(tx)
        except TransactionDoesNotExist:
            # This tx does not exist in our storage
            details = self.pending_transactions.get(tx_id, None)
            if details is not None:
                # Some peer already requested this tx and is waiting for the download to finish
                # so we just return the same deferred that will be resolved to all of them
                details.connections.append(connection)
                return details.deferred

            # Creating a new deferred to handle the download of this tx
            deferred = Deferred()
            details = TxDetails(tx_id, deferred, [connection])
            self.pending_transactions[tx_id] = details
            self.waiting_deque.append(tx_id)
            self.download_next_if_possible()
            return details.deferred

    def download_next_if_possible(self) -> None:
        """ Start as many downloads as the number of available slots in the sliding window.
        """
        while self.waiting_deque and len(self.downloading_deque) < self.window_size:
            self.start_next_download()

    def start_next_download(self) -> None:
        """ Start the next download from the waiting queue.
        The tx_id is moved from the waiting queue to the downloading queue.
        """
        tx_id = self.waiting_deque.popleft()

        details = self.pending_transactions[tx_id]
        connection = details.get_connection()

        if connection is None:
            self._remove_pending_tx(tx_id)
        else:
            # Setting downloading deferred
            self.add_get_downloading_deferred(tx_id, details, connection)

            # Adding to download deque
            self.downloading_deque.append(tx_id)

    def add_get_downloading_deferred(self, tx_id: bytes, details: TxDetails, connection: 'NodeSyncTimestamp') -> None:
        """ Getting a downloading deferred when requesting data from a connection
        """
        assert details.downloading_deferred is None
        details.downloading_deferred = connection.request_data(tx_id)
        details.downloading_deferred.addCallback(self.on_new_tx)

        # Adding timeout to callback
        fn_timeout = partial(self.on_deferred_timeout, tx_id=tx_id)
        details.downloading_deferred.addTimeout(
            settings.GET_DATA_TIMEOUT,
            connection.reactor,
            onTimeoutCancel=fn_timeout
        )

    def on_deferred_timeout(self, result, timeout, **kwargs) -> None:
        """ Timeout handler for the downloading deferred
            It just calls the retry method
        """
        tx_id = kwargs['tx_id']
        self.retry(tx_id)

    def on_new_tx(self, tx) -> None:
        """ This is called when a new transaction arrives.
        """
        details = self.pending_transactions.get(tx.hash, None)
        if not details:
            # Something is wrong! It should never happen.
            self.log.warn(
                'Downloader: new transaction arrived but tx detail does not exist. Tx {}'.format(tx.hash.hex())
            )
            return

        assert len(self.downloading_deque) > 0
        self.downloading_buffer[tx.hash] = tx
        self.check_downloading_queue()

    def check_downloading_queue(self) -> None:
        """ Check whether the transactions of the downloading queue
            have already been downloaded. Those that were are added to the DAG.

            downloading_deque is a list of transactions that are being downloaded
            downloading_buffer is a dict with transactions already downloaded

            We need to add to the DAG in the same order as the downloading_deque
            so we iterate in this order and add to the DAG if it the download was already done
        """
        count = 0
        while self.downloading_deque:
            tx_id = self.downloading_deque[0]
            tx = self.downloading_buffer.pop(tx_id, None)
            if not tx:
                # If we still don't have this tx in the downloading_buffer
                # means that we need to wait until its download is finished to add to the DAG
                break

            self.downloading_deque.popleft()
            count += 1

            # Run the deferred.
            details = self.pending_transactions.pop(tx_id)
            details.deferred.callback(tx)

        if count > 0:
            self.download_next_if_possible()

    def retry(self, tx_id: bytes) -> None:
        """ Retry a failed download
            It will only try once per connection
        """
        details = self.pending_transactions.get(tx_id, None)

        if details is None:
            # Nothing to retry but should never enter here
            # Maybe a race condition in which the timeout has triggered and the tx has arrived.
            return

        # Failing old downloading deferred
        if details.downloading_deferred:
            details.downloading_deferred.cancel()
            details.downloading_deferred = None

        # Get new connection
        new_connection = details.get_connection()

        if new_connection is None:
            self._remove_pending_tx(tx_id)
            return

        # Start new download
        self.add_get_downloading_deferred(tx_id, details, new_connection)

    def _remove_pending_tx(self, tx_id: bytes) -> None:
        """ Cancel tx deferred and remove it from the pending dict
        """
        # No new connections available, so we must remove this tx_id from pending_transactions and cancel the deferred
        details = self.pending_transactions.pop(tx_id)
        details.deferred.cancel()
        self.log.warn(
            'Downloader: No new connections available to download the transaction. Tx {}'.format(tx_id.hex())
        )
