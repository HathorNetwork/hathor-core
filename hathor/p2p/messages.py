from enum import Enum
from collections import namedtuple


GetTipsPayload = namedtuple('GetTipsPayload', [
    'timestamp',  # int
    'include_hashes',  # bool
    'offset',  # int, default=0
])

TipsPayload = namedtuple('TipsPayload', [
    'length',  # int
    'timestamp',  # int
    'prev_timestamp',  # int
    'next_timestamp',  # int
    'merkle_tree',  # str(hash)
    'hashes',  # List[str(hash)]
    'has_more',  # bool
])


class ProtocolMessages(Enum):
    # ---
    # General Error Messages
    # ---
    # Notifies an error.
    ERROR = 'ERROR'

    # Notifies a throttle.
    THROTTLE = 'THROTTLE'

    # ---
    # Peer-to-peer Control Messages
    # ---
    # Identifies the app and network the peer would like to connect to.
    HELLO = 'HELLO'

    # Identifies the peer.
    PEER_ID = 'PEER-ID'

    # Request a list of peers.
    GET_PEERS = 'GET-PEERS'

    # Usually it is a response to a GET-PEERS command. But it can be sent
    # without request when a new peer connects.
    PEERS = 'PEERS'

    # Ping is used to prevent an idle connection.
    PING = 'PING'

    # Pong is a response to a PING command.
    PONG = 'PONG'

    # ---
    # Hathor Specific Messages
    # ---
    NOTIFY_DATA = 'NOTIFY-DATA'  # Notify about a new piece of data.
    GET_DATA = 'GET-DATA'        # Request the data for a specific transaction.
    DATA = 'DATA'                # Send the data for a specific transaction.

    GET_TIPS = 'GET-TIPS'
    TIPS = 'TIPS'

    GET_BLOCKS = 'GET-BLOCKS'  # Request a list of hashes for blocks. Payload is the current latest block.
    BLOCKS = 'BLOCKS'          # Send a list of hashes for blocks. Payload is a list of hashes.

    GET_TRANSACTIONS = 'GET-TRANSACTIONS'  # Request a list of hashes for transactions.
    TRANSACTIONS = 'TRANSACTIONS'          # Send a list of hashes for transactions.

    HASHES = 'HASHES'

    # Request the height of the last known block.
    GET_BEST_HEIGHT = 'GET-BEST-HEIGHT'

    # Send the height of the last known block.
    BEST_HEIGHT = 'BEST-HEIGHT'
